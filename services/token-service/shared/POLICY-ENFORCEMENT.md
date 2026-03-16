# Policy Enforcement — How WID Enforces Policy

## The Core Principle

WID enforces policy through a graduated **Simulate → Audit → Enforce** lifecycle. This ensures operators can observe the impact of a policy before it blocks production traffic. Every decision — simulate, audit, or enforce — is logged with full context for deterministic replay.

---

## Three Enforcement Modes

### Simulate (Zero Impact)

- Policies evaluate normally but **never block traffic**
- Returns `WOULD_BLOCK` decisions showing what would be denied
- No graph changes — edges remain solid, nodes retain normal styling
- Used to preview impact before rollout
- Decisions logged to `ext_authz_decisions` with `adapter_mode='simulate'`

### Audit (Observe Only)

- Policies evaluate and all violations are recorded
- **Traffic is never blocked** — the verdict is always `allow`
- Graph shows amber dashed edges with a violation badge indicating "violations being logged"
- Operators can see real traffic patterns before committing to enforcement
- Decisions logged with `adapter_mode='audit'`

### Enforce (Hard Block)

- Policies with `enforcement_mode='enforce'` are evaluated first
- **Violations block traffic immediately** — HTTP 403 returned to the caller
- Graph updates:
  - Affected edges turn gray dashed with a severed indicator
  - Affected nodes turn green with a ring indicator (remediated)
  - Risk score jumps as attack paths are broken
  - Credential nodes used by enforced workloads dim to 40% opacity
- Decisions logged with `adapter_mode='enforce'` and `enforcement_action='REJECT_REQUEST'`

---

## Policy Evaluation Pipeline

When a workload makes an API call, the edge gateway intercepts and evaluates the request through a multi-stage pipeline:

### Stage 1: WID Token Validation

If the request includes a WID token (issued during attestation):
- Verify HMAC-SHA256 signature
- Check token expiry
- Extract: SPIFFE ID, trust level, attestation method, is_ai_agent flag
- Invalid or expired tokens → automatic deny (HTTP 403)

### Stage 2: Workload Registry Check

Both source and destination workloads are resolved from the database:
- Unregistered workloads → automatic deny (zero-trust default)
- Populates context: name, type, trust_level, verified status, environment

### Stage 3: AI Traffic Detection

If the destination matches a known AI provider (OpenAI, Anthropic, etc.):
- Query daily stats (cost, request count, token count)
- Build AI context for policy evaluation (enables cost-ceiling and rate-limit policies)

### Stage 4: Multi-Policy Evaluation

Policies are split by enforcement mode and evaluated in priority order:

1. **Enforce-mode policies evaluated first** — if any deny, traffic is blocked immediately
2. **Audit-mode policies evaluated second** — violations are logged but traffic flows
3. **Compliance checks** — non-access policies (posture, lifecycle) evaluated against the source workload

The evaluator supports 25+ condition operators:
- String: `equals`, `contains`, `starts_with`, `matches` (regex)
- Numeric: `gt`, `gte`, `lt`, `lte`, `between`
- Boolean: `is_true`, `is_false`
- Existence: `exists`, `not_exists`
- Time: `older_than_days`, `within_time_window`
- Array: `includes_any`, `includes_all`, `exceeds_count`

### Stage 5: Verdict Determination

```
1. If enforce policy denies          → verdict = deny, action = REJECT_REQUEST
2. If enforce allows + compliance    → verdict = deny (compliance violation)
3. If enforce allows + no violations → verdict = allow, action = FORWARD_REQUEST
4. If only audit policies match      → verdict = allow, mode = audit (logged only)
5. If no policies match              → verdict = deny (default deny)
```

### Stage 6: Decision Logging

Every decision is persisted with full context:
- Decision ID, trace ID, hop index, total hops
- Source/destination workload names and SPIFFE IDs
- Verdict, policy name, enforcement action
- Token context (WID token validation result)
- Request context (method, path, headers, identity info)
- Response context (decision rationale, latency)

---

## Policy Templates

WID ships with 30+ policy templates across 6 categories that can be instantiated as live policies:

### 1. Compliance / Posture
- `prod-attestation-required`: Block unattested production workloads
- `no-owner-violation`: Flag identities without assigned owners
- `shadow-identity-detection`: Flag shadow identities needing review

### 2. Lifecycle
- `stale-credential-lifecycle`: Quarantine identities inactive 90+ days
- `credential-rotation-overdue`: Force rotation every 90 days
- `max-credential-age`: Disable credentials older than 365 days

### 3. Access Control
- `cross-env-access-deny`: Block production → non-production access
- `prod-requires-attestation`: Only attested clients access production
- `prod-min-trust-access`: Minimum trust level for production access

### 4. Conditional Access
- Business-hours-only access
- Geo-restricted access
- Posture score gating (minimum security score required)

### 5. AI Agent (Specialized)
- Scope ceiling enforcement (prevent financial + CRM access in single agent)
- Delegation chain binding (require human authorization root)
- MCP tool restrictions (block dangerous tools: shell, exec, delete)
- Kill switch triggers (emergency shutdown for compromised agents)

### Template → Enforce Flow

```
POST /api/v1/policies/from-template/credential-vault-migration
  body: { enforcement_mode: 'enforce', workload: 'billing-agent' }
  ↓
Template loaded from DB → conditions extracted → compiled to Rego
  ↓
Policy inserted/updated with enforcement_mode='enforce'
  ↓
Next gateway evaluation picks up the enforce policy
  ↓
Traffic matching the policy is blocked with HTTP 403
```

---

## Control Scoring (Playbook)

When the user selects a node in the graph, the Inspector's Playbook tab shows ranked remediation controls. Each control is scored on four dimensions:

### Path Break Strength (40% weight)
How effectively does this control sever attack paths?
- **Edge position**: Entry-point controls score highest (100), credential-level controls (70), resource-level (40)
- **Edges severed**: More edges broken = higher score
- **Crown jewel proximity**: Controls near sensitive targets (external APIs, data stores) score higher

### Blast Radius Impact (20% weight, inverse)
Fewer affected workloads = higher score. Controls that precisely target one workload without collateral impact score highest.

### Operational Cost (20% weight, inverse)
- **Implementation effort**: Hours → days → weeks
- **Ongoing toil**: How much maintenance does this control require?
- **Expertise required**: Low → medium → high

### Confidence (20% weight)
Based on control type:
- Policy controls: 90% (well-understood, reversible)
- Replace controls: 80% (credential swap)
- Remediate controls: 85% (direct fix)
- Architecture controls: 60% (larger blast radius, harder to verify)

---

## Multi-Hop Trace Chains

WID tracks policy decisions across multi-hop agent chains. When servicenow-it-agent calls code-review-agent which calls OpenAI, all three hops share a single `trace_id`:

```
Hop 0: servicenow-it-agent → code-review-agent   trace-abc, hop 0/3
Hop 1: code-review-agent → OpenAI API             trace-abc, hop 1/3
Hop 2: servicenow-it-agent → billing-agent         trace-abc, hop 2/3
```

Each hop has:
- `trace_id`: Links all hops in the chain
- `hop_index`: Position in the chain (0-based)
- `total_hops`: Chain length
- `parent_decision_id`: Links to the previous hop's decision

The Authorization Events page can filter by `trace_id` to replay entire chains and identify which hop was blocked by enforcement.

---

## Failure Semantics

### Default Posture
```
DEFAULT_MODE  = audit     # Start in audit, observe before enforcing
FAIL_BEHAVIOR = open      # If evaluator crashes, allow traffic (not fail-closed)
```

This ensures deployments are safe by default — no silent failures blocking legitimate traffic.

### Edge Gateway Guarantees
1. Unregistered workloads → deny (zero-trust)
2. Invalid WID tokens → deny
3. Policy evaluation timeout → allow + log (degraded mode, not a blocker)
4. Database unavailable → allow (cached policies still apply)
5. Malformed request → deny (defensive)

### Rollout Strategy
The intended rollout path for any new policy:
```
simulate → observe WOULD_BLOCK decisions for 24-48 hours
  ↓
audit → enable logging, monitor for false positives
  ↓
enforce (per-workload) → enable blocking for one workload, verify
  ↓
enforce (globally) → roll out to all matching workloads
  ↓
fail-closed (optional) → change FAIL_BEHAVIOR for critical paths
```

---

## Graph Impact Summary

| Action | Edges | Nodes | Score | Attack Paths |
|--------|-------|-------|-------|-------------|
| **Simulate** | No change | No change | No change | Shown with `WOULD_BLOCK` |
| **Audit** | Amber dashed | No change | No change | Still counted |
| **Enforce** | Gray dashed + severed | Green ring | Jumps up | Severed → 0 |
| **Rollback** | Restored to solid | Revert to original color | Drops back | Reappear |

---

## End-to-End Example

```
1. User selects "billing-agent" node in graph
2. Inspector shows: 2 attack paths, 3 findings (static Stripe key, no attestation)
3. Playbook shows ranked controls:
     #1 — Migrate to Vault (score: 87/100, policy-based, automated)
     #2 — Rotate credential (score: 72/100, replace, semi-automated)
     #3 — Restrict network (score: 45/100, architecture, manual)

4. User clicks Simulate on #1
   → WOULD_BLOCK decisions shown in Evidence tab
   → No traffic affected

5. User clicks Audit on #1
   → Policy created with enforcement_mode='audit'
   → Graph edges turn amber dashed
   → Violations logged to ext_authz_decisions

6. User clicks Enforce on #1
   → Policy updated to enforcement_mode='enforce'
   → billing-agent → Stripe traffic blocked (HTTP 403)
   → Graph edges severed, billing-agent node turns green
   → Attack paths through Stripe credential → 0
   → Security score jumps from 35 to 78
   → Decision logged with full trace context

7. Authorization Events page shows:
   → Baseline decision (simulate): allow, FORWARD_REQUEST
   → Audit decision: deny, MONITOR (traffic still flowed)
   → Enforce decision: deny, REJECT_REQUEST (traffic blocked)
   → All three linked by trace_id for replay
```
