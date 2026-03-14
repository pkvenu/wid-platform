# WID Platform — Attack Path Detection Walkthrough

> Version 1.0 | March 2026
> A narrative walkthrough demonstrating WID's end-to-end attack path detection on a realistic AI agent environment.

---

## Scenario Setup

An enterprise runs 8 AI agents on GCP Cloud Run, communicating via the A2A protocol. The agents perform IT automation, code review, billing, supply chain management, security scanning, customer support, and analytics. Several call external APIs (OpenAI, Stripe, GitHub, Salesforce, Anthropic).

| Agent | Role | External APIs | Trust Level |
|-------|------|---------------|-------------|
| **servicenow-it-agent** | IT orchestrator, delegates to other agents | OpenAI | High |
| **code-review-agent** | Reviews PRs, runs static analysis | GitHub, Anthropic | High |
| **billing-agent** | Manages invoices, processes payments | Stripe, Salesforce | High |
| **supply-chain-agent** | Monitors dependencies, scans repos | GitHub | Medium |
| **security-scanner-agent** | Vulnerability scanning, compliance checks | - | Medium |
| **zendesk-support-agent** | Customer ticket triage and response | Zendesk | Medium |
| **github-actions-runner** | CI/CD pipeline execution | GitHub | Medium |
| **mcp-analytics-server** | MCP server providing analytics tools | - | Medium |

The environment has several intentional security weaknesses that WID discovers. This is a realistic scenario — not every agent has cryptographic attestation, not every credential is in Vault, and not every Agent Card is signed.

---

## Step 1: Discovery Scan

Trigger a workload scan:

```bash
curl -X POST https://wid.example.com/api/v1/workloads/scan \
  -H "Cookie: auth_token=<session>" \
  -H "Content-Type: application/json" \
  -d '{"provider": "gcp"}'
```

### What Happens

17 scanners activate in sequence:

1. **GCP Cloud Run Scanner** — discovers 8 Cloud Run services, their service accounts, IAM bindings, ingress settings, and environment variables
2. **GCP IAM Scanner** — maps project-level IAM bindings, role assignments, and cross-project trusts
3. **Protocol Scanner** — probes each workload for:
   - A2A Agent Cards at `/.well-known/agent.json` (5 detected, 3 unsigned)
   - MCP server capabilities (1 MCP server detected with 12 tools)
   - External API credentials (Stripe, OpenAI, GitHub, Salesforce, Anthropic keys found in environment variables)
   - Agent Card JWS signature verification (5 verified, 3 unsigned)

### Result

40+ workloads discovered, including:
- 8 Cloud Run services (the AI agents)
- 8 GCP service accounts
- 5 A2A agents with Agent Cards
- 1 MCP server with 12 tools
- 6 external API endpoints (OpenAI, Stripe, GitHub, Salesforce, Anthropic, Zendesk)
- 7 credential nodes (API keys in environment variables)
- Network exposure nodes (public internet)
- IAM role and policy nodes

---

## Step 2: Identity Graph Construction

The 7-phase relationship scanner builds the identity graph:

| Phase | What It Does | Nodes/Edges Added |
|-------|-------------|-------------------|
| **Phase 1**: Workload Nodes | Create one node per discovered workload | 8 workload nodes |
| **Phase 2**: Identity Nodes | Service account and IAM role nodes | 8 SA nodes, 12 role nodes |
| **Phase 3**: IAM Bindings | Link workloads → SAs → roles → resources | 35 edges |
| **Phase 4**: Network Exposure | Identify public workloads, firewall rules | 3 exposure nodes, 8 edges |
| **Phase 5**: Shared Identity | Detect workloads sharing the same SA | 2 `shares-identity` edges |
| **Phase 6**: Credentials | Create nodes for static API keys | 7 credential nodes, 14 edges |
| **Phase 7**: AI Protocol | A2A Agent Cards, MCP tools, delegation chains | 6 protocol nodes, 18 edges |

**Final graph**: ~57 nodes, ~170 edges.

The graph is now a complete map of the environment: every workload, every identity it uses, every credential it holds, every external API it calls, and every attack path between them.

---

## Step 3: Attack Path Findings

WID's 11 attack path detectors traverse the graph using BFS. Here are the findings for this environment:

### Finding A: Shared Service Account Blast Radius (Critical)

```
  billing-agent ──runs-as──▶ shared-billing-sa ◀──runs-as── supply-chain-agent
       │                                                           │
  holds-credential                                          holds-credential
       │                                                           │
       ▼                                                           ▼
  STRIPE_SECRET_KEY                                        GITHUB_TOKEN
       │                                                           │
  accesses-api                                              accesses-api
       │                                                           │
       ▼                                                           ▼
   Stripe API                                              GitHub API
```

**What WID found**: `billing-agent` and `supply-chain-agent` share the same GCP service account (`shared-billing-sa`). Both have access to `STRIPE_SECRET_KEY` and `GITHUB_TOKEN` via their shared identity.

**Blast radius**: BFS from the shared SA reaches **6 workloads** — every service that shares this identity or is reachable through its roles.

**Why this matters**: An attacker who compromises `supply-chain-agent` (which processes untrusted GitHub repositories) inherits `billing-agent`'s Stripe access. That's a direct financial impact path through identity sharing.

**Severity**: Critical (shared SA + public exposure + financial credential)

### Finding B: Static External Credential Exposure (Critical)

**What WID found**: `billing-agent` has `STRIPE_SECRET_KEY` as a static environment variable — not managed by Vault or any secret manager. The credential is a live secret key with financial scope.

**Why this matters**: If the container image is leaked, the Cloud Run service metadata is accessed via SSRF, or the GCP project is compromised, the Stripe key is immediately exposed. This is OWASP NHI2 (Secret Leakage) — the #1 credential attack vector for non-human identities.

**Related finding**: `toxic-credential-combo` — `billing-agent` holds both Stripe *and* Salesforce credentials. A single compromise exposes both financial and CRM systems.

### Finding C: Public-to-Internal Pivot (Critical)

```
  public-internet ──exposed-via──▶ servicenow-it-agent
                                         │
                                    runs-as
                                         │
                                         ▼
                                   orchestrator-sa
                                         │
                                    has-role
                                         │
                                         ▼
                                    roles/editor
                                         │
                                   grants-access
                                         │
                                         ▼
                                    Cloud SQL (internal DB)
```

**What WID found**: `servicenow-it-agent` is publicly exposed (Cloud Run `INGRESS_TRAFFIC_ALL`). Its service account has `roles/editor`, which grants access to the internal Cloud SQL database.

**BFS depth**: Public internet → internal database in **3 hops**.

**Why this matters**: An attacker who compromises the public-facing orchestrator can pivot to internal databases via the service account's IAM bindings. No lateral movement detection tool would catch this because it's all legitimate IAM access.

### Finding D: Confused Deputy — Delegation Chain Risk (High)

**What WID found**: `servicenow-it-agent` delegates tasks to `code-review-agent` (hop 0 → 1). `code-review-agent` has GitHub access but should not have Stripe access. Without chain-aware enforcement, a crafted request could trick `code-review-agent` into calling `billing-agent`'s endpoints — escalating from code review scope to financial scope.

**Chain path**:
```
servicenow-it-agent → code-review-agent → [potential pivot] → billing-agent → Stripe
       hop 0                hop 1                                   hop 2
```

**Why this matters**: This is the classic confused deputy problem. Agent A delegates to Agent B, and a malicious prompt causes B to call Agent C with A's implicit authority. WID's chain context (`chain.origin`, `chain.depth`, `chain.authorized_scopes`) enables policies that prevent this transitive escalation.

### Finding E: Unsigned Agent Cards (Medium)

**What WID found**: 3 of the 8 agents serve unsigned Agent Cards — `security-scanner-agent`, `github-actions-runner`, and `mcp-analytics-server`. Without JWS signatures, there is no cryptographic proof that the Agent Card hasn't been tampered with.

**Why this matters**: An attacker could replace an agent's card with a modified version that claims different capabilities or authentication requirements. Signed cards (verified via the platform's JWKS endpoint) provide tamper-evident identity for A2A discovery.

**Recommendation**: Set `TOKEN_SERVICE_URL` on these agents to enable automatic Agent Card signing at startup. The platform's token-service signs cards with the same ES256 key used for workload tokens.

---

## Step 4: Risk Scoring

WID computes a security score (0-100) for each workload. The score combines governance factors, attestation trust, and finding severity.

### Before Remediation

| Agent | Score | Key Factors |
|-------|:-----:|-------------|
| billing-agent | **23** | Critical findings (static credential, shared SA), no attestation bonus |
| supply-chain-agent | **31** | Shared SA, medium trust, GitHub token exposure |
| servicenow-it-agent | **35** | Public exposure, critical pivot path, high trust |
| code-review-agent | **52** | Confused deputy risk, otherwise well-governed |
| security-scanner-agent | **58** | Unsigned card, medium trust |
| zendesk-support-agent | **62** | Medium findings, API key in env var |
| github-actions-runner | **55** | Unsigned card, CI/CD without OIDC federation |
| mcp-analytics-server | **48** | Unsigned card, MCP server without OAuth 2.1 |

**Environment totals**: 8 critical findings, 12 high findings, 6 medium findings. Average security score: **45**.

### Scoring Algorithm (Brief)

```
Base score:                     50
+ Governance (owner, team):    +15 to +35
+ Environment (prod, known):   +10 to +20
+ Attestation trust:           +0 to +15
- Worst finding severity:      -5 to -40
- Volume penalty:              -0 to -15
= Final score:                 0 to 100
```

For the full algorithm, see [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md) section 2.

---

## Step 5: Remediation Playbook

WID doesn't just find problems — it provides a scored, prioritized remediation playbook. Let's walk through remediating **Finding B** (static Stripe credential).

### Control Catalog

When you click a finding in the graph, WID shows ranked remediation controls:

| # | Control | Type | Score | Effort |
|---|---------|------|:-----:|--------|
| 1 | Migrate to JIT credential (Vault) | `policy` | 87/100 | Medium |
| 2 | Rotate credential immediately | `replace` | 72/100 | Low |
| 3 | Add credential rotation policy | `code_change` | 65/100 | Medium |
| 4 | Monitor credential usage | `process` | 45/100 | Low |

### Deploying Control #1: Migrate to Vault

**Simulate** — Preview the impact without blocking anything:

The policy "JIT Credential Required for External APIs" evaluates against billing-agent's Stripe traffic. The UI shows `WOULD_BLOCK` decisions — orange indicators on the graph. No traffic is actually blocked.

```
Decision: WOULD_BLOCK
Source:   billing-agent
Dest:     api.stripe.com
Policy:   jit-credential-required
Reason:   Static credential detected — STRIPE_SECRET_KEY not Vault-managed
```

**Audit** — Enable real-time violation logging:

Promote the policy to `audit` mode. Graph edges between billing-agent and Stripe turn amber with dashed lines and a violation badge. Every API call is logged with the violation context, but traffic continues flowing. Security team can review the violation volume and impacted request patterns.

**Enforce** — Block the traffic:

Promote to `enforce` mode. Graph edges turn gray with a severed indicator. Billing-agent receives HTTP 403 for Stripe API calls until the credential is migrated to Vault. The billing-agent node turns green with a remediated ring.

### Impact

| Metric | Before | After |
|--------|:------:|:-----:|
| billing-agent security score | 23 | **72** |
| Attack paths through Stripe credential | 4 | **0** |
| Static external credentials | 5 | **4** |

---

## Step 6: Chain-Aware Enforcement

Deploy an anti-confused-deputy policy to address Finding D.

### Policy Template: `require-authorized-chain`

```json
{
  "name": "Prevent Chain Privilege Escalation",
  "enforcement_mode": "enforce",
  "conditions": [
    { "field": "chain.depth", "operator": "gt", "value": 2 },
    { "field": "destination.name", "operator": "equals", "value": "billing-agent" },
    { "field": "chain.origin", "operator": "not_equals", "value": "billing-agent" }
  ],
  "effect": "deny",
  "actions": ["block_deploy"]
}
```

This policy says: "If a request reaches billing-agent through a delegation chain deeper than 2 hops, and the chain didn't originate from billing-agent itself, deny it."

### Trace Correlation

All hops in a chain share the same `trace_id`, with each hop recording its position:

```
Hop 0: servicenow-it-agent → code-review-agent
       trace_id: tr-abc123, hop_index: 0, total_hops: 3

Hop 1: code-review-agent → billing-agent
       trace_id: tr-abc123, hop_index: 1, total_hops: 3
       ❌ DENIED — chain.depth > 2 from non-billing origin

Hop 2: (never reached)
       billing-agent → Stripe API
```

The chain-aware policy stops the confused deputy at hop 1 — `code-review-agent` cannot call `billing-agent` because the request originated from `servicenow-it-agent` (a non-billing context) at depth 3.

---

## Step 7: Deterministic Replay

Every enforcement decision can be replayed exactly — the same inputs, the same policy version, the same verdict. This is required by EU AI Act Article 12 (mandatory August 2, 2026).

### Replay Package

Navigate to **Authorization Events** and find the trace:

```
GET /api/v1/access/decisions/replay/tr-abc123
```

Returns:

```json
{
  "trace_id": "tr-abc123",
  "replay_mode": "deterministic",
  "policy_version_hash": "sha256:a1b2c3d4...",
  "hops": [
    {
      "hop_index": 0,
      "source": "servicenow-it-agent",
      "destination": "code-review-agent",
      "verdict": "allow",
      "policy": "default-allow-internal",
      "timestamp": "2026-03-14T10:30:00Z"
    },
    {
      "hop_index": 1,
      "source": "code-review-agent",
      "destination": "billing-agent",
      "verdict": "deny",
      "policy": "prevent-chain-privilege-escalation",
      "chain_context": {
        "origin": "servicenow-it-agent",
        "depth": 3,
        "has_revoked_hop": false
      },
      "timestamp": "2026-03-14T10:30:01Z"
    }
  ],
  "chain_integrity": "verified",
  "exportable": true
}
```

**PDF export**: Click "Export for Auditor" to generate a PDF with the full replay package, chain diagram, policy version, and timestamp chain. This is the evidence that EU AI Act Article 12 and SOC 2 CC7.1 require.

---

## Before/After Summary

| Metric | Before WID | After Remediation |
|--------|:----------:|:-----------------:|
| Critical attack paths | 8 | **1** |
| Static credentials exposed | 5 | **1** |
| Shared service accounts | 2 pairs | **0** |
| Unsigned Agent Cards | 3 | **0** (after signing recommendation) |
| Average security score | 45 | **78** |
| Chain enforcement coverage | 0% | **100%** |
| Compliance coverage (SOC 2) | 0% | **92%** |
| Mean time to detect new agent | Hours/days | **Real-time** |
| Decision replay capability | None | **Deterministic** |

---

## What Happens Next

1. **Deploy remaining compliance frameworks** — One-click deploy for PCI DSS, NIST 800-53, ISO 27001, EU AI Act (all start in audit mode)
2. **Enable continuous MCP fingerprinting** — 5-minute rescan interval detects capability drift (tools added/removed/modified)
3. **Promote audit → enforce** — Workload by workload, promote remaining audit-mode policies to enforcement
4. **Sign remaining Agent Cards** — Set `TOKEN_SERVICE_URL` on the 3 unsigned agents
5. **Migrate all static credentials to Vault** — Use JIT credential injection via the credential broker

---

## Related Documentation

- [architecture.md](architecture.md) — System architecture overview
- [threat-model.md](threat-model.md) — STRIDE analysis and trust boundaries
- [deployment-models.md](deployment-models.md) — 4 deployment modes
- [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md) — Scoring algorithm (section 2), attack path detection (section 6)
- [shared/RELATIONSHIP-GENERATION.md](../shared/RELATIONSHIP-GENERATION.md) — Graph construction pipeline
- [shared/POLICY-ENFORCEMENT.md](../shared/POLICY-ENFORCEMENT.md) — Simulate/Audit/Enforce lifecycle
- [COMPLIANCE.md](COMPLIANCE.md) — 5 compliance frameworks, 68 controls
