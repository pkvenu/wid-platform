# WID Platform — Technical Specification

> Version 1.0 | March 2026 | Spec-based development reference
> This document describes what has been built and how it works.

---

## 1. System Architecture

### Deployment Model: Hub-and-Spoke Federation

```
                    ┌─── GCP Cloud Run (CENTRAL CONTROL PLANE) ───┐
                    │                                               │
                    │  policy-engine :3001     token-service :3000  │
                    │  credential-broker :3002 discovery :3003      │
                    │  relay (HUB) :3005       web-ui :3100         │
                    │  Cloud SQL (PostgreSQL 16)                    │
                    │  LB: 34.120.74.81                            │
                    └──────────────┬────────────────────────────────┘
                                   │  Policy sync (pull, 15s)
                                   │  Audit events (push, 5s batch)
                                   │  Heartbeats (60s)
                    ┌──────────────┴──────────────┐
              ┌─────▼──────────┐          ┌───────▼─────────┐
              │ Docker Spoke   │          │ AWS Spoke       │
              │ relay + 7 GWs  │          │ (future)        │
              └────────────────┘          └─────────────────┘
```

**Principle**: Each spoke runs only relay + edge-gateways. All state, policy, UI, and database live in GCP central. Demo agents are a separate project (`wid-demo-agents/`).

### Data Plane Modes

| Mode | Directory | Use When |
|------|-----------|----------|
| Edge Gateway (default) | `services/edge-gateway/` | No service mesh. VMs, Docker, plain K8s |
| ext-authz Adapter | `services/ext-authz-adapter/` | Customer has Istio/Envoy |

Both modes use shared `@wid/core` (CircuitBreaker, PolicyCache, CredBuffer, AuditBuffer, AIInspector).

---

## 2. Services

### 2.1 Policy Engine (`services/policy-sync-service/`)

**Port**: 3001 | **Role**: Policy CRUD, evaluation, gateway decisions, template management

**Key subsystems:**
- **Policy evaluator** (`engine/evaluator.js`): In-memory policy evaluation with 14 operators (equals, not_equals, contains, starts_with, ends_with, in, not_in, matches, gt, gte, lt, lte, is_true, is_false, exists, not_exists). First-deny-wins, first-allow-wins short-circuit.
- **Template engine** (`engine/templates.js`): 133 seeded policy templates mapped to finding types via `finding_remediation_map` table and to 5 compliance frameworks (SOC 2, PCI DSS, NIST 800-53, ISO 27001, EU AI Act). Templates cover: JIT credentials, static credential bans, A2A auth requirements, agent scope ceilings, MCP tool whitelists, chain integrity, compliance posture.
- **Rego compiler** (`compilers/rego.js`): Translates policy conditions into OPA-compatible Rego. Produces `workload.rego` bundles.
- **Gateway evaluate** (`routes.js:1282+`): The hot-path endpoint called by edge gateways and demo agents. Evaluates all matching policies, returns verdict (allow/deny), logs to `ext_authz_decisions`.
- **Auth routes** (`auth/auth-routes.js`): User registration, login (cookie-based JWT), logout, password reset, demo-reset.

**Key endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/gateway/evaluate` | Hot-path: evaluate request against policies |
| POST | `/api/v1/gateway/evaluate-chain` | Multi-hop chain evaluation |
| POST | `/api/v1/policies/from-template/:templateId` | Deploy policy from template |
| POST | `/api/v1/access/decisions/batch` | Batch decision recording |
| GET | `/api/v1/access/decisions/live` | Live decision stream with filters |
| GET | `/api/v1/access/decisions/stats` | Aggregate stats (hourly, top offenders) |
| GET | `/api/v1/access/decisions/traces` | Trace ID listing |
| GET | `/api/v1/access/decisions/traces/:traceId` | Full trace chain |
| GET/POST/PUT/DELETE | `/api/v1/policies[/:id]` | Policy CRUD (GET list includes `compliance_frameworks` via LEFT JOIN on `policy_templates`) |
| GET | `/api/v1/policies/templates` | Template listing |
| POST | `/api/v1/governance/seed-agent-policies` | Seed demo enforcement policies |
| GET | `/api/v1/access/decisions/replay/:traceId` | Deterministic decision replay with policy snapshots |
| GET | `/api/v1/compliance/frameworks` | List compliance frameworks with coverage stats |
| GET | `/api/v1/compliance/frameworks/:id` | Framework detail with mapped templates |
| POST | `/api/v1/compliance/frameworks/:id/deploy` | One-click deploy all framework templates (audit mode) |
| GET | `/api/v1/compliance/frameworks/:id/coverage` | Per-control coverage breakdown |

### 2.2 Discovery Service (`services/discovery-service/`)

**Port**: 3003 (internal container port), 3004 (external/host mapped) | **Role**: Workload scanning, identity graph, attack paths

**Key subsystems:**
- **Cloud scanners** (`scanners/`): GCP (Cloud Run, IAM, firewall, SA, Vertex AI), AWS (IAM, EC2, Lambda, S3, RDS, VPC), Azure (RBAC, managed identity, storage, SQL, NSG), Docker (containers, networks, ports), On-prem (K8s SA, SPIFFE)
- **Protocol scanner** (`graph/protocol-scanner.js`): A2A Agent Card detection (probes `/.well-known/agent.json`), MCP capability detection, external API credential detection (two-pass: env key names + metadata.credentials), agent linking
- **Relationship scanner** (`graph/relationship-scanner.js`): 5-phase pipeline:
  1. Phase 1: Node creation from workloads
  2. Phase 2: Provider-specific relationships (IAM bindings, firewall rules, SA linkage)
  3. Phase 3: Cross-cutting relationships (shared identity, network exposure, credentials)
  4. Phase 3.5: Protocol detection (A2A, MCP)
  5. Phase 4: Attack path computation (11 detectors)
- **Graph routes** (`graph/graph-routes.js`): GET /api/v1/graph assembles full identity graph. Includes CONTROL_CATALOG (~70 controls across 15+ finding types), `scoreControls()` ranking, graph enrichment with deployed policy status.
- **Attestation** (`attestation/`): SPIFFE/SPIRE integration, manual/auto attestation, token issuance/revocation, continuous attestation scheduler
- **Connectors** (`connectors/`): Cloud account onboarding wizard, provider-specific scan triggers

**Key endpoints:**
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/v1/graph` | Full identity graph (nodes, relationships, attack_paths) |
| GET | `/api/v1/graph/timeline` | Historical graph events |
| POST | `/api/v1/workloads/scan` | Trigger workload scan |
| GET | `/api/v1/graph/controls/:finding_type` | Controls for a finding type |
| GET | `/api/v1/graph/remediation/:nodeId` | Remediation options for a node |
| POST | `/api/v1/graph/remediation/:nodeId/execute` | Execute remediation |
| GET | `/api/v1/graph/finding-types` | All finding type metadata |

### 2.3 Token Service (`services/token-service/`)

**Port**: 3000 | **Role**: JIT token issuance, validation, chain tracking

Manages SPIFFE-bound short-lived tokens. Tracks token chains via `token_chain` table (parent_jti, root_jti, chain_depth). Supports On-Behalf-Of (OBO) token exchange for delegation chains.

### 2.4 Credential Broker (`services/credential-broker/`)

**Port**: 3002 | **Role**: Multi-provider secret management

Pluggable providers: Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, 1Password. Credential rotation lifecycle tracking. Dynamic credential issuance with scope constraints.

### 2.5 Relay Service (`services/relay-service/`)

**Port**: 3005 | **Role**: Hub-spoke federation bridge

- **Hub mode** (GCP central): Receives registrations from spoke relays, serves policy bundles, accepts audit event batches, tracks environment health
- **Spoke mode** (Docker/AWS): Pulls policies every 15s, caches in memory, serves local edge gateways, buffers audit events and flushes upstream every 5s, sends heartbeats every 60s
- **Delegation** (`/api/v1/delegation/*`): Initiate/extend delegation chains across environments

### 2.6 Edge Gateway (`services/edge-gateway/`)

**Ports**: 15001 (outbound proxy), 15006 (inbound), 15000 (admin) | **Role**: Data-plane enforcement

Transparent proxy sidecar pattern. One gateway per workload. Evaluates policy locally using cached bundles from relay. Modes: `audit` (log only), `enforce` (block), `passthrough` (transparent). Includes AIInspector for AI/LLM API call telemetry (detects OpenAI, Anthropic, Google AI, Cohere, HuggingFace endpoints; estimates token counts and costs).

### 2.7 Web UI (`web/workload-identity-manager/`)

**Port**: 3100 | **Framework**: React 18 + Vite + Tailwind CSS

**Pages:**
- **GraphPage** (`src/pages/GraphPage.jsx`): D3 force-directed identity graph. Inspector panel with: Threat Brief, Remediation (Playbook), AI Agent details, Credentials, Resource Details, Identity & Evidence (Connections). Simulate/Audit/Enforce workflow buttons.
- **Policies** (`src/pages/Policies.jsx`): Policy CRUD, template deployment, policy editor
- **AccessEvents** (`src/pages/AccessEvents.jsx`): Live authorization decision stream, trace viewer, agent chain visualization, audit replay with PDF export
- **Compliance** (`src/pages/Compliance.jsx`): Compliance policy packs dashboard — 5 frameworks (SOC 2, PCI DSS, NIST 800-53, ISO 27001, EU AI Act), one-click deploy, coverage tracking. See `docs/COMPLIANCE.md`
- **Dashboard** (`src/pages/Dashboard.jsx`): Overview KPIs, risk distribution, recent activity
- **Connectors** (`src/pages/Connectors.jsx`): Cloud account onboarding wizard

---

## 3. Identity Graph

### Node Types (22)

| Category | Types |
|----------|-------|
| Human | `user` |
| Identity | `service-account`, `managed-identity`, `iam-role`, `iam-policy`, `spiffe-id` |
| GCP Workloads | `cloud-run`, `cloud-run-service`, `gce-instance`, `cloud-function`, `gke-cluster` |
| AWS Workloads | `lambda`, `ec2`, `ecs-task` |
| Containers | `container`, `pod` |
| AI | `a2a-agent`, `mcp-server` |
| Resources | `resource`, `external-resource`, `credential`, `external-api`, `gcs-bucket`, `cloud-sql` |
| Network | `exposure`, `firewall-rule` |

### Relationship Types (17+)

| Category | Type | Meaning |
|----------|------|---------|
| **Network Exposure** | `exposed-via` | Workload accessible from internet |
| | `allows-ingress-from` | Firewall allows inbound traffic |
| | `publicly-exposes` | Public exposure without access controls |
| **Identity Binding** | `runs-as` | Workload authenticates as this SA |
| | `shares-identity` | Multiple workloads share same SA |
| | `communicates-with` | Same Docker network, direct reachability |
| | `identifies` | SPIFFE ID bound to workload |
| **Privilege Chain** | `has-role` | Identity has IAM role |
| | `grants-access` | Role grants access to resource |
| | `holds-credential` | Identity holds a credential |
| | `accesses-api` | Credential accesses an external API |
| | `has-policy` | IAM policy attached |
| | `can-assume` | Cross-account role assumption |
| | `can-escalate-to` | Privilege escalation path |
| **Agent Protocol** | `runs-as-protocol` | Implements A2A/MCP protocol |
| | `uses-mcp-server` | Agent uses MCP server |
| | `can-delegate-to` | Agent can delegate tasks to another |

### Connection Provenance

Every relationship edge carries:
- `discovered_by`: The API or mechanism used (e.g., "GCP Cloud Run API", "A2A protocol probe")
- `evidence`: Full sentence explaining what was found and what it means

### Attack Path Detectors (11)

| Detector | Finding Type | Severity |
|----------|-------------|----------|
| Shared service account | `shared-sa` | critical/high |
| Credential exposure | `key-leak` | critical |
| Public-to-internal pivot | `public-internal-pivot` | critical |
| Over-privileged identity | `over-privileged` | high |
| Privilege escalation | `privilege-escalation` | critical |
| Cross-account trust | `cross-account-trust` | critical/high |
| Unbounded admin | `unbounded-admin` | critical |
| Public data exposure | `public-data-exposure` | high |
| Public database | `public-database` | critical |
| Internet-to-data path | `internet-to-data` | critical |
| Overly permissive security group | `overly-permissive-sg` | high |

Additional finding types from protocol scanner: `static-external-credential`, `a2a-no-auth`, `a2a-unsigned-card`, `mcp-static-credentials`, `toxic-combo`, `public-exposure-untagged`, `unused-iam-role`, `orphaned-asset`.

### Connection Display (Inspector Panel)

Connections grouped into four color-coded semantic categories:
- **NETWORK EXPOSURE** (red `#ef4444`): exposed-via, allows-ingress-from
- **IDENTITY BINDING** (purple `#a78bfa`): runs-as, shares-identity
- **PRIVILEGE CHAIN** (amber `#f59e0b`): has-role, grants-access, holds-credential
- **AGENT PROTOCOL** (pink `#ec4899`): runs-as-protocol, uses-mcp-server

Each connection shows:
1. Practical meaning (what the relationship means operationally)
2. Attack path badge (if connection participates in an attack path)
3. Three-layer evidence: DISCOVERED (API scan) -> CONFIRMED (runtime traffic) -> ACTIONABLE (policy status)

---

## 4. Policy Engine

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| `simulate` | Project WOULD_BLOCK decisions. No traffic impact. No graph change. |
| `audit` | Log decisions. Traffic flows. Amber dashed edges on graph. |
| `enforce` | Block unauthorized. Edges severed. Nodes turn green. Score drops. |

### Policy Structure

```json
{
  "name": "Block Non-Billing Stripe Access",
  "policy_type": "access",
  "severity": "high",
  "enforcement_mode": "enforce",
  "effect": "deny",
  "conditions": [
    { "field": "destination.name", "operator": "contains", "value": "stripe" },
    { "field": "source.name", "operator": "not_equals", "value": "billing-agent" }
  ],
  "actions": [{ "type": "block" }],
  "priority": 100,
  "client_workload_id": null,
  "attack_path_id": null
}
```

### Scoping

- **Global policies**: `client_workload_id = NULL` — apply to all matching traffic
- **Scoped policies**: `client_workload_id = UUID` — apply only to specific workload
- **Attack-path scoped**: `attack_path_id` links policy to specific finding

### Evaluation Order

1. Load policies WHERE enabled AND (global OR scoped to this workload)
2. Split by enforcement_mode (enforce vs audit)
3. Evaluate enforce policies in priority order (lower = higher priority)
4. First deny wins -> REJECT
5. First allow wins -> FORWARD
6. No match -> default action (configurable: allow or deny)
7. Audit policies evaluated separately, logged but don't affect verdict

### CONTROL_CATALOG

~70 controls across 15+ finding types. Each control has:
- `id`, `name`, `description`
- `action_type`: remediate, replace, harden, detect
- `remediation_type`: policy, iac, infra, code_change, vendor, process
- `template_id`: links to deployable policy template (for policy-type controls)
- `path_break`, `feasibility`, `operational`: scoring dimensions

---

## 5. Data Flow

### Discovery -> Graph -> UI

```
Cloud Scanner (gcp.js / aws.js / docker.js)
  -> Workload[] array
  -> ProtocolScanner.scan()         # AI data, credentials
  -> RelationshipScanner.build()    # attack paths, blast radius
  -> saveWorkload() x N             # writes to postgres
  -> GET /api/v1/graph              # reads postgres, ranks controls
  -> GraphPage.jsx D3 render
```

### Gateway Evaluate (Hot Path)

```
Agent -> POST /api/v1/gateway/evaluate
  -> Resolve source/destination workloads
  -> Load matching policies (scoped + global)
  -> Evaluate conditions (in-memory, <1ms)
  -> INSERT ext_authz_decisions (trace_id, hop_index, total_hops)
  -> Return verdict {allow|deny}
Latency: ~12-17ms total (dominated by DB I/O)
```

### Policy Sync (Hub-Spoke)

```
GCP Central relay (hub) :3005
  <- Docker spoke relay pulls policies every 15s
  -> Spoke caches in memory
  -> Local edge gateways call spoke relay, not GCP
  -> Spoke buffers audit events, flushes every 5s
  -> Spoke heartbeats every 60s
```

### Demo Agent Chain (UC1 example)

```
servicenow-it-agent (hop 0)
  -> POST /api/v1/gateway/evaluate (trace_id=T, hop=0, total=4)
  -> a2aCall -> code-review-agent (hop 1)
    -> POST /api/v1/gateway/evaluate (trace_id=T, hop=1, total=4)
    -> calls OpenAI GPT-4o-mini
  -> a2aCall -> billing-agent (hop 2)
    -> POST /api/v1/gateway/evaluate (trace_id=T, hop=2, total=4)
    -> calls Stripe /v1/charges (hop 3)
      -> POST /api/v1/gateway/evaluate (trace_id=T, hop=3, total=4)
```

---

## 6. Database Schema

**Engine**: PostgreSQL 16 (GCP Cloud SQL)
**Authoritative schema**: `database/init.sql` (v3.0.0)
**Tables**: 25 in init.sql + 4 created at service startup

### Core Tables

| Table | Rows (typical) | Purpose |
|-------|----------------|---------|
| `workloads` | 40-80 | All discovered NHIs |
| `policies` | 10-50 | Policy definitions with conditions/actions |
| `ext_authz_decisions` | 1000s | Data-plane decision log (hot table) |
| `policy_templates` | 20-30 | Seeded remediation templates |
| `finding_remediation_map` | 30-40 | Finding type -> template mappings |
| `identity_graph` | 1 | Cached graph JSON (rebuilt per scan) |
| `token_chain` | varies | OBO token lineage tracking |
| `attestation_history` | varies | Workload attestation audit trail |
| `connectors` | 1-5 | Cloud account connections |
| `users` | 1-10 | Platform authentication |

### Key Decision Record (`ext_authz_decisions`)

```sql
decision_id, source_principal, destination_principal,
source_name, destination_name, method, path_pattern,
verdict, policy_name, policies_evaluated, adapter_mode,
latency_ms, cached, token_jti, chain_depth,
trace_id, hop_index, total_hops,
enforcement_action, enforcement_detail,
token_context, request_context, response_context,
created_at
```

This is the table that creates data gravity. Every request through the edge gateway produces a row with full context: who called what, under which policy, with what verdict, linked to the full trace chain.

---

## 7. Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | mTLS between services (SPIFFE SVIDs in production) |
| Authentication | Cookie-based JWT sessions (web UI), bearer tokens (API), IAM (Cloud Run agents) |
| Authorization | OPA policy evaluation (embedded), policy engine evaluate endpoint |
| Secrets | GCP Secret Manager (production), env vars (development) |
| Audit | Tamper-evident decision logs in `ext_authz_decisions` |
| Data plane isolation | Edge gateways stateless, relay caches in-memory only, DB in central |
| Failure semantics | Configurable per-action: fail-open (default), fail-closed, fail-conditional |
| Default mode | `audit` + `fail-open` — traffic flows, violations logged |

---

## 8. Test Coverage

| Service | Tests | Framework | Status |
|---------|-------|-----------|--------|
| `shared/data-plane-core` | 72 | node:test | All passing |
| `services/edge-gateway` | 23 | node:test | All passing |
| `services/policy-sync-service` | 31 | Custom assert | All passing |
| `services/ext-authz-adapter` | 1 | node:test | 1 failing |
| `services/relay-service` | 0 | — | No test files |
| `services/discovery-service` | 0 | — | No test files |
| `services/token-service` | 0 | — | No test files |
| `services/credential-broker` | 0 | — | No test files |
| **Total** | **127** | | **126 passing, 1 failing** |

---

## 9. Live Deployment

### GCP Central (Production)

```
Project: wid-platform | Region: us-central1
LB: 34.120.74.81 | DB: 10.179.0.3 (Cloud SQL)

Services:
  wid-dev-policy-engine      wid-dev-token-service
  wid-dev-credential-broker  wid-dev-discovery-service
  wid-dev-relay-service      wid-dev-web-ui
```

### Demo Agents (Separate Cloud Run services)

```
demo-orchestrator (public) + 7 IAM-secured agents
UC1: IT ticket orchestration (4-hop chain)
UC2: Supply chain security scan (toxic delegation)
UC3: Shadow AI detection (unauthorized Anthropic API)
```

### Docker Spoke (Local)

```
1 relay (spoke mode) + 7 edge-gateways
Connected to GCP central via relay federation
```
