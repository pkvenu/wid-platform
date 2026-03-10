# WID Platform --- Architecture Deep Dive

> Version 1.0 | March 2026
>
> For architecture overview and deployment, see [README.md](../README.md). For detailed specifications, see [SPEC.md](SPEC.md).

This document explains the algorithms, scoring logic, decision processes, and architectural choices that power the WID platform. It is written for security architects, platform engineers, compliance teams, and investors who need to understand _how_ and _why_ the system works without reading source code.

---

## Table of Contents

1. [Architectural Decisions](#1-architectural-decisions)
2. [Security Scoring Algorithm](#2-security-scoring-algorithm)
3. [Workload Attestation and Trust Tiers](#3-workload-attestation-and-trust-tiers)
4. [Identity Graph Construction](#4-identity-graph-construction)
5. [Relationship Generation Pipeline](#5-relationship-generation-pipeline)
6. [Attack Path Detection](#6-attack-path-detection)
7. [Policy Evaluation Pipeline](#7-policy-evaluation-pipeline)
8. [Progressive Enforcement: Simulate, Audit, Enforce](#8-progressive-enforcement-simulate-audit-enforce)
9. [Remediation Control Scoring (Playbook)](#9-remediation-control-scoring-playbook)
10. [AI Agent and MCP Protocol Detection](#10-ai-agent-and-mcp-protocol-detection)
11. [Authorization Decision Logging and Replay](#11-authorization-decision-logging-and-replay)
12. [Credential Chain Computation](#12-credential-chain-computation)

---

## 1. Architectural Decisions

Every significant design choice is recorded as an Architecture Decision Record (ADR). The table below summarizes the decisions that define the platform.

| # | Decision | Rationale |
|---|----------|-----------|
| ADR-01 | Edge Gateway as default (no Istio required) | Enterprises don't have service meshes. Works everywhere without prerequisites. |
| ADR-02 | Hub-and-spoke relay | Control plane centralized; data plane operates locally with cached policies. |
| ADR-03 | Relay buffers audit events | Data plane never blocks on audit write. Batch-flush upstream. |
| ADR-04 | Single authoritative `init.sql` | All tables defined once. No divergence between services. |
| ADR-05 | OPA embedded in policy evaluation | Local evaluation on hot path. No round-trip to central. |
| ADR-06 | Shared data-plane-core library | One fix applies to both edge-gateway and ext-authz-adapter. |
| ADR-07 | Trace IDs across agent chains | Full decision chain queryable and replayable in audit. |
| ADR-08 | Vault for credential brokering | Pluggable providers: Vault, AWS, GCP, Azure, 1Password. |
| ADR-09 | Demo agents as separate project | Workloads being monitored are not platform code. Clean separation. |
| ADR-10 | Demo orchestrator as public entry point | Avoids coupling platform services to demo agent URLs. |
| ADR-11 | Remediation Decision Framework | 6-category taxonomy, decision routing, approval tiers. |

### Why Edge Gateway Over Service Mesh

The single most important architectural decision is ADR-01: deploying an edge gateway as the default data-plane enforcement point rather than requiring a service mesh like Istio.

The reasoning is grounded in market reality. Most enterprises do not run a service mesh. Requiring one as a prerequisite would eliminate 70-80% of prospective customers before a single conversation begins. WID's edge gateway operates as a lightweight sidecar proxy --- one per workload --- that intercepts traffic via iptables redirect or explicit proxy configuration. No control plane, no sidecar injection webhook, no CRDs, no Envoy xDS configuration.

For the minority of customers who already have Istio or standalone Envoy, WID provides an ext-authz adapter that plugs into the existing mesh using the standard `ext_authz` filter. Both modes share the same core library, so policy evaluation, caching, circuit breaking, and audit logging are identical.

| Factor | Edge Gateway | Service Mesh (Istio) |
|--------|-------------|---------------------|
| Install complexity | Copy binary + iptables rule | Mesh operator + CRDs + injection webhook |
| Sidecar overhead | One lightweight proxy per workload | Envoy sidecar + xDS control plane |
| Time to first enforcement | Minutes | Weeks to months |
| Customer prerequisites | None | Running Kubernetes with mesh |
| VM and bare-metal support | Yes (systemd + iptables) | No (mesh requires K8s) |

Both modes share identical: policy caching, data sanitization, circuit breaking, credential buffering, and metrics collection.

### Why Hub-and-Spoke Over Centralized

A centralized architecture would create a single point of failure: if the control plane is unreachable, enforcement stops. That is unacceptable.

In WID's hub-and-spoke model, each spoke (a relay + its edge gateways) operates autonomously. The relay pulls policy bundles from the hub every 15 seconds and caches them locally. Edge gateways pull from their local relay. If the hub goes down, spokes continue enforcing with the last-known-good (LKG) policy set. Audit events are buffered locally and flushed upstream when connectivity returns.

This means:
- **Spoke autonomy**: A network partition between hub and spoke does not interrupt enforcement.
- **LKG policies**: Gateways always have a working policy set, even during upgrades or outages.
- **Offline operation**: Air-gapped environments can run spokes with manually distributed bundles.
- **Graduated rollout**: New policies propagate hub-to-spoke within 15 seconds, but spokes can be pinned to a specific bundle version during change windows.

### Why Embedded OPA Over Central OPA

Open Policy Agent is the industry standard for policy evaluation. The question is where to run it.

A central OPA cluster introduces latency (network round-trip per decision), availability risk (OPA down means enforcement down), and a scaling bottleneck (all gateways compete for OPA capacity). WID embeds OPA evaluation directly in the policy evaluation engine. Policies are compiled to Rego and distributed as signed bundles. Each gateway evaluates locally.

| Factor | Embedded OPA | Central OPA |
|--------|-------------|-------------|
| Decision latency | Sub-millisecond (in-process) | 2-10ms (network round-trip) |
| Availability | Gateway-local, no external dependency | Single point of failure |
| Scaling | Horizontal with gateways | Requires separate OPA cluster scaling |
| Policy updates | Bundle pull (15s sync) | Bundle pull (similar) |
| Failure mode | Continue with cached policy | No evaluation possible |

### Control Plane and Data Plane Separation

WID enforces a strict separation between the control plane (where policies are authored, workloads are discovered, and the graph is built) and the data plane (where requests are intercepted and policy decisions are made).

```
    CONTROL PLANE                          DATA PLANE
    (can fail without                      (must never stop
     breaking enforcement)                  making decisions)

    +-------------------+                  +-------------------+
    | Policy Engine     |  -- bundles -->  | Edge Gateway      |
    | Discovery Service |                  | (per workload)    |
    | Token Service     |                  |                   |
    | Credential Broker |  <-- audit ---   | ext-authz Adapter |
    | Web UI            |                  | (per mesh)        |
    | Relay (Hub)       |  -- sync  -->    | Relay (Spoke)     |
    +-------------------+                  +-------------------+

    State: PostgreSQL                      State: In-memory cache
    Failure: Degrades UI/discovery         Failure: Blocks traffic
    Recovery: Standard deploy              Recovery: Automatic (LKG)
```

The control plane owns the database, the graph, and the UI. The data plane owns the request path. They communicate through asynchronous channels: policy sync (pull), audit events (push), and heartbeats. No synchronous call from the data plane to the control plane exists on the hot path.

---

## 2. Security Scoring Algorithm

Every workload in the system receives a security score between 0 and 100. This score is the single number that answers the question: "How worried should I be about this workload?"

### Base Score

Every workload starts at **50** --- the midpoint of the scale. This represents a workload with no additional information: unknown ownership, unknown environment, unverified identity, no findings.

### Governance Factors (Additive)

Governance factors reward organizational hygiene. A well-governed workload is inherently less risky because accountability is clear and response is faster.

**Ownership signals** (maximum +35):
- Owner assigned: **+15** --- someone is accountable for this workload
- Team assigned: **+10** --- the workload belongs to an organizational unit
- Cost center assigned: **+10** --- the workload has financial accountability

**Environment classification** (maximum +20):
- Environment is known (not "unknown"): **+10** --- the workload is classified
- Environment is "production": **+10** --- production workloads receive additional scrutiny and are expected to have higher governance

**Identity trust** (based on attestation method):
- Cryptographic verification (GCP JWT signed, AWS IMDSv2+TPM, SPIFFE X.509 SVID): **+15**
- Very-high confidence (AWS IMDSv2, ECS task role): **+10**
- High confidence (AWS Lambda context, GCP metadata, Azure MSI): **+10**
- Medium confidence (K8s service account, catalog match): **+5**
- Low or no verification: **+0**

### Penalty Factors (Subtractive)

**Operational state penalties:**
- Shadow workload (not in any catalog, undiscovered until scan): **-25**
- Dormant workload (no traffic in threshold period): **-25**

These penalties are severe because shadow and dormant workloads represent blind spots --- exactly where attackers hide.

### Finding-Based Penalty

After the governance score is computed, findings from the attack path detectors apply a secondary penalty.

**Worst-finding severity penalty:**

| Severity | Penalty |
|----------|---------|
| Critical | -40 |
| High | -25 |
| Medium | -15 |
| Low | -5 |
| Info | 0 |

**Volume penalty**: For multiple findings, an additional penalty of `min(15, (finding_count - 1) * 3)` is applied. Three critical findings are worse than one, but the penalty caps at -15 to avoid double-counting.

### Final Score

The score is clamped to the range [0, 100]. A workload with perfect governance, cryptographic attestation, and no findings scores 100. A shadow workload with critical findings and no ownership scores near 0.

**Score interpretation:**

| Range | Meaning |
|-------|---------|
| 90--100 | Excellent. Cryptographically attested, well-governed, no findings. |
| 70--89 | Good. Minor gaps in governance or low-severity findings. |
| 55--69 | Needs attention. Missing governance or medium findings. |
| 40--54 | At risk. Significant gaps or high-severity findings. |
| 0--39 | Critical. Shadow/dormant workloads with critical attack paths. |

---

## 3. Workload Attestation and Trust Tiers

Attestation answers the question: "Is this workload really who it claims to be?" WID implements a 4-tier trust hierarchy. The attestation engine tries the highest tier first and falls back gracefully.

### The Four Tiers

| Tier | Trust Level | Methods | WID Token TTL |
|------|-------------|---------|---------------|
| **1 --- Cryptographic** | `cryptographic` | SPIRE X.509 SVID, GCP metadata JWT (JWKS-verified), AWS IMDSv2 signed document, Azure MSI signed JWT, mTLS | 1 hour |
| **2 --- Token-Based** | `high` | JWT/OIDC verified, GitHub Actions OIDC, Vault token introspection, K8s TokenReview, AWS STS | 30 minutes |
| **3 --- Attribute-Based** | `medium` | Multi-signal ABAC (3+ runtime attributes), container verification (image digest + labels), network verification | 15 minutes |
| **4 --- Policy/Manual** | `low` | Service catalog match, OPA/Rego evaluation, manual operator approval | 5 minutes |

**Why the TTL varies by tier**: Higher trust methods produce stronger evidence that is harder to forge. A cryptographic attestation (Tier 1) is valid for a longer period because the evidence is cryptographically bound to the workload's identity. A catalog match (Tier 4) is weak evidence that could become stale quickly --- hence the 5-minute TTL forces frequent re-verification.

### Multi-Signal Bonus

If four or more attestation methods pass simultaneously, the trust level is boosted by one tier. This is the machine equivalent of multi-factor authentication: any single signal could be spoofed, but four independent signals corroborating the same identity is strong evidence.

### Platform-Specific Evidence Collection

**GCP**: The attestation engine fetches an identity token from the GCP metadata server (`http://metadata.google.internal/...`) and verifies the JWT signature against Google's published JWKS endpoint. The audience claim is validated to prevent token reuse across services.

**AWS**: The engine retrieves the signed instance identity document via IMDSv2 (token-based metadata service) and verifies the PKCS7 signature against AWS's published certificate chain. This is Tier 1 (cryptographic). As a fallback, `STS GetCallerIdentity` provides Tier 2 (token-based) attestation.

**Azure**: The engine obtains a Managed Service Identity (MSI) token and the attested instance metadata document, then verifies both JWTs against Microsoft Entra ID's JWKS endpoint.

### Trust Correlation with Security Score

The attestation tier directly influences the security score floor --- a cryptographically attested workload cannot score below a certain threshold regardless of other factors:

| Trust Level | Minimum Score |
|-------------|---------------|
| Cryptographic | 90 |
| High | 70 |
| Medium | 55 |
| Low | 40 |

Additional bonuses and penalties apply on top of the floor:
- Multiple attestation methods passed: **+5**
- No static credentials detected: **+5**
- No owner assigned: **-10**
- No team assigned: **-5**
- Stale credentials detected: **-5**
- Credentials not stored in a vault: **-10**

### WID Token Structure

Upon successful attestation, WID issues a short-lived token that encodes the attestation result:

```json
{
  "typ": "WID-TOKEN",
  "sub": "spiffe://wid-platform/workload/billing-agent",
  "wid": {
    "trust_level": "cryptographic",
    "attestation_method": "gcp-metadata-jwt",
    "is_ai_agent": true,
    "attestation_chain": [
      { "method": "gcp-metadata-jwt", "trust": "cryptographic", "tier": 1 }
    ]
  }
}
```

This token travels with every request through the edge gateway. Downstream policy decisions reference the trust level, attestation method, and AI agent flag without re-performing attestation.

### Continuous Re-Attestation

WID does not treat attestation as a one-time event. A scheduled process monitors token TTLs and triggers re-attestation when a token is within 20% of its expiry window. For a 1-hour Tier 1 token, re-attestation begins at the 48-minute mark. This ensures uninterrupted service while maintaining fresh evidence.

---

## 4. Identity Graph Construction

The identity graph is the beating heart of WID. It is a directed graph that represents every workload, identity, credential, resource, and relationship in the customer's infrastructure. It answers questions that no other tool can: "If this service account is compromised, what can the attacker reach?"

### Node Taxonomy

The graph contains **22 node types** across 7 categories:

| Category | Node Types | Purpose |
|----------|------------|---------|
| **Human** | `user` | Human operators with IAM bindings |
| **Identity** | `service-account`, `managed-identity`, `iam-role`, `iam-policy`, `spiffe-id` | Authentication principals |
| **GCP Workloads** | `cloud-run`, `cloud-run-service`, `gce-instance`, `cloud-function`, `gke-cluster` | Google Cloud compute |
| **AWS Workloads** | `lambda`, `ec2`, `ecs-task` | Amazon Web Services compute |
| **Containers** | `container`, `pod` | Docker and Kubernetes workloads |
| **AI** | `a2a-agent`, `mcp-server` | AI agent protocols |
| **Resources** | `resource`, `external-resource`, `credential`, `external-api`, `gcs-bucket`, `cloud-sql` | Data stores, APIs, secrets |
| **Network** | `exposure`, `firewall-rule` | Network topology and access |

### Relationship Taxonomy

The graph uses **17+ relationship types** across 4 semantic categories, each color-coded in the UI for instant visual recognition:

**Network Exposure (red)** --- "Who can reach this from the internet?"
- `exposed-via`: Workload accessible from the internet through a load balancer or public IP
- `allows-ingress-from`: Firewall rule permits inbound traffic from a source
- `publicly-exposes`: Public exposure without authentication or access controls

**Identity Binding (purple)** --- "Who does this workload authenticate as?"
- `runs-as`: Workload authenticates using this service account or managed identity
- `shares-identity`: Multiple workloads use the same service account (a finding in itself)
- `communicates-with`: Workloads on the same network with direct reachability
- `identifies`: SPIFFE ID cryptographically bound to this workload

**Privilege Chain (amber)** --- "What can this identity access?"
- `has-role`: Identity has been granted an IAM role
- `grants-access`: Role grants access to a specific resource
- `holds-credential`: Identity holds a credential (API key, secret, certificate)
- `accesses-api`: Credential is used to call an external API
- `has-policy`: IAM policy attached to identity
- `can-assume`: Identity can assume a role in another account (cross-account)
- `can-escalate-to`: Identity can escalate privileges (e.g., `iam:PassRole`)

**Agent Protocol (pink)** --- "How do AI agents interact?"
- `runs-as-protocol`: Workload implements A2A or MCP protocol
- `uses-mcp-server`: Agent uses an MCP server for tool access
- `can-delegate-to`: Agent can delegate tasks to another agent

### Edge Provenance

Every edge in the graph carries two pieces of metadata that make it auditable:

- **`discovered_by`**: The API or mechanism that detected the relationship (e.g., "GCP Cloud Run API", "A2A protocol probe", "Docker network inspection")
- **`evidence`**: A full sentence explaining what was found and what it means (e.g., "billing-agent runs as billing-sa@project.iam.gserviceaccount.com, discovered via GCP Cloud Run service configuration")

This provenance chain means every line on the graph can be traced back to a specific API call or scan result. Security teams can validate findings independently.

---

## 5. Relationship Generation Pipeline

Building the identity graph is not a single scan --- it is a 7-phase pipeline that progressively enriches the graph from basic workload nodes to full attack paths.

### Phase 1 --- Workload Nodes

For every workload discovered by the cloud scanners (GCP, AWS, Azure, Docker, on-prem), create a graph node with a stable identifier (`w:{workload_id}`). This is the foundation --- every subsequent phase connects to these nodes.

### Phase 2 --- Identity Nodes

Extract identity principals from each workload: service accounts, IAM roles, managed identities, human users, and groups. Each identity gets a namespaced node (`i:{provider}:{name}`) to prevent collisions across clouds.

### Phase 3 --- IAM Bindings

Map the privilege chains from identities to resources:
- **GCP**: Service account to IAM role to resource (via `getIamPolicy` on each resource)
- **AWS**: IAM role to attached policies to ARN-level resource grants
- **Azure**: Role assignments from Entra ID to resource scopes
- **Kubernetes**: RBAC ClusterRoles and Roles to service accounts via RoleBindings

This phase creates the amber "privilege chain" edges that are critical for blast radius computation.

### Phase 4 --- Network and Exposure

Detect how workloads are accessible from the network:
- **Public ingress**: Load balancers, public IPs, ingress controllers without authentication
- **Internal connectivity**: VPC peering, shared subnets, Docker networks
- **Security groups and NSGs**: Firewall rules that permit or deny traffic

Creates exposure nodes (`exp:public`, `exp:internal`) and the red "network exposure" edges.

### Phase 5 --- Shared Identities

Detect when multiple workloads use the same service account. This is a common misconfiguration and a critical finding: if one workload is compromised, the attacker inherits the identity of all workloads sharing that service account.

The pipeline uses a **hub-and-spoke pattern** for shared identity edges: all workloads connect to the shared service account node, rather than creating pairwise edges between every pair of workloads. This avoids O(n^2) edge explosion while preserving the full blast radius information.

### Phase 6 --- Credential Nodes

Discover credentials associated with each workload:
- **User-managed keys**: API keys, service account keys, with age and rotation status
- **External API credentials**: Detected from environment variable names (key patterns like `*_API_KEY`, `*_SECRET`) and metadata.credentials fields
- **Storage method tracking**: Whether credentials are stored in a vault, in environment variables, or hardcoded

Each credential becomes a node with edges to the identity that holds it (`holds-credential`) and the resource it accesses (`accesses-api`).

### Phase 7 --- AI and Protocol-Specific

The final phase detects AI-specific relationships:
- **A2A agent relationships**: Which agents can delegate to which other agents, discovered via Agent Card probing
- **MCP server relationships**: Which agents use which MCP servers, discovered via MCP protocol probing
- **AI endpoint relationships**: Which workloads call AI/LLM provider APIs (OpenAI, Anthropic, Google AI, Cohere, HuggingFace)

---

## 6. Attack Path Detection

The attack path engine runs 11 automated detectors that traverse the identity graph to find exploitable paths. Each detector answers a specific question about the customer's security posture.

### Detector Catalog

| # | Detector | Question It Answers | BFS Strategy | Default Severity |
|---|----------|-------------------|-------------|-----------------|
| 1 | **Shared SA Blast Radius** | "If this service account leaks, how many services are affected?" | BFS from each service sharing the SA. If any is publicly exposed, severity escalates to critical. | High/Critical |
| 2 | **Key Leak to Sensitive Resources** | "Can a leaked user-managed credential reach sensitive data?" | BFS from credential node through privilege chain edges. | Critical |
| 3 | **Public to Internal Pivot** | "Can an attacker pivot from a public service to internal resources via shared identity?" | BFS from public nodes following identity binding edges. | Always Critical |
| 4 | **Over-Privileged Roles** | "Which identities have excessive permissions relative to their actual usage?" | BFS counts sensitive resource targets reachable from the role. | High |
| 5 | **Privilege Escalation** | "Can an identity escalate via iam:PassRole or equivalent?" | BFS from the escalator identity through escalation edges. | Always Critical |
| 6 | **Cross-Account Trust** | "Can an external account assume roles in this environment?" | Checks for ExternalId condition. Missing ExternalId = critical. | Critical/High |
| 7 | **Unbounded Admin** | "Does any identity have admin access without a permission boundary?" | Direct check: admin role present AND no permission boundary attached. | Critical |
| 8 | **Public Data Exposure** | "Is any data store publicly accessible?" | Direct detection: `is_public = true` on data store nodes. No BFS needed. | High |
| 9 | **Unencrypted Data Store** | "Is any data store unencrypted at rest?" | Direct check: `storage_encrypted = false`. | High |
| 10 | **Internet-to-Data Path** | "Can an attacker reach a data store from the public internet?" | BFS from `exp:public` through all edge types to any data store node. | Always Critical |
| 11 | **Overly Permissive Security Group** | "Does any security group allow unrestricted public internet ingress?" | Checks for `0.0.0.0/0` source on ingress rules protecting workloads. | High |

Additional finding types are generated by the protocol scanner: `static-external-credential`, `a2a-no-auth`, `a2a-unsigned-card`, `mcp-static-credentials`, `toxic-combo`, `public-exposure-untagged`, `unused-iam-role`, `orphaned-asset`.

### Blast Radius Calculation

For each attack path, the engine computes the blast radius --- the total number of workload-type nodes reachable from the attack path's seed nodes.

**Algorithm**: Breadth-first search (BFS) from each seed node. The following edge types are traversed:
- `runs-as` (reversed direction --- from identity back to workload)
- `has-role`
- `grants-access`
- `holds-credential`
- `accesses-api`
- `can-delegate-to`

Only nodes of workload types (cloud-run, lambda, ec2, container, pod, etc.) are counted in the blast radius. Identity and credential nodes are traversal intermediaries, not endpoints.

The blast radius number appears on every attack path in the UI and directly influences remediation priority.

---

## 7. Policy Evaluation Pipeline

The policy engine is the brain of enforcement. It evaluates every request against a set of policies and produces a verdict: allow, deny, or monitor.

### Policy Types

WID supports 6 policy types, each addressing a different security concern:

| Type | Purpose | Example |
|------|---------|---------|
| **Compliance/Posture** | Enforce organizational standards | "All production workloads must have an owner" |
| **Lifecycle** | Control credential and workload lifecycle | "Rotate credentials older than 90 days" |
| **Access** | Control which workloads can reach which destinations | "Only billing-agent may call Stripe API" |
| **Least Privilege** | Detect and restrict excessive permissions | "No workload may have more than 3 IAM roles" |
| **Conditional Access** | Time-based or context-based restrictions | "Allow database access only during business hours" |
| **AI Agent** | AI-specific controls | "Agent chains must not exceed depth of 5" |

### Evaluation Algorithm

For each incoming request, the policy engine executes the following steps:

**Step 1 --- Scope Check**: Load all policies that match the request's context. A policy matches if its scope conditions align with the request's environment, workload types, team, specific workload ID, or server ID. Global policies (no scope restrictions) match everything.

**Step 2 --- Build Evaluation Context**: Merge attributes from multiple sources into a single context object:
- Client attributes (source workload, identity, trust level)
- Server attributes (destination workload, resource type)
- Runtime attributes (time of day, day of week, request method, path)
- AI attributes (agent chain context, MCP server details, delegation depth)

**Step 3 --- Evaluate Conditions**: Each policy contains a list of conditions. All conditions must be true for the policy to match (AND logic). For each condition:
- Resolve the field using dot notation (e.g., `source.trust_level`, `chain.depth`)
- Apply the operator with the specified value

**Step 4 --- Determine Violation**: Based on the policy's effect (`allow` or `deny`):
- A `deny` policy that matches = violation (block)
- An `allow` policy that fails to match = violation (no explicit permission)

**Step 5 --- Priority Ordering**: Policies are evaluated in priority order (lower number = higher priority):
- First deny wins: immediately return REJECT
- First allow wins: immediately return FORWARD
- No match: apply the default action (configurable per deployment, typically deny for zero-trust)

### Condition Operators

The policy engine supports 30+ operators across multiple data types:

| Category | Operators |
|----------|-----------|
| **String** | `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `matches` (regex) |
| **Numeric** | `gt`, `gte`, `lt`, `lte`, `between` |
| **Boolean** | `is_true`, `is_false` |
| **Existence** | `exists`, `not_exists` |
| **Date** | `older_than_days`, `newer_than_days` |
| **Time** | `within_time_window` |
| **Array** | `includes_any`, `includes_all`, `exceeds_count` |
| **Identity** | `in`, `not_in` |

### Action Types

When a policy triggers, one or more actions execute:

| Action | Behavior |
|--------|----------|
| `allow` | Permit the request |
| `deny` / `block_deploy` | Reject the request (HTTP 403) |
| `flag` | Log a finding without blocking |
| `notify` | Send alert to configured channel |
| `quarantine` | Isolate the workload from network |
| `rate_limit` | Throttle requests from this source |
| `require_approval` | Hold request pending human approval |
| `require_attest` | Require fresh attestation before proceeding |
| `revoke_access` | Remove credential or role binding |
| `force_rotation` | Trigger immediate credential rotation |
| `disable_identity` | Disable the service account or managed identity |
| `auto_remediate` | Execute automated remediation playbook |
| `kill_agent` | Terminate an AI agent process |
| `restrict_tools` | Limit which MCP tools an agent can invoke |
| `require_human_loop` | Force human-in-the-loop for subsequent actions |
| `bind_delegator` | Lock delegation chain to specific origin |

---

## 8. Progressive Enforcement: Simulate, Audit, Enforce

This is WID's core selling point. No other NHI platform offers graduated enforcement that lets security teams preview impact before touching production traffic.

### The Problem

Security teams know they need to restrict non-human identity access. But they are terrified of breaking production. A misconfigured policy that blocks a payment service from reaching the payment API causes an outage that costs more than the security risk it was mitigating. The result: policies are written but never enforced. Security posture documents exist, but enforcement is zero.

### The Solution: Three-Stage Graduation

```
    SIMULATE                    AUDIT                       ENFORCE

    "What would happen?"        "Log everything,            "Block unauthorized
                                 break nothing"              traffic"

    +-------------------+       +-------------------+       +-------------------+
    | Evaluate policies |       | Evaluate policies |       | Evaluate policies |
    | Log WOULD_BLOCK   |       | Log WOULD_BLOCK   |       | Return HTTP 403   |
    | Show in panel     |       | Amber dashed edges|       | Sever graph edges |
    | Zero traffic      |       | Amber node rings  |       | Green node rings  |
    |   impact          |       | Zero traffic      |       | Score improvement |
    |                   |       |   impact          |       | Blast radius drop |
    +-------------------+       +-------------------+       +-------------------+

    Duration: Hours/days        Duration: 1-2 weeks         Duration: Permanent
    Audience: Security eng      Audience: Security + SRE    Audience: Production
```

**Simulate**: Policies evaluate against live traffic but never block anything. The UI shows WOULD_BLOCK decisions in the inspector panel and highlights violating nodes on the graph. Security teams use this to answer: "If I enforce this policy, what breaks?" There are no graph changes, no edge modifications, no score updates.

**Audit**: All violations are recorded. Traffic is never blocked --- the verdict is always "allow." The graph shows amber dashed edges on relationships that would be severed, and amber rings around affected nodes. Live WOULD_BLOCK decision streams flow to the Access Events page. Security teams share this with SRE teams: "Here is what we plan to enforce. Review these violations for false positives."

**Enforce**: Violations block traffic (HTTP 403). The graph updates in real-time: edges turn gray and dashed (severed), credential nodes dim to 40% opacity, enforced nodes turn green with a shield icon. Security scores improve, blast radius numbers drop, and attack path counts decrease. Every blocked request is logged with full context for audit.

### Visual Progression

The UI displays a 3-step stepper indicator for each policy:

```
    [ SIM ] -----> [ AUDIT ] -----> [ ENFORCE ]
      gray          amber            green
```

Each step shows the timestamp of when it was activated and the user who activated it. This creates an audit trail of the organizational decision process.

### Gateway Evaluation Hot Path

When a request arrives at an edge gateway, the following evaluation occurs:

1. **WID Token Validation**: Verify HMAC-SHA256 signature, check expiry, extract SPIFFE ID and trust level from the token
2. **Workload Registry Check**: Resolve source and destination workloads. Unregistered workloads are denied (zero-trust default)
3. **AI Traffic Detection**: If the destination matches a known AI provider endpoint, query daily usage statistics for budget and rate enforcement
4. **Multi-Policy Evaluation**: Enforce-mode policies evaluated first (can block). Audit-mode policies evaluated second (log only, never block)
5. **Verdict Determination**: Deny overrides allow. No match falls through to the default action
6. **Decision Logging**: Full context persisted --- decision_id, trace_id, hop_index, token_context, request_context, response_context, latency_ms, cached flag

Total latency: 12-17ms (dominated by database I/O for decision logging).

### Failure Semantics

Every failure mode has an explicit, configurable behavior:

| Failure | Default Behavior | Rationale |
|---------|-----------------|-----------|
| Normal operation | Audit + fail-open | Safe deployment: new gateways don't break anything |
| Unregistered workload | Deny | Zero-trust: unknown workloads are not trusted |
| Invalid WID token | Deny | Tokens are the identity proof; invalid = untrusted |
| Policy evaluation timeout | Allow + log | Degraded but not blocking; alert triggers investigation |
| Database unavailable | Allow (cached policies) | Cached policies still apply; audit events buffered locally |

---

## 9. Remediation Control Scoring (Playbook)

When an attack path is detected, the platform does not just flag the problem --- it ranks the available remediation controls by effectiveness. This is the Playbook.

### The Scoring Model

Each control is scored across 5 dimensions using a composite formula. The goal is to surface the control that breaks the most attack paths with the least operational disruption.

| Dimension | Weight | What It Measures |
|-----------|--------|-----------------|
| **Path Break Strength** | 40% | How effectively does this control sever attack paths? |
| **Feasibility** | Hard gate | Are the preconditions met to execute this control? |
| **Blast Radius** | 20% (inverse) | How many workloads are affected by this remediation? Fewer = better. |
| **Operational Cost** | 20% (inverse) | How much effort to implement and maintain? Lower = better. |
| **Confidence** | 20% | How likely is this control to work as expected? |

### Path Break Strength (40%)

This is the most heavily weighted factor because the primary goal of remediation is to break attack paths.

The score considers:
- **Edge position in the attack path**: Entry-point edges (the first hop from public exposure) score 100. Credential edges (where secrets are held) score 70. Resource-adjacent edges (last hop before data) score 40. Breaking an entry edge is more valuable because it prevents the entire chain.
- **Number of edges severed**: Controls that break multiple edges simultaneously score higher.
- **Crown jewel proximity**: Controls that protect high-value resources (databases, payment APIs, secrets vaults) score higher than those protecting low-value targets.

### Feasibility (Hard Gate)

Feasibility is not a weighted factor --- it is a hard gate. If the preconditions for a control are not met, the control's total score is multiplied by 0.3, effectively pushing it to the bottom of the list.

Preconditions checked include:
- `can-split-workload`: Can the workload's identity be separated from shared service accounts?
- `delegation-chain`: Does the infrastructure support delegation chains for credential rotation?
- `approval-workflow`: Is there an approval workflow configured for this remediation type?

A control that would be highly effective but cannot be executed is clearly marked as infeasible rather than hidden, so teams know what to work toward.

### Blast Radius (20%, Inverse)

Fewer affected workloads = higher score. The penalty is 8 points per affected workload. A control that affects 1 workload scores near 100. A control that affects 10 workloads scores near 20.

This factor prevents the system from recommending "rotate all service account keys" when only one specific key is the problem.

### Operational Cost (20%, Inverse)

Three sub-dimensions contribute:
- **Implementation effort**: One-click policy deployment vs. multi-week infrastructure change
- **Ongoing toil**: Does this control require continuous human attention?
- **Expertise required**: Can a junior engineer execute this, or does it need a principal architect?

### Confidence (20%)

Based on the control's action type:

| Action Type | Confidence | Rationale |
|-------------|-----------|-----------|
| Policy enforcement | 90% | Well-understood, reversible, immediate effect |
| Remediation (credential rotation) | 85% | Proven process but requires coordination |
| Replacement (migrate to managed identity) | 80% | Effective but involves more moving parts |
| Hardening (restrict permissions) | 70% | Requires careful scoping to avoid breaking things |
| Architecture change (split service) | 60% | High-effort, multi-team, longer timeline |

### Composite Formula

```
Score = ROUND(
    (path_break * 0.40 * feasibility_multiplier)
  + (blast_radius_score * 0.20)
  + (operational_cost_score * 0.20)
  + (confidence * 0.20)
)
```

Controls are sorted by composite score descending. The highest-scoring control is the recommended first action.

### Remediation Categories

Controls are classified into 6 categories, each with a distinct UI treatment:

| Category | Examples | UI Treatment |
|----------|----------|-------------|
| **Policy** | Deploy access policy, enforce MCP tool whitelist | Simulate/Audit/Enforce buttons |
| **IaC** | Terraform to split service account, CloudFormation to add permission boundary | CLI commands, Terraform export |
| **Infrastructure** | Rotate credentials, restrict security group | CLI steps, one-click where possible |
| **Code Change** | Remove hardcoded secrets, add credential injection | Code diff suggestions |
| **Vendor** | Contact vendor to enable SSO, request API key rotation | Vendor-specific guidance |
| **Process** | Establish approval workflow, create runbook | Process documentation |

---

## 10. AI Agent and MCP Protocol Detection

WID is built from the ground up for the AI agent era. It detects, classifies, and monitors two critical protocols: Google's Agent-to-Agent (A2A) protocol and Anthropic's Model Context Protocol (MCP).

### Signal-Based Classification

Rather than relying on a single indicator, WID uses a multi-signal scoring system to classify workloads as AI agents or MCP servers.

**MCP Server Signals:**

| Signal Source | What Is Checked | Points |
|---------------|----------------|--------|
| Container image | Patterns like `mcp-server`, `modelcontextprotocol` in image name | 3 |
| Environment variables | `MCP_SERVER_URL`, `MCP_TRANSPORT`, `MCP_PORT` | 2 |
| Labels/annotations | `mcp.server`, `ai.mcp.server` in container labels | 2 |
| Command/entrypoint | MCP-related command patterns in container startup | 2 |

**Classification threshold**: A workload scoring 2 or more points is classified as an MCP server candidate and subjected to protocol probing.

**A2A Agent Signals**: The same pattern applies --- image names, environment variables (`A2A_AGENT_URL`, `A2A_AGENT_CARD`), and labels are scored. The same 2-point threshold triggers agent protocol probing.

### Protocol Probing

When a workload crosses the classification threshold, WID performs active probing to confirm the protocol and collect capabilities:

1. **Agent Card Discovery**: `POST /api/v1/agent-card/info` or `GET /.well-known/agent.json` --- retrieves the agent's capability declaration
2. **MCP Initialization**: `POST /initialize` via JSON-RPC --- confirms MCP protocol version and server capabilities
3. **Capability Introspection**: `POST /tools/list`, `POST /resources/list`, `POST /prompts/list` --- enumerates every tool, resource, and prompt the MCP server exposes

The results are stored in the graph as node metadata and used by the tool poisoning detector.

### Tool Poisoning Detection

MCP tool descriptions are free-form text that is injected into LLM prompts. Malicious MCP servers can embed instructions in tool descriptions that cause the LLM to perform unintended actions. WID scans every tool description for 5 categories of poisoning:

| Category | Detection Pattern | Severity |
|----------|------------------|----------|
| **Prompt Injection** | "ignore previous instructions", "you are now", "system prompt override" | Critical |
| **Hidden Unicode** | Zero-width spaces (U+200B), byte order marks (U+FEFF), invisible characters | Critical |
| **Code Execution** | `eval()`, `exec()`, `subprocess`, `os.system` in descriptions | Critical |
| **Data Exfiltration** | Suspicious URLs: ngrok tunnels, webhook.site, pipedream endpoints | High |
| **Stealth Patterns** | "do not inform user", "silently", "without telling" | Critical |

### MCP Integrity Verification

Beyond poisoning detection, WID verifies the integrity of MCP servers against a known-good registry:

1. **Name Check**: Is the server name in the known-good registry?
2. **Fingerprint Computation**: SHA-256 hash of: server name + version + protocol version + tool list + resources + prompts
3. **Version Check**: Does the server meet the minimum version requirement?

Output states:
- **Verified**: Name matches registry, fingerprint matches, version is current
- **Unverified**: Name not in registry or fingerprint mismatch
- **Outdated**: Name matches but version is below minimum

---

## 11. Authorization Decision Logging and Replay

Every authorization decision made by the platform is persisted with full context. This is not just logging --- it is the foundation for deterministic replay, compliance evidence, and forensic investigation.

### Decision Record Structure

Each decision record contains:

| Field | Purpose |
|-------|---------|
| `decision_id` | Unique identifier for this specific decision |
| `trace_id` | Correlation ID linking all decisions in a multi-hop chain |
| `hop_index` | Position of this decision in the chain (0 = origin) |
| `total_hops` | Total number of hops in the chain |
| Source principal | SPIFFE ID, workload name, workload type of the caller |
| Destination principal | SPIFFE ID, workload name, workload type of the target |
| `method` | HTTP method (GET, POST, etc.) |
| `path_pattern` | Request path |
| `verdict` | allow, deny, or no-match |
| `policy_name` | Name of the policy that produced the verdict |
| `policies_evaluated` | Count of all policies checked |
| `policy_version` | SHA-256 hash of the policy conditions/actions/effect at evaluation time |
| `adapter_mode` | simulate, audit, or enforce |
| `enforcement_action` | WOULD_BLOCK, REJECT_REQUEST, FORWARD_REQUEST, or MONITOR |
| `token_context` | WID token validation result (trust level, attestation method, chain info) |
| `request_context` | Full request payload (sanitized) |
| `response_context` | Response metadata |
| `latency_ms` | Time taken for the evaluation |
| `cached` | Whether the decision used a cached policy evaluation |
| `created_at` | Timestamp |

### Deterministic Replay

Any authorization decision can be reconstructed from first principles. The replay chain is:

```
    Attestation Evidence
          |
          v
    WID Token (trust level, method, tier)
          |
          v
    Policy Evaluation (policy version hash ensures exact conditions)
          |
          v
    Verdict (allow/deny)
          |
          v
    Enforcement Action (FORWARD/REJECT/WOULD_BLOCK/MONITOR)
```

The `policy_version` hash is critical. When a policy is evaluated for the first time with a given version hash, a snapshot of the policy (conditions, actions, effect, enforcement mode, severity) is written to the `policy_snapshots` table. This means even if the policy is later modified, the exact version used for any historical decision can be retrieved.

The replay endpoint (`GET /api/v1/access/decisions/replay/:traceId`) returns:
- All decision hops in the trace
- The policy version used at each hop
- The request context at each hop
- The verdict at each hop
- Full policy snapshots for every policy version referenced

This capability directly addresses EU AI Act Article 12 (mandatory August 2, 2026), which requires that automated decision-making systems maintain logs sufficient to reconstruct and audit any decision. It also addresses California's ADMT requirement for 5-year decision retention.

### Multi-Hop Trace Correlation

For AI agent chains where Agent A calls Agent B which calls Agent C, the trace_id links all decisions into a single queryable chain. The `hop_index` and `total_hops` fields provide positional context.

The chain analysis endpoint (`GET /api/v1/access/decisions/chain/:traceId`) returns:
- The origin agent (hop 0)
- Authorization status of every hop
- Whether any hop was denied
- Whether any hop used a revoked token
- The full delegation chain with trust levels at each hop

This is the anti-confused-deputy mechanism: policy decisions at hop N have access to the full context of hops 0 through N-1.

---

## 12. Credential Chain Computation

The credential chain answers the question: "Starting from this workload's identity, what credentials does it hold, and what resources can those credentials reach?"

### Algorithm

The computation is a 3-step graph traversal:

**Step 1 --- Find the Identity Node**: Starting from a workload node, follow the `runs-as` edge to find the identity node (service account, managed identity, IAM role) that the workload authenticates as.

**Step 2 --- Collect Credentials**: From the identity node, follow all `holds-credential` edges. Each edge leads to a credential node (API key, secret, certificate, token). Collect every credential.

**Step 3 --- Map to Resources**: From each credential node, follow all `accesses-api` edges. Each edge leads to a resource node (external API, data store, cloud service). Collect every resource.

### Output Structure

The result is a linear chain:

```
    [Identity]  --holds-credential-->  [Credential]  --accesses-api-->  [Resource]

    Example:
    billing-sa      -->  stripe-api-key-prod  -->  Stripe Payments API
    (service-account)    (credential)              (external-api)
```

Each element in the chain includes:
- The node's name and type
- The relationship that connects it to the next element
- Metadata (age of credential, rotation status, storage method, access frequency)

### Purpose

This chain powers the "Credential Chain" visualization in the graph inspector panel. When a security engineer clicks on a workload, they see the complete path from workload identity to every external resource it can reach. Combined with the attack path detectors, this answers: "If this workload is compromised, which external APIs are at risk, and through which specific credentials?"

---

## Appendix: Glossary

| Term | Definition |
|------|-----------|
| **NHI** | Non-Human Identity. Service accounts, API keys, machine credentials, AI agents. |
| **SPIFFE** | Secure Production Identity Framework for Everyone. Standard for workload identity. |
| **SVID** | SPIFFE Verifiable Identity Document. A cryptographic proof of workload identity. |
| **OPA** | Open Policy Agent. Policy engine that evaluates Rego policies. |
| **A2A** | Agent-to-Agent. Google's protocol for AI agent communication. |
| **MCP** | Model Context Protocol. Anthropic's protocol for LLM tool access. |
| **PEP** | Policy Enforcement Point. Where access control decisions are enforced (edge gateway). |
| **LKG** | Last Known Good. The most recent successfully loaded policy bundle. |
| **BFS** | Breadth-First Search. Graph traversal algorithm used in attack path detection. |
| **mTLS** | Mutual TLS. Both client and server present certificates. |
| **IMDSv2** | Instance Metadata Service version 2. AWS's token-based metadata endpoint. |
| **JWKS** | JSON Web Key Set. Public keys for JWT verification. |
| **TTL** | Time To Live. Expiry duration for tokens and cache entries. |
