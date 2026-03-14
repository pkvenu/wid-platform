# WID Platform — System Architecture

> Version 1.0 | March 2026

---

## Introduction

WID is an enterprise-grade Workload Identity platform that discovers, attests, and governs every non-human identity (NHI) across multi-cloud and hybrid infrastructure. It builds a live identity graph showing every workload, its credentials, the external APIs it calls, and the attack paths between them — then enforces policy at the edge without requiring a service mesh.

For market positioning and competitive analysis, see [STRATEGY.md](STRATEGY.md). For algorithms and scoring logic, see [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md). For API reference, see [SPEC.md](SPEC.md).

---

## Design Principles

| Principle | Rationale |
|-----------|-----------|
| **Policy decisions evaluated locally** | Edge gateways evaluate policy using cached OPA bundles. No hot-path dependency on central services. Sub-millisecond policy evaluation. |
| **Control plane can fail without breaking enforcement** | Data plane operates autonomously with last-known-good (LKG) policies. Hub outage = stale UI, not stale enforcement. |
| **No infrastructure prerequisites** | Edge gateway works without Istio, Envoy, or a service mesh. One binary + iptables = enforcement. |
| **Deterministic failure semantics** | Fail-open, fail-closed, or fail-conditional per workload and action type. Explicitly configurable, never ambiguous. |
| **Database is single source of truth** | All state lives in PostgreSQL. No hardcoded mock data, no in-memory-only state, no divergent schemas. |
| **Security by default** | mTLS between services, signed policy bundles, default-deny OPA base policy, ES256 asymmetric tokens, tamper-evident audit logs. |
| **Observe before enforce** | Simulate → Audit → Enforce lifecycle. No policy goes live without observability. Every decision is logged for replay. |

---

## System Context

```
                        ┌─────────────────────────────────────┐
                        │         Cloud Providers              │
                        │  AWS · GCP · Azure · K8s · Docker    │
                        └───────────────┬─────────────────────┘
                                        │ Discovery APIs
                                        ▼
    ┌──────────┐    ┌─────────────────────────────────────────────────┐
    │  SPIRE   │───▶│               WID PLATFORM                      │
    │  (SVID)  │    │                                                  │
    └──────────┘    │  ┌────────────┐  ┌───────────┐  ┌────────────┐  │
                    │  │ Discovery  │  │  Policy   │  │   Token    │  │
    ┌──────────┐    │  │ + Graph    │  │  Engine   │  │  Service   │  │
    │  Vault   │───▶│  └────────────┘  └───────────┘  └────────────┘  │
    │ (Secrets)│    │  ┌────────────┐  ┌───────────┐  ┌────────────┐  │
    └──────────┘    │  │ Credential │  │   Relay   │  │   Web UI   │  │
                    │  │  Broker    │  │   (Hub)   │  │            │  │
    ┌──────────┐    │  └────────────┘  └───────────┘  └────────────┘  │
    │ AI Agents│───▶│            PostgreSQL 16                         │
    │ A2A, MCP │    └─────────────────────┬───────────────────────────┘
    └──────────┘                          │
                                          │ Policy sync, audit events
                                          ▼
                        ┌─────────────────────────────────────┐
                        │          DATA PLANE (Spokes)         │
                        │  Relay (Spoke) + Edge Gateways       │
                        │  Per-workload enforcement             │
                        └─────────────────────────────────────┘
                                          │
                                          ▼
                        ┌─────────────────────────────────────┐
                        │           Outputs                    │
                        │  Enforcement · Audit Logs · Graph    │
                        │  Compliance Evidence · Replay        │
                        └─────────────────────────────────────┘
```

---

## Service Architecture

### Services

| Service | Port | Role | Deployment |
|---------|------|------|------------|
| **Policy Engine** | 3001 | Policy CRUD, evaluation, template management, compliance frameworks, gateway decisions | Control plane |
| **Discovery Service** | 3003 | Workload scanning (17 scanners), identity graph, attack path detection, attestation | Control plane |
| **Token Service** | 3000 | ES256 token issuance, JWKS endpoint, chain tracking, Agent Card signing | Control plane |
| **Credential Broker** | 3002 | Multi-provider secret management (Vault, AWS, GCP, Azure, 1Password) | Control plane |
| **Relay Service** | 3005 | Hub-spoke federation bridge, policy distribution, audit aggregation | Both |
| **Web UI** | 3100 | React dashboard: graph, policies, auth events, compliance, connectors | Control plane |
| **Edge Gateway** | 15001 | Transparent HTTP proxy, per-workload enforcement, AI/MCP telemetry | Data plane |
| **ext-authz Adapter** | 9191 | gRPC ext_authz hook for Envoy/Istio service meshes | Data plane |
| **Policy-Sync Service** | 3001 | Batch decision storage, MCP event ingestion, live decision stream | Control plane |

### Container Diagram

```
    ┌─────────── CONTROL PLANE (can fail without breaking enforcement) ──────────┐
    │                                                                              │
    │  ┌──────────────┐  ┌──────────────┐  ┌───────────────┐  ┌──────────────┐   │
    │  │ Policy Engine│  │ Discovery    │  │ Token Service │  │ Credential   │   │
    │  │ (133 templates│  │ (17 scanners)│  │ (ES256/JWKS) │  │ Broker       │   │
    │  │  5 frameworks)│  │ (32 findings)│  │ (OBO chains) │  │ (5 providers)│   │
    │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
    │         │                 │                  │                  │           │
    │         └────────┬────────┴──────────┬───────┘                  │           │
    │                  │                   │                          │           │
    │           ┌──────▼──────┐    ┌───────▼──────┐                   │           │
    │           │ PostgreSQL  │    │   Web UI     │                   │           │
    │           │ (16 tables) │    │ (React/D3)   │                   │           │
    │           └─────────────┘    └──────────────┘                   │           │
    │                                                                 │           │
    │  ┌──────────────┐                                               │           │
    │  │ Relay (Hub)  │ ◄────────── API key + mTLS ──────────────────┘           │
    │  └──────┬───────┘                                                           │
    └─────────┼───────────────────────────────────────────────────────────────────┘
              │
              │  Policy bundles (pull, 15s) · Audit events (push, 5s) · Heartbeats (60s)
              │
    ┌─────────▼─────── DATA PLANE (must never stop making decisions) ─────────────┐
    │                                                                               │
    │  ┌──────────────┐     ┌──────────────┐  ┌──────────────┐                     │
    │  │ Relay (Spoke)│────▶│ Edge Gateway │  │ Edge Gateway │  ... (1 per wkld)   │
    │  │ (LKG cache)  │     │ (workload A) │  │ (workload B) │                     │
    │  └──────────────┘     └──────────────┘  └──────────────┘                     │
    │                                                                               │
    │  OR:  ┌──────────────┐     ┌─────────────────────────────────┐               │
    │       │ ext-authz    │◄────│ Envoy / Istio sidecar mesh      │               │
    │       │ adapter      │     └─────────────────────────────────┘               │
    │       └──────────────┘                                                       │
    └──────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Plane Architecture

WID provides two mutually exclusive data-plane modes, both backed by the same shared core library (`@wid/core`). This guarantees identical policy evaluation, caching, circuit breaking, and audit logging regardless of deployment mode.

### Mode A: Edge Gateway (Default)

A transparent HTTP proxy deployed as a sidecar alongside each workload. Intercepts outbound traffic via iptables redirect — the workload doesn't know it's being proxied.

```
    ┌──────────────────────────┐
    │  Workload Pod / VM       │
    │  ┌────────┐  ┌─────────┐│
    │  │  App   │──│  Edge   ││  ← iptables REDIRECT (transparent)
    │  │        │  │ Gateway ││  ← Evaluates policy locally
    │  └────────┘  └─────────┘│  ← Emits audit events to relay
    └──────────────────────────┘
```

**When to use**: No service mesh. VMs, Docker, plain Kubernetes, bare metal. This covers 70-80% of enterprise environments.

### Mode B: ext-authz Adapter

A gRPC server implementing Envoy's `ext_authz` API. Plugs into an existing Istio or standalone Envoy deployment.

```
    ┌──────────┐    ┌──────────┐    ┌─────────────┐
    │ App Pod  │───▶│  Envoy   │───▶│ ext-authz   │
    │          │    │ sidecar  │    │ adapter      │
    └──────────┘    └──────────┘    └─────────────┘
```

**When to use**: Customer already has Istio, Linkerd, Consul, or standalone Envoy.

### Feature Parity (ADR-06)

| Capability | Edge Gateway | ext-authz Adapter |
|------------|:---:|:---:|
| Policy caching (LRU + TTL) | Yes | Yes |
| Circuit breaker | Yes | Yes |
| Rate limiter | Yes | Yes |
| Credential buffering | Yes | Yes |
| Audit buffer (batch flush) | Yes | Yes |
| AI traffic inspection | Yes | Yes |
| MCP telemetry | Yes | Yes |
| Prometheus metrics | Yes | Yes |
| Header sanitization | Yes | Yes |
| iptables transparent redirect | Yes | N/A |
| gRPC ext_authz protocol | N/A | Yes |

One fix to `@wid/core` applies to both modes simultaneously.

---

## Hub-and-Spoke Federation

WID uses a hub-and-spoke architecture for multi-environment deployment. The hub (control plane) runs centrally. Spokes (relay + gateways) run in each customer environment.

```
                    ┌─── GCP Cloud Run (CENTRAL HUB) ───┐
                    │                                     │
                    │  Policy Engine · Discovery · Token  │
                    │  Credential Broker · Web UI         │
                    │  Relay (Hub) · Cloud SQL (PG 16)    │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
       ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
       │ AWS Spoke   │     │ Docker Spoke│     │ Azure Spoke │
       │ ECS Fargate │     │ Compose     │     │ Container   │
       │ relay + GWs │     │ relay + GWs │     │ Apps + GWs  │
       └─────────────┘     └─────────────┘     └─────────────┘
```

### Sync Cadences

| Channel | Direction | Interval | Purpose |
|---------|-----------|----------|---------|
| Policy sync | Hub → Spoke (pull) | 15 seconds | Signed policy bundles with version hash |
| Audit events | Spoke → Hub (push) | 5 seconds | Batch-flushed decision logs |
| Heartbeats | Spoke → Hub | 60 seconds | Environment health, gateway count, last sync |

### Offline Resilience

- **LKG policies**: Spokes cache the last-known-good policy bundle. If the hub is unreachable, enforcement continues with cached policies.
- **Audit buffering**: Events are buffered locally (configurable max) and flushed when connectivity returns. No audit data is lost during partitions.
- **Automatic reconnection**: Spokes retry hub connection with exponential backoff. No manual intervention required.

---

## Identity and Trust Model

WID enforces a 4-tier trust hierarchy. Higher tiers earn longer token TTLs and access to more sensitive resources.

| Tier | Trust Level | Methods | Token TTL |
|------|-------------|---------|-----------|
| **1 — Cryptographic** | `cryptographic` | SPIRE X.509 SVID, GCP metadata JWT (JWKS-verified), AWS IMDSv2 signed document, Azure MSI signed JWT, mTLS | 1 hour |
| **2 — Token-Based** | `high` | JWT/OIDC verified, GitHub Actions OIDC, Vault token introspection, K8s TokenReview, AWS STS | 30 min |
| **3 — Attribute-Based** | `medium` | Multi-signal ABAC (3+ runtime attributes), container verification (image digest + labels), network verification | 15 min |
| **4 — Policy/Manual** | `low` | Service catalog match, OPA/Rego evaluation, manual operator approval | 5 min |

**Multi-signal bonus**: If 4+ attestation methods pass simultaneously, trust is boosted by one tier — the machine equivalent of multi-factor authentication.

### WID Token Structure (ES256)

```json
{
  "alg": "ES256",
  "typ": "WID-TOKEN",
  "kid": "wid-es256-2026"
}
.
{
  "iss": "wid-platform://wid-platform",
  "sub": "spiffe://wid-platform/workload/billing-agent",
  "aud": "wid-gateway://wid-platform",
  "exp": 1709603600,
  "jti": "wid-1709600000-abc123",
  "wid": {
    "workload_name": "billing-agent",
    "trust_level": "cryptographic",
    "attestation_method": "gcp-metadata-jwt",
    "is_ai_agent": true,
    "attestation_chain": [
      { "method": "gcp-metadata-jwt", "trust": "cryptographic", "tier": 1 }
    ]
  }
}
```

Tokens are signed with ECDSA P-256 (ES256). Only the token-service holds the private key. All other services verify via the JWKS endpoint (ADR-10).

---

## Policy Evaluation Pipeline

When an edge gateway intercepts a request, it evaluates policy through a 6-stage pipeline:

```
    Request ──▶ [1. Token    ] ──▶ [2. Workload ] ──▶ [3. AI Traffic]
                [   Validation]     [   Registry  ]     [   Detection ]
                                                              │
    Response ◀── [6. Decision ] ◀── [5. Verdict   ] ◀── [4. Multi-Policy]
                 [   Logging  ]     [   Determine ]     [   Evaluation ]
```

| Stage | What | Hot-path latency |
|-------|------|-----------------|
| 1. Token validation | Verify ES256 signature, check expiry, extract SPIFFE ID | < 1ms |
| 2. Workload registry | Resolve source + destination from DB (cached) | < 1ms |
| 3. AI traffic detection | Match destination against known AI providers, build cost context | < 1ms |
| 4. Multi-policy evaluation | Enforce-mode first (deny = block), then audit-mode (log only), then compliance | 1-3ms |
| 5. Verdict determination | First-deny-wins for enforce; always-allow for audit | < 1ms |
| 6. Decision logging | Async write to audit buffer (never blocks hot path) | 0ms (async) |

**Total hot-path latency**: ~12-17ms (dominated by network I/O, not policy evaluation).

The evaluator supports 25+ condition operators across string, numeric, boolean, existence, time, and array categories. Policies support `simulate`, `audit`, and `enforce` modes — see [POLICY-ENFORCEMENT.md](../shared/POLICY-ENFORCEMENT.md).

---

## Identity Graph

The identity graph answers: **"If this identity is compromised, what can the attacker reach?"**

### Node Taxonomy (22 types)

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

### Relationship Taxonomy (17+ types)

| Category | Types | Example |
|----------|-------|---------|
| Network Exposure | `exposed-via`, `allows-ingress-from`, `publicly-exposes` | Cloud Run → public-internet |
| Identity Binding | `runs-as`, `shares-identity`, `communicates-with`, `identifies` | Workload → Service Account |
| Privilege Chain | `has-role`, `grants-access`, `holds-credential`, `accesses-api`, `can-assume`, `can-escalate-to` | SA → roles/editor → Cloud SQL |
| Agent Protocol | `runs-as-protocol`, `uses-mcp-server` | Agent → A2A protocol |

### Attack Path Detection

32 finding types across 11 detectors, using BFS-based blast radius computation:

- **Credential exposure**: leaked-credentials, static-external-credential, over-privileged-iam
- **Network risk**: public-internal-pivot, internet-to-data-path
- **Identity abuse**: shared-service-account, cross-account-trust
- **AI/Agent**: a2a-unsigned-card, a2a-invalid-signature, a2a-no-auth, mcp-tool-poisoning, mcp-capability-drift
- **Supply chain**: toxic-credential-combo, shadow-ai-usage

For the full algorithm, see [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md) section 6.

---

## Data Flow Diagrams

### Discovery Flow

```
Cloud Provider APIs ──▶ Cloud Scanners (GCP/AWS/Azure/K8s/Docker)
        │
        ▼
  Workload DB ──▶ Protocol Scanner (A2A/MCP/OAuth probing)
        │
        ▼
  Relationship Scanner (5-phase pipeline) ──▶ Attack Path Detectors (11)
        │
        ▼
  Identity Graph ──▶ Graph API ──▶ Web UI (D3 force-directed)
```

### Enforcement Flow

```
Agent Request ──▶ Edge Gateway ──▶ Policy Evaluation (6 stages)
        │                                    │
        │                              ┌─────▼──────┐
        │                              │ allow/deny  │
        │                              └─────┬───────┘
        ▼                                    │
  Destination ◀──────────────────────────────┘
        │
  Audit Buffer ──(batch 5s)──▶ Relay ──▶ Policy-Sync DB ──▶ Decision Stream
```

### Compliance Flow

```
Framework (SOC 2 / PCI DSS / NIST / ISO / EU AI Act)
        │
        ▼
  Template Catalog (133 templates, 68 controls)
        │
  One-click deploy ──▶ Audit mode (observe violations)
        │
  Review ──▶ Promote to enforce ──▶ Coverage tracking
```

---

## Technology Decisions (ADR Summary)

| # | Decision | Rationale |
|---|----------|-----------|
| ADR-01 | Edge Gateway as default | Works everywhere without service mesh prerequisites |
| ADR-02 | Hub-and-spoke relay | Control plane centralized; data plane operates locally with cached policies |
| ADR-03 | Relay buffers audit events | Data plane never blocks on audit write. Batch-flush upstream |
| ADR-04 | Single authoritative `init.sql` | All tables defined once. No divergence between services |
| ADR-05 | OPA embedded in policy evaluation | Local evaluation on hot path. No round-trip to central |
| ADR-06 | Shared data-plane-core library | One fix applies to both edge-gateway and ext-authz-adapter |
| ADR-07 | Trace IDs across agent chains | Full decision chain queryable and replayable in audit |
| ADR-08 | Vault for credential brokering | Pluggable providers: Vault, AWS, GCP, Azure, 1Password |
| ADR-09 | Remediation Decision Framework | 6-category taxonomy, decision routing, approval tiers |
| ADR-10 | ES256 for workload tokens | Asymmetric signing. Only token-service holds private key. JWKS for verification |
| ADR-11 | MCP Runtime Auditing + Agent Card Signing | Zero-copy tee, async parse. Tool argument values redacted by default |

---

## Related Documentation

- [SPEC.md](SPEC.md) — API endpoints, data models, database schema
- [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md) — Algorithms, scoring, decision processes
- [STRATEGY.md](STRATEGY.md) — Market positioning, competitive analysis
- [threat-model.md](threat-model.md) — STRIDE analysis, trust boundaries, residual risks
- [deployment-models.md](deployment-models.md) — 4 deployment modes (SaaS, self-hosted, air-gapped, edge-only)
- [attack-path-demo.md](attack-path-demo.md) — End-to-end attack path detection walkthrough
- [shared/ARCHITECTURE.md](../shared/ARCHITECTURE.md) — Dual-mode data plane details
- [shared/ATTESTATION.md](../shared/ATTESTATION.md) — 4-tier trust model
- [shared/POLICY-ENFORCEMENT.md](../shared/POLICY-ENFORCEMENT.md) — Simulate/Audit/Enforce lifecycle
