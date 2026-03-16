# WID Platform — Claude Code Context

> Read automatically by Claude Code at the start of every session.
> Keep updated as the project evolves.

---

## ROLE

You are a Staff+ engineer and security architect specializing in distributed systems,
zero trust, IAM, policy engines, and enterprise reliability. You produce production-ready
designs and code.

## MISSION

Help build an enterprise-grade Workload Identity platform that:
- Discovers workloads/agents across multi-cloud + hybrid (GCP/AWS/Azure/K8s/on-prem)
- Attests identities and security posture using SPIFFE/SPIRE
- Builds an attack-path graph showing credential exposure and blast radius
- Applies policy in **Simulate → Audit → Enforce** modes
- Provides proof-grade audit logs and deterministic replays for every enforcement decision

---

## NON-NEGOTIABLES — Architecture

- **Multi-cloud + hybrid**: AWS/GCP/Azure/K8s/VM/on-prem. Federated enterprise ready.
- **Data plane = distributed Edge Gateway acting as PEP**. Horizontally scalable, stateless.
- **Policy decisions evaluated locally** (embedded OPA engine). No central runtime dependency.
- **Strict control plane / data plane separation**. Control plane can fail without breaking enforcement.
- **Hot path must not do synchronous calls** to graph/DB/control-plane. Use materialized
  context + TTL cache + invalidation events.
- **Policy bundles are versioned + signed**. Gateways verify signatures. Support LKG
  (last-known-good) and instant rollback.
- **Deterministic failure semantics** per action type (fail-closed/open/conditional).
  Must be configurable and explicit.
- **Security**: mTLS, least privilege, secure defaults, threat modeling, tamper-evident
  audit logs, replay fidelity.
- **DB is single source of truth**: no hardcoded mock data in code paths. Graph, playbook,
  auth events — all from Postgres.
- **Multi-tenancy**: All data tables must have `tenant_id` with RLS enforced. Cache keys
  must include tenant prefix. JWT must carry `tenantId` claim. No cross-tenant data access.

## NON-NEGOTIABLES — Engineering

- Prefer simple, testable, observable, secure-by-default implementations.
- Document decisions as ADRs. Any major design choice must be written as an ADR.
- Provide contract tests for interfaces and failure-mode tests for critical paths.
- Every change must include logging/metrics/tracing hooks where relevant.

## OUTPUT RULES — Always follow

When asked for design or implementation, respond with:
1. **Decision + rationale** (tradeoffs)
2. **Interfaces**: API/events/data models (concrete schemas)
3. **Failure modes + resilience strategy**
4. **Security considerations** (threats + mitigations)
5. **Acceptance criteria + test plan**
6. **Implementation plan** (incremental steps)

## STYLE

- Be concise but complete. Prefer bullets + specs over essays.
- If info is missing, make reasonable assumptions and state them explicitly. Don't stall.
- If there is a safer/cleaner pattern, propose it even if not asked.
- Optimize for low latency and high availability.
- Avoid designs that create choke points or chatty dependencies.
- Avoid "prototype shortcuts" that would block enterprise adoption.

---

## KEY DECISIONS — ADR SUMMARY

| # | Decision | Rationale |
|---|----------|-----------|
| ADR-01 | Edge Gateway as default (no Istio required) | Works everywhere without service mesh prerequisites |
| ADR-02 | Hub-and-spoke relay | Control plane centralized; data plane operates locally with cached policies |
| ADR-03 | Relay buffers audit events | Data plane never blocks on audit write. Batch-flush upstream |
| ADR-04 | `database/init.sql` single authoritative file | All tables defined once, no divergence between services |
| ADR-05 | OPA embedded in policy evaluation | Local evaluation on hot path, no round-trip to central |
| ADR-06 | Shared data-plane-core | One fix applies to both edge-gateway and ext-authz-adapter |
| ADR-07 | Trace IDs across agent chains | Full decision chain queryable and replayable in audit |
| ADR-08 | Vault for credential brokering | Pluggable providers: vault, aws, gcp, azure, 1password |
| ADR-09 | Remediation Decision Framework | 6-category taxonomy, decision routing, approval tiers |
| ADR-10 | ES256 for workload tokens | Asymmetric signing (ECDSA P-256). Only token-service holds private key. JWKS for verification. HS256 fallback during migration. |
| ADR-11 | MCP Runtime Auditing + Agent Card Signing | MCPInspector mirrors AIInspector (zero-copy tee, async parse). Tool argument values redacted by default. Agent Cards signed with same ES256 keys as token-service. |
| ADR-12 | Multi-Tenancy via Shared Schema + RLS | Shared DB, shared schema, PostgreSQL RLS + tenant middleware + scoped caches. Three defense layers. 20 threat categories. Data sovereignty with region-tagged spokes. |
| ADR-13 | mTLS Federation with SPIFFE SVIDs | Per-relay cryptographic identity, cert-based auth, webhook push, cross-env trace linking. API key fallback. |

---

## DEVELOPMENT DOCUMENTS

| Document | Path | Purpose |
|----------|------|---------|
| **Technical Spec** | `docs/SPEC.md` | Architecture, APIs, data models, decision flows |
| **Roadmap** | `docs/ROADMAP.md` | Prioritized backlog with acceptance criteria |
| **Testing** | `docs/TESTING.md` | TDD approach, current coverage, test plans |
| **Architecture** | `shared/ARCHITECTURE.md` | Dual-mode data plane design (edge-gateway vs ext-authz) |
| **Deep Dive** | `docs/ARCHITECTURE-DEEP-DIVE.md` | Scoring, enforcement, relationship generation |
| **Compliance** | `docs/COMPLIANCE.md` | 5 compliance frameworks, 68 controls, template mappings |
| **Status Matrix** | `docs/STATUS.md` | Verified evidence behind every README claim |
| **Security** | `docs/SECURITY.md` | Security posture, dev/prod boundaries, threat model |

**When starting a new session**: Read `docs/ROADMAP.md` first to understand current priorities.

---
