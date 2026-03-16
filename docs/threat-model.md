# WID Platform — Threat Model

> Version 1.0 | March 2026
> STRIDE-per-element analysis of the Workload Identity Defense platform.

---

## 1. Scope and Methodology

### Methodology

This threat model uses **STRIDE-per-element** analysis: each trust boundary in the system is analyzed for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege threats.

### System Under Analysis

WID deployed in production: GCP Cloud Run control plane, spoke data planes across AWS/Azure/Docker/K8s/on-prem, with PostgreSQL (Cloud SQL) as the data store.

### Assets Under Protection

| Asset | Sensitivity | Impact if Compromised |
|-------|-------------|----------------------|
| ES256 private key | Critical | Token forgery — attacker can impersonate any workload |
| Policy bundles | Critical | Policy bypass — attacker can allow/deny arbitrary traffic |
| Audit decision logs | High | Repudiation — attacker can erase evidence of actions |
| Workload tokens (JWTs) | High | Identity spoofing — attacker can assume workload identity |
| Credential material (Vault secrets, API keys) | Critical | Lateral movement — direct access to external systems |
| Identity graph data | High | Reconnaissance — attacker maps all relationships and blast radius |
| Agent Card signing keys | High | Card forgery — attacker can create trusted-looking agents |
| Database (PostgreSQL) | Critical | Full compromise — all state, policies, audit logs, tokens |

---

## 2. Trust Boundaries

```
    INTERNET
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ TB-1 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │
    │  Google Load Balancer (34.120.74.81)
    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ TB-2 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │
    │  ┌─────────────────── GCP Cloud Run ──────────────────┐
    │  │  Policy Engine · Discovery · Token Service · Web UI │
    │  │                                                      │
    │  │  ─ ─ ─ ─ ─ ─ ─ TB-5 ─ ─ ─ ─ ─ ─ ─                │
    │  │  │                                  │                │
    │  │  │  Cloud SQL (PostgreSQL 16)       │                │
    │  │  │  VPC connector, private IP       │                │
    │  │  ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─                 │
    │  └─────────────────┬──────────────────────────────────┘
    │                    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ TB-3 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │                    │
    │         ┌──────────▼──────────┐
    │         │ Relay (Spoke)       │
    │         └──────────┬──────────┘
    │                    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ TB-4 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │                    │
    │         ┌──────────▼──────────┐
    │         │ Edge Gateway        │──── Workloads / AI Agents
    │         └─────────────────────┘
    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ TB-6 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │         Token Service JWKS ────▶ Any consumer
    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ TB-7 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │         Discovery Scanners ────▶ AWS / GCP / Azure APIs
    │
    ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ TB-8 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │         A2A Agent ◄──── MCP/A2A protocol ────▶ A2A Agent
```

| Boundary | From → To | Authentication |
|----------|-----------|----------------|
| TB-1 | Internet → GLB | TLS termination, no client auth |
| TB-2 | GLB → Cloud Run services | IAM, auth cookie (JWT) |
| TB-3 | Control plane → Data plane (relay hub ↔ spoke) | API key + mTLS |
| TB-4 | Edge gateway → Workloads | WID token (ES256) |
| TB-5 | Cloud Run services → Cloud SQL | VPC connector, private IP, IAM auth |
| TB-6 | Token-service JWKS → Any consumer | Public endpoint (read-only) |
| TB-7 | Discovery scanners → Cloud provider APIs | Cloud IAM credentials (SA key, IAM role, MSI) |
| TB-8 | Agent ↔ Agent (A2A/MCP) | Agent Card + optional JWS signature |

---

## 3. STRIDE Analysis

### Spoofing

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Workload identity forgery | TB-4 | Attacker creates fake WID token to impersonate a workload | ES256 asymmetric signing — only token-service holds private key. JWKS for verification. JTI uniqueness + expiry. | **Shipped** |
| Relay impersonation | TB-3 | Attacker deploys rogue relay to intercept policy bundles | API key + mTLS authentication between relay and hub. Relay registration with environment binding. | **Shipped** |
| Agent Card forgery | TB-8 | Attacker serves fake Agent Card at `/.well-known/agent.json` | ES256 JWS signing. 4-state verification (verified/invalid/unverified/unsigned). High-severity finding for invalid. | **Shipped** |
| Token replay | TB-4 | Attacker captures valid token and replays it against a different service | JTI tracking in DB, audience claim validation, short TTL (5 min–1 hr based on trust tier). Token revocation via API. | **Shipped** |
| Admin session hijack | TB-1 | Attacker steals auth cookie to access Web UI | httpOnly + Secure + SameSite=Strict cookie flags. Session expiry. Password change invalidates sessions. | **Shipped** |
| Cloud metadata SSRF | TB-7 | Attacker tricks discovery scanner into fetching internal metadata | Scanner URL validation. Only configured cloud provider endpoints are contacted. | **Shipped** |

### Tampering

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Policy bundle modification | TB-3 | MITM modifies policy bundle in transit between hub and spoke | Signed bundles with version hashing. Relay verifies bundle signature before caching. | **Shipped** |
| Audit log manipulation | TB-3 | Attacker modifies audit events to hide enforcement decisions | Tamper-evident chain: decision_id + trace_id linking. Batch hashing. DB-level integrity. | **Shipped** |
| Graph data poisoning | TB-2 | Attacker injects false nodes/relationships into the identity graph | DB is single source of truth — no client-side graph mutation. Graph is rebuilt from scanner results on each scan. | **Shipped** |
| MCP tool description manipulation | TB-8 | Attacker modifies MCP server tool descriptions to inject hidden instructions | 22-pattern poisoning detector across 8 categories. Capability fingerprinting detects drift. Description hash comparison. | **Shipped** |
| Decision context manipulation | TB-4 | Attacker modifies request context to influence policy evaluation | Gateway reconstructs context from raw request (not client-supplied). WID token claims are cryptographically verified. | **Shipped** |
| Database record tampering | TB-5 | Attacker with DB access modifies policies or audit records | VPC connector (private IP only). Cloud SQL IAM auth. Audit table with append-only semantics. | **Shipped** |

### Repudiation

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Deny authorization decision | TB-4 | Workload claims it never made a denied request | Full decision logging: decision_id, trace_id, hop_index, total_hops, timestamp, policy version, request context, verdict. Deterministic replay capability. | **Shipped** |
| Agent chain repudiation | TB-8 | Agent in a delegation chain claims it wasn't involved | Trace correlation across all hops. Each hop logged with `hop_index`, `total_hops`, `chain_context`. Chain integrity verification. | **Shipped** |
| Policy change repudiation | TB-2 | Admin claims they didn't deploy a policy | Policy change events logged with user identity and timestamp. Template deployment tracked with framework mappings. | **Shipped** |

### Information Disclosure

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Credential leakage through gateway | TB-4 | Gateway exposes raw API keys to callers | JIT credential injection — gateway injects credentials on the fly, never exposes raw keys to the calling workload. | **Shipped** |
| Token payload exposure | TB-6 | Token contains sensitive data visible to any verifier | Minimal claims in JWT payload — only workload name, trust level, and attestation chain. No secrets, no credentials. | **Shipped** |
| MCP tool argument leakage | TB-8 | MCP tool call arguments contain sensitive data that gets logged | Argument values redacted by default. Only keys are logged, never values. Zero-customer-data principle (ADR-11). | **Shipped** |
| Graph data unauthorized access | TB-1, TB-2 | Unauthorized user accesses identity graph with all relationships | Auth cookie required for all API endpoints. Graph API requires authenticated session. | **Shipped** |
| ES256 private key exposure | TB-5 | Private key leaked from container/env var | Secret Manager integration. Key loaded at runtime from secure storage. Never in environment variables, code, or container images. Dev keys in `.gitignore`. | **Shipped** |
| Header leakage in audit logs | TB-4 | Sensitive headers (Authorization, cookies) stored in audit records | Header sanitization allowlist in `@wid/core`. Only safe headers logged. Auth headers stripped before storage. | **Shipped** |

### Denial of Service

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Control plane unavailability | TB-3 | Hub goes down — spokes can't get policy updates | LKG policy cache. Spokes continue enforcing with last-known-good bundles. Auto-reconnect with exponential backoff. | **Shipped** |
| Audit buffer overflow | TB-4 | Audit events generated faster than they can be flushed | Configurable max buffer size. Drop-oldest eviction. Batch flush every 5 seconds. Buffer state metric for alerting. | **Shipped** |
| Policy sync flooding | TB-3 | Attacker floods hub with policy sync requests | Pull-based sync (spoke pulls every 15s), not push-based. Rate limiting on hub endpoints. | **Shipped** |
| Gateway CPU exhaustion | TB-4 | AI traffic with large payloads overwhelms gateway | Configurable `MAX_BODY_BYTES` for AI/MCP inspection. Stream passthrough for bodies exceeding limit. Circuit breaker for upstream failures. | **Shipped** |
| Database connection exhaustion | TB-5 | Many concurrent requests exhaust Cloud SQL connection pool | Connection pooling per service. Circuit breaker on DB operations. Cached policy evaluation doesn't require DB. | **Shipped** |

### Elevation of Privilege

| Threat | Trust Boundary | Attack Scenario | Mitigation | Status |
|--------|---------------|-----------------|------------|--------|
| Confused deputy attack | TB-8 | Malicious agent tricks an intermediary agent into performing actions it shouldn't | Chain-aware enforcement: trace_id + hop_index + total_hops. Scope ceiling enforcement. Delegation chain binding prevents unauthorized transitive access. | **Shipped** |
| Shared service account abuse | TB-7 | Attacker compromises one workload sharing a SA, pivots to all others | Attack path detector: `shared-service-account` finding (critical). BFS blast radius computation shows all reachable workloads. | **Shipped** |
| Cross-account trust abuse | TB-7 | Attacker exploits misconfigured cross-account IAM trust to assume roles | Attack path detector: `cross-account-trust` finding. ExternalId validation. Trust chain visualization in graph. | **Shipped** |
| MCP tool poisoning → code execution | TB-8 | Attacker injects hidden instructions in MCP tool descriptions to cause agent to execute malicious operations | 22-pattern detector: hidden instructions, URL exfiltration, prompt injection, scope escalation, etc. Capability fingerprinting detects post-deploy changes. | **Shipped** |
| Privilege escalation via IAM | TB-7 | Attacker with limited IAM role escalates to admin via policy chain | Attack path detector: `over-privileged-iam` finding. IAM policy chain analysis in graph. | **Shipped** |
| Agent scope escalation | TB-8 | Agent requests access beyond its authorized scope in a delegation chain | Scope ceiling enforcement in policy engine. Chain context includes `authorized_scopes`. Exceeded scope → deny. | **Shipped** |

---

## 4. OWASP NHI Top 10 Mapping

| # | OWASP NHI Risk | WID Detection | WID Mitigation |
|---|---------------|---------------|----------------|
| NHI1 | Improper Offboarding | `improper-offboarding` finding type. Detects workloads with credentials for decommissioned services. | Policy template: credential lifecycle enforcement |
| NHI2 | Secret Leakage | `static-external-credential` + `leaked-credentials` findings. Environment variable scanning for API keys. | JIT credential injection via Vault. Ban static credentials policy. |
| NHI3 | Vulnerable Third-Party NHIs | A2A Agent Card verification (4-state). MCP integrity scanning (22 patterns). Capability fingerprinting for drift. | `a2a-unsigned-card`, `a2a-invalid-signature`, `mcp-tool-poisoning` findings with remediation controls |
| NHI4 | Insecure Authentication | 4-tier attestation trust model. Graduated from cryptographic (SPIRE) to manual (catalog match). | Enforce attestation tier minimums per resource sensitivity |
| NHI5 | Overly Privileged NHIs | `over-privileged-iam` attack path detector. IAM policy chain analysis. | Policy templates for least-privilege enforcement |
| NHI6 | Insecure Cloud Deployment | `public-internal-pivot`, `internet-to-data-path` detectors. Network exposure mapping. | Firewall rule analysis, network segmentation controls |
| NHI7 | Long-Lived Credentials | `long-lived-api-key`, `credential-rotation-overdue` findings. Age tracking per credential. | Rotation enforcement policies. JIT issuance as replacement. |
| NHI8 | Insufficient Access Controls | 133 policy templates. 25+ condition operators. Simulate/Audit/Enforce lifecycle. | Full policy engine with real-time enforcement at edge |
| NHI9 | Inadequate Logging | Every decision logged with trace_id, hop_index, policy_version. Deterministic replay for auditors. | EU AI Act Article 12 compliance via audit replay with PDF export |
| NHI10 | Lack of NHI Visibility | 17 scanners across 5 cloud providers. A2A/MCP protocol detection. Identity graph with 22 node types. | Full-stack discovery: cloud → workload → identity → credential → API → protocol |

---

## 5. AI Agent-Specific Threats

WID addresses threats unique to the agentic AI era:

| Threat | Description | WID Response |
|--------|-------------|-------------|
| **Confused Deputy** | Agent A delegates to Agent B, which is tricked into calling Agent C with A's authority | Chain-aware enforcement: 9 chain condition fields (chain.origin, chain.depth, chain.has_revoked_hop, etc.) in policy evaluation |
| **MCP Tool Poisoning** | Attacker modifies MCP server tool descriptions to contain hidden instructions for LLMs | 22-pattern detector across 8 categories: hidden instructions, URL exfiltration, prompt injection, scope escalation, data harvesting, social engineering, tool shadowing, credential theft |
| **Agent Card Forgery** | Attacker deploys a fake agent with a convincing but unsigned/invalid Agent Card | ES256 JWS signing + 4-state verification pipeline. Invalid cards generate HIGH severity findings |
| **Shadow AI** | Workloads making undocumented API calls to AI providers (OpenAI, Anthropic, etc.) | Protocol scanner detects AI API credentials and API calls. AIInspector captures runtime AI traffic telemetry |
| **Capability Drift** | MCP server silently adds/removes/modifies tools after initial deployment | Periodic capability fingerprinting (5-min rescan). SHA-256 hash of tool names + descriptions. Drift generates `mcp-capability-drift` finding |
| **Toxic Delegation Combos** | Agent chain accumulates dangerous permission combinations (e.g., financial + CRM access) | `toxic-credential-combo` attack path detector. Cross-workload credential analysis |

---

## 6. Residual Risks

Honest assessment of threats not yet fully mitigated:

| Risk | Current State | Planned Mitigation | Priority |
|------|--------------|-------------------|----------|
| Multi-tenant data isolation | Single-tenant. No row-level security (RLS). | PostgreSQL RLS policies per tenant. Tenant-scoped API tokens. | P2 |
| Enterprise SSO | Cookie-based JWT auth. No SAML/OIDC federation. | SAML 2.0 + OIDC integration for enterprise IdPs. | P2 |
| SIEM integration | Audit events stored internally only. | Webhook/Kafka/S3 export for Splunk, Sentinel, Elastic. | P2 |
| Rate limiting / WAF | No application-level rate limiting on public endpoints. | Rate limiting middleware + Cloud Armor WAF rules. | P2 |
| Production secret rotation | ES256 keys are static after generation. | Automated key rotation with JWKS versioning (kid-based). | P2 |
| Insider threat (admin) | Admin has full DB access. No 4-eyes principle. | Admin audit log + approval workflows for destructive operations. | P3 |

---

## 7. Security Controls Matrix

| Control | S | T | R | I | D | E |
|---------|---|---|---|---|---|---|
| ES256 token signing | X | | | | | |
| Policy bundle signing | | X | | | | |
| Decision audit logging | | | X | | | |
| JIT credential injection | | | | X | | |
| LKG policy cache | | | | | X | |
| Chain-aware enforcement | | | | | | X |
| 4-tier attestation | X | | | | | |
| Header sanitization | | | | X | | |
| MCP tool poisoning detector | | X | | | | X |
| Agent Card JWS verification | X | X | | | | |
| JWKS public key distribution | X | | | | | |
| VPC connector (private DB) | | | | X | X | |
| Default-deny OPA policy | | | | | | X |
| Capability fingerprinting | | X | | | | X |

*S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=Denial of Service, E=Elevation of Privilege*

---

## Related Documentation

- [architecture.md](architecture.md) — System architecture overview
- [SECURITY.md](SECURITY.md) — Security posture, dev/prod defaults, hardening checklist
- [ARCHITECTURE-DEEP-DIVE.md](ARCHITECTURE-DEEP-DIVE.md) — Algorithms, scoring, attack path detection
- [COMPLIANCE.md](COMPLIANCE.md) — 5 compliance frameworks, 68 controls
- [deployment-models.md](deployment-models.md) — 4 deployment modes with security implications
- [attack-path-demo.md](attack-path-demo.md) — Live attack path detection walkthrough
- [shared/ATTESTATION.md](../shared/ATTESTATION.md) — 4-tier trust model details
