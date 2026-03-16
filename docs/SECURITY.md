# Security Architecture

> WID Platform security posture, dev/prod boundaries, and threat model.

---

## Security Posture Summary

| Control | Status | Source |
|---------|--------|--------|
| `.env` excluded from git | YES | `.gitignore` |
| mTLS between services | YES | `docker-compose.fullstack.yml`, edge-gateway config |
| Fail-closed on OPA failure | YES | `services/token-service/src/index.js:355` |
| Policy bundles signed | YES | Version hashing + bundle signatures |
| Audit logs tamper-evident | YES | Decision chain hashing, trace_id linking |
| Default-deny OPA policy | YES | `services/opa/policy/` |

---

## Development vs Production Defaults

| Secret | Dev Default | File:Line | Production Override |
|--------|------------|-----------|-------------------|
| `POSTGRES_PASSWORD` | `wip_password` | `docker-compose.fullstack.yml:14` | Set in `.env` — 32+ random chars |
| `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_FILE` | Dev EC keys in `services/token-service/keys/dev/` | `services/token-service/src/crypto.js` | Set `JWT_PRIVATE_KEY` (base64 PEM) or `JWT_PRIVATE_KEY_FILE` (path) |
| `VAULT_DEV_ROOT_TOKEN` | `dev-root-token` | `docker-compose.fullstack.yml` (vault service) | Vault HA mode with proper unseal keys |
| `CENTRAL_API_KEY` | empty | `services/relay-service/src/index.js:58` | Set `CENTRAL_API_KEY` env var |
| `ADMIN_PASSWORD` | `Admin12345` | `database/init.sql` | Change via API after first boot |

All dev defaults use `${VAR:-default}` substitution pattern. Setting the env var overrides the default.

---

## Production Hardening Checklist

- [ ] Generate random `POSTGRES_PASSWORD` (32+ chars, alphanumeric)
- [ ] Generate production ES256 keys (`node services/token-service/scripts/generate-keys.js /path/to/prod/keys`)
- [ ] Vault HA mode (not `dev` server mode)
- [ ] PostgreSQL SSL/TLS enabled
- [ ] mTLS between all services (edge-gateway ↔ relay ↔ control plane)
- [ ] `NODE_ENV=production` on all services
- [ ] Audit log encryption at rest (Cloud SQL encryption or equivalent)
- [ ] Replace `ADMIN_PASSWORD` immediately after first boot
- [ ] Set `CENTRAL_API_KEY` for relay-to-hub authentication
- [ ] Configure `FAIL_BEHAVIOR=closed` on edge gateways
- [ ] Enable Cloud SQL audit logging
- [ ] Set up log retention policy (minimum 1 year for compliance)
- [ ] Verify RLS policies on all tenant-scoped tables (`SELECT * FROM pg_policies`)
- [ ] Set per-tenant connection pool limits (prevent noisy neighbor)
- [ ] Configure data residency mode for regulated tenants (`strict` mode)
- [ ] Configure credential auto-rotation policies (30d for API keys, 90d for service accounts)
- [ ] Azure spoke: verify Managed Identity is used (no stored ACR credentials)
- [ ] Azure spoke: verify Key Vault access via Managed Identity (no secret blocks in Terraform state)
- [ ] Validate tenant context propagation in relay federation (spoke tenant binding)
- [ ] Audit tenant membership changes (owner/admin role grants)
- [ ] Configure federation CA for relay mTLS (`FEDERATION_CA_PATH` pointing to trust domain root)
- [ ] Set `RELAY_CERT_PATH` and `RELAY_KEY_PATH` on each spoke relay (SPIFFE X.509 SVID)
- [ ] Verify relay certificate rotation is operational (default 1-hour TTL)

---

## What is NOT Exposed

| Asset | Protection |
|-------|-----------|
| `.env` files | `.gitignore` — never committed |
| AWS credentials | Environment variables only — never in compose files or code |
| TLS certificates | `.gitignore` — generated per environment |
| Terraform state | `.gitignore` — contains cloud secrets |
| Vault unseal keys | Dev mode only in compose — production uses proper init/unseal |
| Database connection strings | Environment variables with `${VAR:-default}` substitution |

---

## Threat Model

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Token forgery | Workload tokens signed with ES256 (ECDSA P-256). Asymmetric: only token-service holds private key. JWKS endpoint for public key distribution. | Shipped |
| Policy bypass | OPA default-deny base policy | Shipped |
| Credential leak via gateway | JIT injection — gateway never exposes raw keys to callers | Shipped |
| Static credential exposure | Auto-rotation via credential broker (30d/90d configurable). 4 vault providers with failover. Rotation logged to `credential_rotations` table. | Shipped |
| Azure spoke credential theft | Managed Identity (no stored credentials). ACR pull via MI, Key Vault access via MI. No admin passwords in Terraform state. | Shipped |
| Confused deputy (agent chains) | Chain-aware enforcement with `trace_id` + `hop_index` validation | Shipped |
| MCP tool poisoning | 22-pattern detector across 8 attack categories | Shipped |
| Relay impersonation | mTLS federation with SPIFFE X.509 SVIDs — per-relay cryptographic identity verified via certificate chain. API key fallback for non-cert environments | Shipped |
| Stale relay entries | Automatic 5-minute timeout — relays that miss heartbeats are removed from the active relay registry | Shipped |
| Certificate theft from compromised spoke | Short TTL certificates (default 1 hour) with automatic rotation. Revocation API allows immediate invalidation of compromised relay SVIDs | Shipped |
| Graph data poisoning | DB is single source of truth — no client-side graph mutation | Shipped |
| Policy tampering | Signed bundles with version hashing | Shipped |
| Gateway compromise | Stateless (no secrets stored), fail-closed configurable | Shipped |
| Shadow AI detection | Protocol scanner detects undocumented AI API calls | Shipped |
| Privilege escalation | Attack path detector flags escalation chains | Shipped |
| DB compromise | RLS planned (P2), encrypted at rest via cloud provider | Planned |
| Token replay | JTI tracking + revocation + TTL enforcement | Shipped |
| Cross-account trust abuse | Attack path detector for cross-account trust misconfigurations | Shipped |
| Cross-tenant data leakage | PostgreSQL RLS on all tables + tenant middleware + scoped caches | Shipped |
| Tenant JWT spoofing | Server-set tenantId claim, membership validated before issuance | Shipped |
| Cross-tenant cache poisoning | All cache keys prefixed `tenant:{id}:`, separate eviction scopes | Shipped |
| Tenant IDOR | RLS enforced at DB layer; middleware double-checks tenant context | Shipped |
| Cross-tenant policy interference | Policies scoped by tenant_id, evaluation loads only current tenant | Shipped |
| Data sovereignty violation | Region-tagged tenants, strict residency mode, spoke-local storage | Shipped |

---

## Data Isolation Guarantees (Multi-Tenancy)

Three defense layers ensure tenant data isolation:

| Layer | Mechanism | Bypass Resistance |
|-------|-----------|-------------------|
| **1. PostgreSQL RLS** | Every table has `tenant_id NOT NULL` + RLS policy using `current_setting('app.current_tenant')`. Connection-level enforcement. | Even raw SQL injection cannot cross tenant boundary |
| **2. Application middleware** | Extracts `tenantId` from JWT, sets `SET LOCAL app.current_tenant` on every DB connection | Missing/invalid tenant context rejects request before query |
| **3. Tenant-scoped caches** | All cache keys prefixed `tenant:{tenantId}:` (policy cache, graph cache, relay cache) | Cache invalidation is tenant-scoped; no cross-tenant pollution |

If any single layer fails, the other two still prevent cross-tenant access.

---

## Data Sovereignty

| Mode | Behavior |
|------|----------|
| **Relaxed** (default) | Data stored in primary region, replicated globally for performance |
| **Strict** | Queries rejected if routed to wrong region. Spoke relays tagged by region; audit events only flow through same-region spokes |
| **Spoke-local** | Sovereign deployments write to local DB. Hub receives metadata only (counts, timestamps — no PII) |

Configuration: `tenants.region` (`us`, `eu`, `ap`) + `tenants.data_residency_mode` (`relaxed`, `strict`).

---

## Multi-Tenant Threat Model

| # | Threat | Mitigation | Status |
|---|--------|-----------|--------|
| T1 | Cross-tenant data leakage (queries) | RLS on every table | Shipped |
| T2 | Cross-tenant cache poisoning | Cache keys prefixed `tenant:{id}:` | Shipped |
| T3 | JWT tenant spoofing | tenantId server-set, membership validated | Shipped |
| T4 | Relay impersonation (cross-tenant) | Relay registration includes tenant_id, verified via mTLS + API key | Shipped |
| T5 | IDOR on API endpoints | RLS + middleware double-check | Shipped |
| T6 | Privilege escalation (viewer -> admin) | Role checked in middleware, changes require owner/admin | Shipped |
| T7 | Tenant enumeration | Slugs not exposed, no listing endpoint for non-owners | Shipped |
| T8 | Cross-tenant policy interference | Policies scoped by tenant_id | Shipped |
| T9 | Audit log cross-contamination | ext_authz_decisions has tenant_id + RLS | Shipped |
| T10 | Graph data leakage | identity_graph cached per tenant | Shipped |
| T11 | Token replay across tenants | Token validation checks tenantId matches request context | Shipped |
| T12 | Shared SA cross-tenant pivoting | Attack path detector scoped to tenant | Shipped |
| T13 | Tenant deletion data remnants | Hard delete with cascade, audit retention per compliance policy | Shipped |
| T14 | Connection pool exhaustion (noisy neighbor) | Per-tenant connection limits, configurable per plan tier | Shipped |
| T15 | Backup/restore cross-contamination | Tenant-scoped restore validated by RLS on import | Shipped |
| T16 | Admin API abuse | Platform super-admin separate from tenant admin, elevated audit | Shipped |
| T17 | Webhook/SIEM cross-tenant routing | Webhook configs tenant-scoped, payloads include tenant context | Shipped |
| T18 | MCP fingerprint cross-tenant pollution | mcp_fingerprints has tenant_id + RLS | Shipped |
| T19 | Compliance framework cross-tenant leakage | Coverage stats per tenant, framework defs global read-only | Shipped |
| T20 | Data sovereignty violation | Strict residency mode at middleware layer, region-tagged spokes | Shipped |

See [ADR-12](ADR-12-multi-tenancy.md) for full design rationale.

---

## Fail-Closed Behavior

| Service | Behavior on OPA Failure | Source |
|---------|------------------------|--------|
| token-service | **DENY** — refuses to issue tokens | `services/token-service/src/index.js:355` |
| edge-gateway | Configurable via `FAIL_BEHAVIOR` (default: `open` for dev, `closed` for prod) | `services/edge-gateway/src/config.js` |
| credential-broker | **DENY** — refuses credential access on auth failure | `services/credential-broker/src/index.js` |
| relay-service | Falls back to cached policies (LKG) | `services/relay-service/src/index.js` |

---

## Security Contact

Report vulnerabilities to the project maintainers. Do not open public issues for security bugs.
