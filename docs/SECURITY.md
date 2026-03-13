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
| `JWT_SECRET` | `dev-secret-change-in-production` | `services/token-service/src/index.js:18` | Set `JWT_SECRET` env var — 64+ random chars |
| `VAULT_DEV_ROOT_TOKEN` | `dev-root-token` | `docker-compose.fullstack.yml` (vault service) | Vault HA mode with proper unseal keys |
| `CENTRAL_API_KEY` | empty | `services/relay-service/src/index.js:58` | Set `CENTRAL_API_KEY` env var |
| `ADMIN_PASSWORD` | `Admin12345` | `database/init.sql` | Change via API after first boot |

All dev defaults use `${VAR:-default}` substitution pattern. Setting the env var overrides the default.

---

## Production Hardening Checklist

- [ ] Generate random `POSTGRES_PASSWORD` (32+ chars, alphanumeric)
- [ ] Generate random `JWT_SECRET` (64+ chars)
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
| Token forgery | JWT signed with HS256 (dev) / RS256 (prod) | Dev: HS256, Prod: RS256 planned |
| Policy bypass | OPA default-deny base policy | Shipped |
| Credential leak via gateway | JIT injection — gateway never exposes raw keys to callers | Shipped |
| Confused deputy (agent chains) | Chain-aware enforcement with `trace_id` + `hop_index` validation | Shipped |
| MCP tool poisoning | 22-pattern detector across 8 attack categories | Shipped |
| Relay impersonation | API key auth + mTLS between relay and control plane | Shipped |
| Graph data poisoning | DB is single source of truth — no client-side graph mutation | Shipped |
| Policy tampering | Signed bundles with version hashing | Shipped |
| Gateway compromise | Stateless (no secrets stored), fail-closed configurable | Shipped |
| Shadow AI detection | Protocol scanner detects undocumented AI API calls | Shipped |
| Privilege escalation | Attack path detector flags escalation chains | Shipped |
| DB compromise | RLS planned (P2), encrypted at rest via cloud provider | Planned |
| Token replay | JTI tracking + revocation + TTL enforcement | Shipped |
| Cross-account trust abuse | Attack path detector for cross-account trust misconfigurations | Shipped |

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
