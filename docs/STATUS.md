# WID Platform — Status Matrix

> Last verified: 2026-03-12
> Every claim in README.md is traced to source code. Verify any claim in <30 seconds.

---

## Table 1 — Platform Claims

| Claim | README Says | Verified | Source |
|-------|------------|----------|--------|
| Pluggable scanners | 17 | **17** | `services/discovery-service/src/scanners/` — cloud/8, container/3, credentials/4, on-prem/2 |
| Node types (graph groups) | 57 across 14 groups | **57 in `groupOf()`** | `services/discovery-service/src/graph/relationship-scanner.js:49-89` |
| Node types (DB constraint) | — | **17 workload types** | `database/init.sql:42-46` |
| Relationship types | 48 | **48** | `services/discovery-service/src/graph/relationship-scanner.js` — unique `type:` literals |
| Policy templates | 133 | **133** | `services/policy-sync-service/src/engine/templates.js` |
| Compliance frameworks | 5 | **5** (SOC 2, PCI DSS, NIST 800-53, ISO 27001, EU AI Act) | `docs/COMPLIANCE.md` |
| Compliance controls | 68 | **68** (10+13+19+17+9) | `docs/COMPLIANCE.md` |
| Attestation tiers | 4 | **4** (cryptographic/high/medium/low) | `services/discovery-service/src/utils/security-scorer.js:48-63` |
| Trust levels | — | **6** (none/low/medium/high/very-high/cryptographic) | `services/discovery-service/src/utils/security-scorer.js:6` |
| Attack path detectors | 11 | **11 categories** in `computeAttackPaths()` | `services/discovery-service/src/graph/relationship-scanner.js` |
| MCP poisoning patterns | 22 | **22** | `services/discovery-service/src/graph/protocol-scanner.js:128-158` |
| MCP known-good registry | 12 | **12** | `services/discovery-service/src/graph/protocol-scanner.js:162-177` |

---

## Table 2 — Feature Status Matrix

| Capability | Status | API Endpoint | Source | Tests |
|-----------|--------|-------------|--------|-------|
| Multi-cloud discovery | Shipped | `POST /api/v1/workloads/scan` | `services/discovery-service/src/scanners/` | Unit: 26 |
| Identity graph + attack paths | Shipped | `GET /api/v1/graph` | `services/discovery-service/src/graph/relationship-scanner.js` | — |
| Progressive enforcement (SIM/AUDIT/ENFORCE) | Shipped | `POST /api/v1/gateway/evaluate` | `services/policy-sync-service/src/engine/evaluator.js` | 22 |
| Chain-aware enforcement | Shipped | `POST /api/v1/gateway/evaluate-chain` | `services/policy-sync-service/src/index.js` | — |
| Deterministic replay | Shipped | `GET /api/v1/access/decisions/replay/:traceId` | `services/policy-sync-service/src/index.js` | — |
| MCP integrity scanning | Shipped | Graph enrichment | `services/discovery-service/src/graph/protocol-scanner.js` | — |
| Compliance policy packs | Shipped | `POST /api/v1/compliance/frameworks/:id/deploy` | `services/policy-sync-service/src/index.js` | — |
| Token issuance + OBO chains | Shipped | `POST /v1/token/exchange` | `services/token-service/src/index.js` | Unit: 25 |
| Credential brokering | Shipped | `ALL /v1/proxy/:target/*` | `services/credential-broker/src/index.js` | Unit: 25 |
| Hub-spoke federation | Shipped | `POST /api/v1/relay/register` | `services/relay-service/src/index.js` | Unit: 20 |
| Edge gateway (sidecar PEP) | Shipped | Ports 15001/15006/15000 | `services/edge-gateway/src/` | 23 |
| Ext-authz adapter | Shipped | Port 9191 (gRPC) / 8080 | `services/ext-authz-adapter/src/` | 1 |
| Data-plane core (shared) | Shipped | — | `shared/data-plane-core/src/` | 80 |
| Policy template engine | Shipped | `POST /api/v1/policies/from-template/:id` | `services/policy-sync-service/src/engine/templates.js` | 9 |

---

## Table 3 — Test Coverage by Service

| Service | Test File(s) | Passing | Coverage Areas | Gaps |
|---------|-------------|---------|----------------|------|
| `shared/data-plane-core` | `test/core.test.js`, `test/ai-inspector.test.js` | ~80 | PolicyCache, CredBuf, CircuitBreaker, RateLimiter, AuditBuf, AIInspector | Edge cases |
| `services/edge-gateway` | `test/gateway.test.js` | 23 | Config, mode resolution, proxy, AI inspection | Enforce mode, fail-closed |
| `services/policy-sync-service` | `src/tests/policy-engine.test.js`, `src/tests/compilers.test.js` | 31 | Policy evaluation, operators, Rego compiler | Gateway evaluate, batch decisions |
| `services/ext-authz-adapter` | `test/adapter.test.js` | 0 (1 failing) | gRPC adapter | Fix existing failure |
| `services/token-service` | `test/canonical-nhi-context.test.js`, `test/token-utils.test.js` | 45 | NHI types, capabilities, trust domain, auth method, ID generation | DB integration, token chain |
| `services/discovery-service` | `test/security-scorer.test.js`, `test/spiffe.test.js`, `test/categorizer.test.js` | 58 | Security scoring, trust levels, finding penalties, SPIFFE IDs, categorization | Graph building, relationship scanner |
| `services/relay-service` | `test/relay-core.test.js` | 23 | Policy matching, workload matching, audit buffer, config parsing | Policy sync, federation |
| `services/credential-broker` | `test/cache.test.js`, `test/providers.test.js`, `test/target-config.test.js` | 28 | Cache ops, provider base class, manager, target configs | Provider integration, rotation |
| **TOTAL** | | **~289** | | |

---

## Table 4 — Discrepancies

All discrepancies resolved as of 2026-03-13:

| Claim | Was | Fix | Status |
|-------|-----|-----|--------|
| Node types | README said "24" | Updated to "57 node types across 14 graph groups" | Fixed |
| MCP poisoning patterns | README said "23" | Updated to "22" (actual count in code) | Fixed |
| Attack path detectors | "11" | 11 detection categories in `computeAttackPaths()` — correct | No change needed |

---

## Scanner Inventory

| Category | Count | Scanners |
|----------|-------|----------|
| Cloud | 8 | `gcp.js`, `aws.js`, `aws-network.js`, `aws-security.js`, `aws-storage.js`, `azure.js`, `azure-entra.js`, `oracle.js` |
| Container | 3 | `kubernetes.js`, `docker.js`, `ecs.js` |
| Credentials | 4 | `vault.js`, `iam.js`, `service-tokens.js`, `cicd.js` |
| On-Prem | 2 | `vmware.js`, `openstack.js` |
| **Total** | **17** | |

All files in `services/discovery-service/src/scanners/<category>/`.

---

## Known-Good MCP Registry

12 verified packages in `services/discovery-service/src/graph/protocol-scanner.js:162-177`:

1. `@modelcontextprotocol/server-filesystem`
2. `@modelcontextprotocol/server-github`
3. `@modelcontextprotocol/server-postgres`
4. `@modelcontextprotocol/server-slack`
5. `@modelcontextprotocol/server-memory`
6. `@modelcontextprotocol/server-puppeteer`
7. `@modelcontextprotocol/server-brave-search`
8. `@modelcontextprotocol/server-google-maps`
9. `@modelcontextprotocol/server-fetch`
10. `@modelcontextprotocol/server-sequentialthinking`
11. `@modelcontextprotocol/server-everything`
12. `mcp-server-sqlite`
