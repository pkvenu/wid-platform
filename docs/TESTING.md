# WID Platform — Testing Strategy

> Version 1.0 | March 2026
> TDD approach, coverage targets, and regression prevention.

---

## Current State

### Test Inventory

| Service | File | Tests | Status | Framework |
|---------|------|-------|--------|-----------|
| `shared/data-plane-core` | `test/core.test.js` | 72 | All passing | node:test |
| `shared/data-plane-core` | `test/ai-inspector.test.js` | ~8 | Passing | node:test |
| `services/edge-gateway` | `test/gateway.test.js` | 23 | All passing | node:test |
| `services/policy-sync-service` | `src/tests/policy-engine.test.js` | 22 | All passing | Custom assert |
| `services/policy-sync-service` | `src/tests/compilers.test.js` | 9 | All passing | Custom assert |
| `services/ext-authz-adapter` | `test/adapter.test.js` | 1 | **FAILING** | node:test |
| `services/token-service` | `test/canonical-nhi-context.test.js` | 30 | All passing | node:test |
| `services/token-service` | `test/token-utils.test.js` | 15 | All passing | node:test |
| `services/discovery-service` | `test/security-scorer.test.js` | 24 | All passing | node:test |
| `services/discovery-service` | `test/spiffe.test.js` | 12 | All passing | node:test |
| `services/discovery-service` | `test/categorizer.test.js` | 22 | All passing | node:test |
| `services/relay-service` | `test/relay-core.test.js` | 23 | All passing | node:test |
| `services/credential-broker` | `test/cache.test.js` | 8 | All passing | node:test |
| `services/credential-broker` | `test/providers.test.js` | 12 | All passing | node:test |
| `services/credential-broker` | `test/target-config.test.js` | 8 | All passing | node:test |
| **TOTAL** | | **~289** | **~288 pass, 1 fail** | |

### What's Covered

**Well tested:**
- Policy evaluation engine: operators, condition matching, bulk evaluation, scope filtering
- Rego compiler: output format, operators, conditions
- Data-plane core: PolicyCache, CredentialBuffer, CircuitBreaker, RateLimiter, AuditBuffer
- Edge gateway: config defaults, mode resolution, outbound proxy integration, AI inspection
- AIInspector: endpoint detection, token estimation, telemetry events

**Newly covered (unit tests):**
- Token service: NHI context builder, capability validation, trust domain extraction, auth method detection, ID generation
- Discovery service: Security scoring, trust level determination, finding penalties, SPIFFE ID generation/parsing, workload categorization
- Relay service: Workload matching, cached policy evaluation, audit buffer, config parsing
- Credential broker: Cache operations, provider base class, provider manager, target API configs

**Not tested at all:**
- Web UI (no component tests, no E2E tests)
- API route handlers (no integration tests against live DB)
- Database migrations and schema
- Graph building, relationship scanner, protocol scanner, attack paths (integration tests needed)

---

## Testing Principles

### 1. Test at the Right Level

| Level | What to Test | Framework | When |
|-------|-------------|-----------|------|
| **Unit** | Pure functions, algorithms, data transformations | node:test | Every PR |
| **Contract** | API request/response shapes, DB query results | node:test + supertest | Every PR |
| **Integration** | Service-to-service calls, DB transactions | docker-compose test env | Pre-deploy |
| **E2E** | Full user flows (scan -> graph -> enforce) | Playwright or curl scripts | Pre-release |

### 2. What MUST Be Tested

**Critical paths that cannot break:**
1. Policy evaluation engine (`evaluator.js`) — wrong verdict = security incident
2. Gateway evaluate endpoint — hot path, wrong decision = blocked traffic or breach
3. Attack path computation — wrong blast radius = wrong risk assessment
4. Graph building (relationship scanner) — missing edges = invisible attack paths
5. Token issuance/validation — wrong token = unauthorized access
6. Auth routes — broken auth = platform compromise

**Test every operator, every edge case.** Policy evaluation bugs are security vulnerabilities.

### 3. Test Naming Convention

```
describe('PolicyEvaluator', () => {
  describe('evaluate()', () => {
    it('should deny when any deny policy matches (first-deny-wins)', () => {});
    it('should allow when allow policy matches and no deny', () => {});
    it('should return default verdict when no policies match', () => {});
  });
});
```

Format: `should {expected behavior} when {condition}`

---

## Coverage Targets

### Phase 1: Critical Path Coverage (Target: before any P1 moat feature)

| Service | Target | Priority Tests |
|---------|--------|----------------|
| `policy-sync-service` | 80% | Gateway evaluate endpoint, batch decisions, policy CRUD, template deployment, scoped policies |
| `discovery-service` | 60% | Relationship scanner addRel, attack path detectors, graph building, protocol scanner |
| `shared/data-plane-core` | 90% (current ~85%) | Already well-tested, add edge cases |
| `edge-gateway` | 80% (current ~70%) | Add enforce mode, fail-closed, AIInspector edge cases |

### Phase 2: Full Coverage (Target: before production deployment)

| Service | Target | Priority Tests |
|---------|--------|----------------|
| `token-service` | 70% | Token issuance, validation, chain tracking, OBO exchange, revocation |
| `credential-broker` | 60% | Provider abstraction, rotation lifecycle, dynamic credentials |
| `relay-service` | 60% | Policy sync, audit batching, heartbeat, hub/spoke modes |
| `ext-authz-adapter` | 70% | Fix existing failure, gRPC check handler, Envoy integration |

### Phase 3: E2E (Target: before first customer)

| Flow | What to Test |
|------|-------------|
| Discovery -> Graph | Scan triggers -> workloads saved -> graph built -> API returns correct shape |
| Simulate -> Audit -> Enforce | Template deploy -> simulate decisions -> audit mode -> enforce -> graph update |
| Agent chain trace | UC1 4-hop chain -> all hops logged -> trace query returns full chain |
| Connection display | Select node -> connections grouped -> evidence layers shown |

---

## Test Plan for P1 Moat Features

### 1.1 Chain-Aware Enforcement Tests

```
describe('ChainAwareEnforcement', () => {
  // Unit tests
  it('should query prior hops when trace_id is provided');
  it('should deny when delegation chain is unauthorized');
  it('should allow when delegation chain is authorized');
  it('should handle missing trace_id gracefully (no chain check)');
  it('should handle orphan hop (trace_id exists but no prior hops)');

  // Policy condition tests
  it('should evaluate chain.origin condition');
  it('should evaluate chain.delegator condition');
  it('should evaluate chain.depth condition (max 3 hops)');

  // Performance tests
  it('should add < 5ms latency for chain lookup');

  // Contract tests
  it('should include chain context in ext_authz_decisions');
  it('should return chain_context in evaluate response');
});
```

### 1.2 Deterministic Replay Tests

```
describe('DeterministicReplay', () => {
  // Unit tests
  it('should snapshot policy state at evaluation time');
  it('should reconstruct full decision context from trace_id');
  it('should return all hops in chain order');
  it('should include policy version hash per hop');

  // Idempotency tests
  it('should produce identical replay output for same trace_id');
  it('should produce correct replay even after policy is modified');
  it('should produce correct replay even after policy is deleted');

  // Contract tests
  it('should return valid JSON replay package');
  it('should include request_context, policy_version, verdict per hop');
});
```

### 1.3 MCP Integrity Scanning Tests

```
describe('MCPIntegrityScanner', () => {
  // Detection tests
  it('should detect MCP server from env vars (MCP_SERVER_URL)');
  it('should detect MCP server from Agent Card skills');
  it('should detect MCP server from config file references');

  // Integrity tests
  it('should compute package hash and compare against registry');
  it('should flag unverified MCP server');
  it('should flag outdated MCP server version');

  // Tool poisoning tests
  it('should detect hidden instructions in tool descriptions');
  it('should flag base64-encoded content in tool descriptions');
  it('should flag URLs in tool descriptions pointing to unknown domains');

  // Graph integration tests
  it('should create mcp-unverified-server finding');
  it('should create mcp-tool-poisoning finding');
  it('should add finding to CONTROL_CATALOG with remediation controls');
});
```

---

## How to Run Tests

```bash
# All tests (from repo root)
cd shared/data-plane-core && npm test
cd services/edge-gateway && npm test
cd services/policy-sync-service && npm test
cd services/token-service && npm test
cd services/discovery-service && npm test
cd services/relay-service && npm test
cd services/credential-broker && npm test

# Individual service
cd services/<service> && npm test

# With verbose output
cd shared/data-plane-core && node --test --test-reporter=spec test/core.test.js
```

## How to Add Tests

### For Pure Functions (unit tests)

```javascript
// services/<service>/test/<module>.test.js
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { myFunction } from '../src/myModule.js';

describe('myFunction', () => {
  it('should return expected output for valid input', () => {
    assert.deepStrictEqual(myFunction('input'), 'expected');
  });

  it('should throw on invalid input', () => {
    assert.throws(() => myFunction(null), /expected error/);
  });
});
```

### For API Endpoints (contract tests)

```javascript
// services/<service>/test/routes.test.js
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

// Start a test server with mock DB
let server;
before(async () => { server = await startTestServer(); });
after(() => server.close());

describe('POST /api/v1/gateway/evaluate', () => {
  it('should return allow verdict for matching allow policy', async () => {
    const res = await fetch(`http://localhost:${server.port}/api/v1/gateway/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'billing-agent', destination: 'stripe-api' }),
    });
    const data = await res.json();
    assert.equal(data.verdict, 'allow');
    assert.ok(data.decision_id);
  });
});
```

### For Database Queries (integration tests)

Use a test PostgreSQL instance (docker-compose with `postgres:16` image). Seed with `database/init.sql`. Run queries and verify results. Tear down after suite.

---

## Regression Prevention

### Pre-Commit Checklist

Before any code change:
1. Run tests for affected service: `npm test`
2. Run data-plane-core tests (shared dependency): `cd shared/data-plane-core && npm test`
3. Build web UI: `cd web/workload-identity-manager && npx vite build`
4. Verify no new security warnings: `npm audit --audit-level=moderate`

### Pre-Deploy Checklist

Before deploying to GCP:
1. All unit tests pass (289+ tests)
2. Manual smoke test: scan -> graph loads -> select node -> connections display -> enforce -> graph updates
3. Demo use cases work: `POST /uc1`, `/uc2`, `/uc3`
4. Edge gateway metrics healthy: `curl localhost:15100/metrics`

### Known Test Debt

| Issue | Priority | Notes |
|-------|----------|-------|
| ext-authz-adapter test failing | P2 | Investigate and fix |
| No web UI tests | P3 | Risk: UI regressions |
| Policy engine tests use custom assert, not node:test | P3 | Migrate for consistency |
| No integration tests for graph building | P2 | Needs DB + scan pipeline |
| No integration tests for token chain tracking | P2 | Needs DB + token exchange flow |
