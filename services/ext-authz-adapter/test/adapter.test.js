// =============================================================================
// ext_authz Adapter — Test Suite
// =============================================================================
// Shared classes (PolicyCache, CircuitBreaker, sanitization, etc.) are tested
// in shared/data-plane-core/test/core.test.js (72 tests).
//
// This file tests ADAPTER-SPECIFIC logic only:
//   1. filterSafeLabels (adapter-specific label allowlist)
//   2. hdr helper (gRPC header builder)
//   3. latencyMs (hrtime-based latency)
//   4. CONFIG defaults
//   5. Shared core smoke tests (verify imports work)
// =============================================================================

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  PolicyCache, CredentialBuffer, CircuitBreaker, RateLimiter,
  MetricsCollector, AuditBuffer,
  sanitizeHeaders, sanitizePath, extractWorkloadName, extractNamespace,
  buildAuditEntry,
} = require('@wid/core');

const {
  CONFIG, filterSafeLabels, hdr, latencyMs,
} = require('../src/adapter.js');


describe('filterSafeLabels', () => {
  it('keeps allowed labels', () => {
    const result = filterSafeLabels({ app: 'frontend', version: 'v1', team: 'platform', env: 'prod' });
    assert.deepEqual(result, { app: 'frontend', version: 'v1', team: 'platform', env: 'prod' });
  });

  it('strips unknown labels', () => {
    const result = filterSafeLabels({ app: 'frontend', secret: 'value', customer_id: '123' });
    assert.deepEqual(result, { app: 'frontend' });
  });

  it('handles null', () => {
    assert.deepEqual(filterSafeLabels(null), {});
    assert.deepEqual(filterSafeLabels(undefined), {});
  });

  it('handles empty object', () => {
    assert.deepEqual(filterSafeLabels({}), {});
  });
});

describe('hdr', () => {
  it('creates gRPC header structure', () => {
    const result = hdr('x-wid-decision-id', 'dec_123');
    assert.deepEqual(result, { header: { key: 'x-wid-decision-id', value: 'dec_123' } });
  });
});

describe('latencyMs', () => {
  it('returns non-negative number', () => {
    const start = process.hrtime.bigint();
    const ms = latencyMs(start);
    assert.equal(typeof ms, 'number');
    assert.ok(ms >= 0);
  });
});

describe('CONFIG', () => {
  it('has required fields', () => {
    assert.ok(CONFIG.grpcPort);
    assert.ok(CONFIG.adminPort);
    assert.ok(CONFIG.policyServiceUrl);
    assert.ok(CONFIG.tokenServiceUrl);
    assert.ok(CONFIG.defaultMode);
    assert.ok(CONFIG.defaultFailBehavior);
    assert.ok(CONFIG.instanceId);
    assert.ok(Array.isArray(CONFIG.platformHeaders));
  });

  it('defaults to audit mode', () => {
    assert.equal(CONFIG.defaultMode, 'audit');
  });

  it('defaults to fail-open', () => {
    assert.equal(CONFIG.defaultFailBehavior, 'open');
  });
});

describe('Shared core smoke tests', () => {
  it('PolicyCache works via @wid/core', () => {
    const cache = new PolicyCache({ ttlMs: 1000 });
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/'), { verdict: 'allow' });
  });

  it('CircuitBreaker works via @wid/core', () => {
    const cb = new CircuitBreaker({ threshold: 3, cooldownMs: 100 });
    assert.equal(cb.isOpen(), false);
  });

  it('sanitizePath works via @wid/core', () => {
    assert.equal(sanitizePath('/users/12345?token=secret'), '/users/{id}');
  });

  it('sanitizeHeaders strips sensitive data via @wid/core', () => {
    const result = sanitizeHeaders({ Authorization: 'Bearer secret', 'Content-Type': 'application/json' });
    assert.equal(result['authorization'], undefined);
    assert.equal(result['content-type'], 'application/json');
  });

  it('buildAuditEntry creates structured entry via @wid/core', () => {
    const entry = buildAuditEntry('d1', 'spiffe://c/ns/p/sa/fe', 'spiffe://c/ns/p/sa/be', 'GET', '/api/v1/users/12345', 'allow', {}, 5, false);
    assert.equal(entry.source_name, 'fe');
    assert.equal(entry.destination_name, 'be');
    assert.equal(entry.path_pattern, '/api/v1/users/{id}');
    assert.ok(!entry.path_pattern.includes('12345'));
  });

  it('MetricsCollector tracks decisions via @wid/core', () => {
    const m = new MetricsCollector();
    m.record('allow', 10);
    m.record('deny', 20);
    const s = m.getSnapshot();
    assert.equal(s.counters.total, 2);
    assert.equal(s.counters.allowed, 1);
    assert.equal(s.counters.denied, 1);
  });
});
