const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  matchWorkload,
  evaluateCachedPolicies,
  createAuditBuffer,
  parseConfig,
} = require('../src/relay-core');

// =============================================================================
// matchWorkload()
// =============================================================================

describe('matchWorkload', () => {
  it('should match wildcard pattern', () => {
    assert.equal(matchWorkload('anything', 'anything', '*'), true);
  });

  it('should match principal containing pattern', () => {
    assert.equal(matchWorkload('spiffe://company.com/billing', null, 'billing'), true);
  });

  it('should match name containing pattern', () => {
    assert.equal(matchWorkload(null, 'billing-agent', 'billing'), true);
  });

  it('should not match when neither contains pattern', () => {
    assert.equal(matchWorkload('payment-svc', 'payment-svc', 'billing'), false);
  });

  it('should handle null principal and name', () => {
    assert.equal(matchWorkload(null, null, 'billing'), false);
  });

  it('should handle null principal with matching name', () => {
    assert.equal(matchWorkload(null, 'billing-agent', 'billing'), true);
  });
});

// =============================================================================
// evaluateCachedPolicies()
// =============================================================================

describe('evaluateCachedPolicies', () => {
  const policies = [
    {
      name: 'deny-external',
      enabled: true,
      effect: 'deny',
      source_match: 'external',
      destination_match: 'internal',
    },
    {
      name: 'allow-billing',
      enabled: true,
      effect: 'allow',
      source_match: 'billing',
      destination_match: 'stripe',
    },
    {
      name: 'disabled-policy',
      enabled: false,
      effect: 'deny',
      source_match: '*',
      destination_match: '*',
    },
    {
      name: 'allow-all',
      enabled: true,
      effect: 'allow',
      source_match: null,
      destination_match: null,
    },
  ];

  it('should return null when no policies', () => {
    assert.equal(evaluateCachedPolicies({ source_principal: 'a' }, []), null);
  });

  it('should skip disabled policies', () => {
    const result = evaluateCachedPolicies(
      { source_principal: 'any', destination_principal: 'any' },
      [{ name: 'disabled', enabled: false, source_match: '*', destination_match: '*', effect: 'deny' }]
    );
    assert.equal(result, null);
  });

  it('should match by source pattern', () => {
    const result = evaluateCachedPolicies(
      { source_principal: 'billing-agent', source_name: null, destination_principal: 'stripe-api', destination_name: null },
      policies
    );
    assert.equal(result.name, 'allow-billing');
  });

  it('should return first matching policy (first-match wins)', () => {
    const result = evaluateCachedPolicies(
      { source_principal: 'external-api', destination_principal: 'internal-svc' },
      policies
    );
    assert.equal(result.name, 'deny-external');
  });

  it('should match when source_match is absent (null)', () => {
    const result = evaluateCachedPolicies(
      { source_principal: 'unknown', destination_principal: 'unknown' },
      policies
    );
    // First two don't match, third disabled, fourth has null source_match and null destination_match → matches
    assert.equal(result.name, 'allow-all');
  });

  it('should not match when source matches but destination does not', () => {
    const onlySourcePolicy = [
      { name: 'partial', enabled: true, effect: 'deny', source_match: 'billing', destination_match: 'nonexistent' },
    ];
    const result = evaluateCachedPolicies(
      { source_principal: 'billing-agent', destination_principal: 'stripe' },
      onlySourcePolicy
    );
    assert.equal(result, null);
  });
});

// =============================================================================
// createAuditBuffer()
// =============================================================================

describe('createAuditBuffer', () => {
  it('should append events and track count', () => {
    const buf = createAuditBuffer(100, 'relay-1');
    buf.append({ decision: 'allow' });
    buf.append({ decision: 'deny' });
    assert.equal(buf.length, 2);
  });

  it('should enrich events with relay_id and buffered_at', () => {
    const buf = createAuditBuffer(100, 'relay-1');
    buf.append({ decision: 'allow' });
    const events = buf.flush();
    assert.equal(events[0].relay_id, 'relay-1');
    assert.ok(events[0].buffered_at, 'missing buffered_at');
  });

  it('should drop events when buffer is full', () => {
    const buf = createAuditBuffer(2, 'relay-1');
    assert.equal(buf.append({ id: 1 }), true);
    assert.equal(buf.append({ id: 2 }), true);
    assert.equal(buf.append({ id: 3 }), false); // dropped
    assert.equal(buf.stats().dropped, 1);
  });

  it('should flush all events and reset buffer', () => {
    const buf = createAuditBuffer(100, 'relay-1');
    buf.append({ id: 1 });
    buf.append({ id: 2 });
    const events = buf.flush();
    assert.equal(events.length, 2);
    assert.equal(buf.length, 0);
  });

  it('should track flushed count across multiple flushes', () => {
    const buf = createAuditBuffer(100, 'relay-1');
    buf.append({ id: 1 });
    buf.flush();
    buf.append({ id: 2 });
    buf.append({ id: 3 });
    buf.flush();
    assert.equal(buf.stats().flushed, 3);
  });

  it('should return correct stats', () => {
    const buf = createAuditBuffer(2, 'relay-1');
    buf.append({ id: 1 });
    buf.append({ id: 2 });
    buf.append({ id: 3 }); // dropped
    buf.flush();
    const stats = buf.stats();
    assert.equal(stats.buffered, 0);
    assert.equal(stats.flushed, 2);
    assert.equal(stats.dropped, 1);
  });
});

// =============================================================================
// parseConfig()
// =============================================================================

describe('parseConfig', () => {
  it('should return defaults when no env vars', () => {
    const config = parseConfig({});
    assert.equal(config.port, 3005);
    assert.equal(config.envName, 'local');
    assert.equal(config.envType, 'docker');
    assert.equal(config.region, 'local');
  });

  it('should parse port as integer', () => {
    const config = parseConfig({ PORT: '8080' });
    assert.equal(config.port, 8080);
    assert.equal(typeof config.port, 'number');
  });

  it('should split LOCAL_ADAPTERS by comma', () => {
    const config = parseConfig({ LOCAL_ADAPTERS: 'gw1,gw2,gw3' });
    assert.deepEqual(config.localAdapters, ['gw1', 'gw2', 'gw3']);
  });

  it('should return empty array for empty LOCAL_ADAPTERS', () => {
    const config = parseConfig({ LOCAL_ADAPTERS: '' });
    assert.deepEqual(config.localAdapters, []);
  });

  it('should parse all timeout values as integers', () => {
    const config = parseConfig({
      POLICY_SYNC_INTERVAL_MS: '60000',
      AUDIT_FLUSH_INTERVAL_MS: '5000',
      SYNC_TIMEOUT_MS: '3000',
    });
    assert.equal(config.policySyncIntervalMs, 60000);
    assert.equal(config.auditFlushIntervalMs, 5000);
    assert.equal(config.syncTimeoutMs, 3000);
  });
});
