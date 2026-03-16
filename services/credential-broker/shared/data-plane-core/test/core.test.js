// =============================================================================
// Shared Core Test Suite
// =============================================================================
// Tests ALL shared logic used by both ext-authz-adapter and edge-gateway.
// If these pass, both deployment modes have a correct foundation.
// =============================================================================

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const {
  PolicyCache,
  CredentialBuffer,
  CircuitBreaker,
  RateLimiter,
  MetricsCollector,
  AuditBuffer,
  sanitizeHeaders,
  sanitizePath,
  extractWorkloadName,
  extractNamespace,
  buildAuditEntry,
  generateIptablesScript,
  parseJSON,
  SENSITIVE_HEADERS,
  SAFE_HEADERS,
} = require('../src/core.js');

// ── PolicyCache ──────────────────────────────────────────────────────────────

describe('PolicyCache', () => {
  let cache;
  beforeEach(() => { cache = new PolicyCache({ ttlMs: 50, maxEntries: 3 }); });

  it('returns null on miss', () => {
    assert.equal(cache.get('a', 'b', 'GET', '/'), null);
  });

  it('returns cached decision on hit', () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/'), { verdict: 'allow' });
  });

  it('expires entries after TTL', async () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    await new Promise(r => setTimeout(r, 70));
    assert.equal(cache.get('a', 'b', 'GET', '/'), null);
  });

  it('normalizes UUIDs in paths', () => {
    cache.set('a', 'b', 'GET', '/users/550e8400-e29b-41d4-a716-446655440000', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'), { verdict: 'allow' });
  });

  it('normalizes numeric IDs in paths', () => {
    cache.set('a', 'b', 'GET', '/users/12345', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/users/99999'), { verdict: 'allow' });
  });

  it('strips query params for cache keys', () => {
    cache.set('a', 'b', 'GET', '/data', { verdict: 'allow' });
    assert.deepEqual(cache.get('a', 'b', 'GET', '/data?secret=token&user=123'), { verdict: 'allow' });
  });

  it('isolates by method', () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.equal(cache.get('a', 'b', 'POST', '/'), null);
  });

  it('isolates by principal', () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.equal(cache.get('c', 'b', 'GET', '/'), null);
  });

  it('evicts LRU when full', () => {
    cache.set('a', 'b', 'GET', '/1', { v: 1 });
    cache.set('a', 'b', 'GET', '/2', { v: 2 });
    cache.set('a', 'b', 'GET', '/3', { v: 3 });
    cache.set('a', 'b', 'GET', '/4', { v: 4 }); // evicts /1
    assert.equal(cache.get('a', 'b', 'GET', '/1'), null);
    assert.deepEqual(cache.get('a', 'b', 'GET', '/4'), { v: 4 });
  });

  it('clear() empties cache', () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    cache.clear();
    assert.equal(cache.get('a', 'b', 'GET', '/'), null);
  });

  it('preserves version prefixes', () => {
    cache.set('a', 'b', 'GET', '/v1/users', { verdict: 'allow' });
    assert.equal(cache.get('a', 'b', 'GET', '/v2/users'), null);
  });

  it('getStats returns hit rate', () => {
    cache.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    cache.get('a', 'b', 'GET', '/');     // hit
    cache.get('a', 'b', 'POST', '/');    // miss
    const stats = cache.getStats();
    assert.equal(stats.hits, 1);
    assert.equal(stats.misses, 1);
    assert.equal(stats.hitRate, '50.0%');
  });

  it('disabled cache always misses', () => {
    const disabled = new PolicyCache({ enabled: false });
    disabled.set('a', 'b', 'GET', '/', { verdict: 'allow' });
    assert.equal(disabled.get('a', 'b', 'GET', '/'), null);
  });
});

// ── CredentialBuffer ─────────────────────────────────────────────────────────

describe('CredentialBuffer', () => {
  let buf;
  beforeEach(() => { buf = new CredentialBuffer({ ttlMs: 50 }); });

  it('returns null on miss', () => {
    assert.equal(buf.get('a', 'b'), null);
  });

  it('returns buffered credential on hit', () => {
    buf.set('a', 'b', { token: 'abc' });
    assert.deepEqual(buf.get('a', 'b'), { token: 'abc' });
  });

  it('expires after buffer TTL', async () => {
    buf.set('a', 'b', { token: 'abc' });
    await new Promise(r => setTimeout(r, 70));
    assert.equal(buf.get('a', 'b'), null);
  });

  it('expires when token itself expires', () => {
    buf.set('a', 'b', { token: 'abc', expires_at: new Date(Date.now() - 1000).toISOString() });
    assert.equal(buf.get('a', 'b'), null);
  });

  it('disabled buffer always misses', () => {
    const disabled = new CredentialBuffer({ enabled: false });
    disabled.set('a', 'b', { token: 'abc' });
    assert.equal(disabled.get('a', 'b'), null);
  });
});

// ── CircuitBreaker ───────────────────────────────────────────────────────────

describe('CircuitBreaker', () => {
  let breaker;
  beforeEach(() => { breaker = new CircuitBreaker({ threshold: 3, cooldownMs: 100 }); });

  it('starts closed', () => {
    assert.equal(breaker.isOpen(), false);
    assert.equal(breaker.getState().state, 'closed');
  });

  it('stays closed below threshold', () => {
    breaker.recordFailure();
    breaker.recordFailure();
    assert.equal(breaker.isOpen(), false);
  });

  it('trips open at threshold', () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure();
    assert.equal(breaker.isOpen(), true);
    assert.equal(breaker.getState().state, 'open');
  });

  it('transitions to half-open after cooldown', async () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure();
    await new Promise(r => setTimeout(r, 150));
    assert.equal(breaker.isOpen(), false);
    assert.equal(breaker.getState().state, 'half-open');
  });

  it('recovers on success in half-open', async () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure();
    await new Promise(r => setTimeout(r, 150));
    breaker.isOpen(); // transition to half-open
    breaker.recordSuccess();
    assert.equal(breaker.getState().state, 'closed');
  });

  it('re-trips on failure in half-open', async () => {
    for (let i = 0; i < 3; i++) breaker.recordFailure();
    await new Promise(r => setTimeout(r, 150));
    breaker.isOpen(); // transition to half-open
    breaker.recordFailure();
    assert.equal(breaker.getState().state, 'open');
  });
});

// ── RateLimiter ──────────────────────────────────────────────────────────────

describe('RateLimiter', () => {
  it('allows within limit', () => {
    const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 3, enabled: true });
    assert.equal(limiter.isAllowed('a'), true);
    assert.equal(limiter.isAllowed('a'), true);
    assert.equal(limiter.isAllowed('a'), true);
  });

  it('denies over limit', () => {
    const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 2, enabled: true });
    limiter.isAllowed('a');
    limiter.isAllowed('a');
    assert.equal(limiter.isAllowed('a'), false);
  });

  it('isolates by principal', () => {
    const limiter = new RateLimiter({ windowMs: 1000, maxRequests: 1, enabled: true });
    assert.equal(limiter.isAllowed('a'), true);
    assert.equal(limiter.isAllowed('b'), true);
    assert.equal(limiter.isAllowed('a'), false);
  });

  it('always allows when disabled', () => {
    const limiter = new RateLimiter({ enabled: false });
    for (let i = 0; i < 100; i++) assert.equal(limiter.isAllowed('a'), true);
  });
});

// ── Data Sanitization ────────────────────────────────────────────────────────

describe('sanitizeHeaders', () => {
  it('strips authorization', () => {
    const r = sanitizeHeaders({ Authorization: 'Bearer secret' });
    assert.equal(r['authorization'], undefined);
  });

  it('strips cookie', () => {
    const r = sanitizeHeaders({ Cookie: 'session=abc' });
    assert.equal(r['cookie'], undefined);
  });

  it('strips x-api-key', () => {
    const r = sanitizeHeaders({ 'X-API-Key': 'secret' });
    assert.equal(r['x-api-key'], undefined);
  });

  it('strips x-user-id', () => {
    assert.equal(sanitizeHeaders({ 'X-User-ID': '123' })['x-user-id'], undefined);
  });

  it('strips x-account-id', () => {
    assert.equal(sanitizeHeaders({ 'X-Account-ID': 'acct' })['x-account-id'], undefined);
  });

  it('strips x-tenant-id', () => {
    assert.equal(sanitizeHeaders({ 'X-Tenant-ID': 't1' })['x-tenant-id'], undefined);
  });

  it('strips x-customer-id', () => {
    assert.equal(sanitizeHeaders({ 'X-Customer-ID': 'c1' })['x-customer-id'], undefined);
  });

  it('strips x-session-id', () => {
    assert.equal(sanitizeHeaders({ 'X-Session-ID': 's1' })['x-session-id'], undefined);
  });

  it('strips trace headers', () => {
    const r = sanitizeHeaders({ 'X-B3-TraceId': 'abc', 'X-B3-SpanId': 'def' });
    assert.equal(r['x-b3-traceid'], undefined);
    assert.equal(r['x-b3-spanid'], undefined);
  });

  it('strips proxy-authorization', () => {
    assert.equal(sanitizeHeaders({ 'Proxy-Authorization': 'x' })['proxy-authorization'], undefined);
  });

  it('strips x-forwarded-for', () => {
    assert.equal(sanitizeHeaders({ 'X-Forwarded-For': '1.2.3.4' })['x-forwarded-for'], undefined);
  });

  it('allows safe headers', () => {
    const r = sanitizeHeaders({ 'Content-Type': 'application/json', 'Accept': 'text/html' });
    assert.equal(r['content-type'], 'application/json');
    assert.equal(r['accept'], 'text/html');
  });

  it('allows x-envoy-* headers', () => {
    const r = sanitizeHeaders({ 'X-Envoy-Peer-Metadata': 'abc' });
    assert.equal(r['x-envoy-peer-metadata'], 'abc');
  });

  it('strips headers longer than 256 chars', () => {
    const r = sanitizeHeaders({ 'Content-Type': 'a'.repeat(300) });
    assert.equal(r['content-type'], undefined);
  });

  it('blocks unknown headers', () => {
    const r = sanitizeHeaders({ 'X-Custom-Stuff': 'val' });
    assert.equal(r['x-custom-stuff'], undefined);
  });

  it('handles null input', () => {
    assert.deepEqual(sanitizeHeaders(null), {});
    assert.deepEqual(sanitizeHeaders(undefined), {});
  });

  it('strips x-csrf-token', () => {
    assert.equal(sanitizeHeaders({ 'X-CSRF-Token': 'tok' })['x-csrf-token'], undefined);
  });

  it('strips x-real-ip', () => {
    assert.equal(sanitizeHeaders({ 'X-Real-IP': '10.0.0.1' })['x-real-ip'], undefined);
  });
});

describe('sanitizePath', () => {
  it('strips query params', () => {
    assert.equal(sanitizePath('/data?secret=123&user=abc'), '/data');
  });

  it('replaces UUIDs', () => {
    assert.equal(sanitizePath('/users/550e8400-e29b-41d4-a716-446655440000'), '/users/{uuid}');
  });

  it('replaces numeric IDs', () => {
    assert.equal(sanitizePath('/users/12345'), '/users/{id}');
  });

  it('replaces long tokens', () => {
    assert.equal(sanitizePath('/verify/abcdefghijklmnopqrstuvwxyz'), '/verify/{token}');
  });

  it('handles null/undefined', () => {
    assert.equal(sanitizePath(null), '/');
    assert.equal(sanitizePath(undefined), '/');
  });

  it('preserves version prefixes', () => {
    assert.match(sanitizePath('/v1/users/12345'), /^\/v1\/users\/\{id\}$/);
  });

  it('handles multiple replacements', () => {
    const result = sanitizePath('/v1/orgs/550e8400-e29b-41d4-a716-446655440000/users/12345?page=1');
    assert.equal(result, '/v1/orgs/{uuid}/users/{id}');
  });
});

describe('extractWorkloadName', () => {
  it('extracts name from SPIFFE ID', () => {
    assert.equal(extractWorkloadName('spiffe://cluster.local/ns/prod/sa/frontend'), 'frontend');
  });

  it('handles unknown', () => {
    assert.equal(extractWorkloadName('unknown'), 'unknown');
    assert.equal(extractWorkloadName(null), 'unknown');
    assert.equal(extractWorkloadName(''), 'unknown');
  });
});

describe('extractNamespace', () => {
  it('extracts namespace from SPIFFE ID', () => {
    assert.equal(extractNamespace('spiffe://cluster.local/ns/prod/sa/frontend'), 'prod');
  });

  it('handles missing namespace', () => {
    assert.equal(extractNamespace('some-principal'), 'unknown');
    assert.equal(extractNamespace(null), 'unknown');
  });
});

// ── MetricsCollector ─────────────────────────────────────────────────────────

describe('MetricsCollector', () => {
  let metrics;
  beforeEach(() => { metrics = new MetricsCollector(); });

  it('counts decisions', () => {
    metrics.record('allowed', 10);
    metrics.record('denied', 20);
    metrics.record('error', 30);
    const s = metrics.getSnapshot();
    assert.equal(s.counters.total, 3);
    assert.equal(s.counters.allowed, 1);
    assert.equal(s.counters.denied, 1);
    assert.equal(s.counters.errors, 1);
  });

  it('calculates latency percentiles', () => {
    for (let i = 1; i <= 100; i++) metrics.record('allowed', i);
    const s = metrics.getSnapshot();
    assert.equal(s.latency.p50, 50);
    assert.ok(s.latency.p99 >= 99);
  });

  it('generates prometheus format', () => {
    metrics.record('allowed', 10);
    const prom = metrics.toPrometheus();
    assert.match(prom, /wid_extauthz_total_total 1/);
    assert.match(prom, /wid_extauthz_allowed_total 1/);
    assert.match(prom, /wid_extauthz_latency_p50/);
  });

  it('records cache hits', () => {
    metrics.recordCacheHit();
    metrics.recordCacheHit();
    assert.equal(metrics.getSnapshot().counters.cached, 2);
  });
});

// ── AuditBuffer ──────────────────────────────────────────────────────────────

describe('AuditBuffer', () => {
  it('buffers entries and reports pending count', () => {
    const buf = new AuditBuffer({ endpoint: null });
    buf.push({ id: 1 });
    buf.push({ id: 2 });
    assert.equal(buf.getStats().pending, 2);
  });

  it('cleans up timer on destroy', () => {
    const buf = new AuditBuffer({ endpoint: 'http://localhost:9999/batch', flushIntervalMs: 100 });
    buf.push({ id: 1 });
    buf.destroy();
    // No assertion needed — just shouldn't throw
  });
});

// ── buildAuditEntry ──────────────────────────────────────────────────────────

describe('buildAuditEntry', () => {
  it('creates structured entry with sanitized data', () => {
    const entry = buildAuditEntry(
      'dec_123',
      'spiffe://cluster.local/ns/prod/sa/frontend',
      'spiffe://cluster.local/ns/prod/sa/backend',
      'GET', '/api/v1/users/12345?token=secret',
      'allowed',
      { mode: 'audit', token_jti: 'jti_abc', chain_depth: 1, adapter_mode: 'local' },
      15, false
    );
    assert.equal(entry.decision_id, 'dec_123');
    assert.equal(entry.source_name, 'frontend');
    assert.equal(entry.destination_name, 'backend');
    assert.equal(entry.path_pattern, '/api/v1/users/{id}');
    assert.equal(entry.verdict, 'allowed');
    assert.equal(entry.cached, false);
    // No query params in path
    assert.ok(!entry.path_pattern.includes('token'));
    assert.ok(!entry.path_pattern.includes('secret'));
  });

  it('contains no customer data', () => {
    const entry = buildAuditEntry('d1', 'src', 'dst', 'POST', '/data?ssn=123-45-6789', 'denied', {}, 10, false);
    const json = JSON.stringify(entry);
    assert.ok(!json.includes('123-45-6789'));
  });
});

// ── generateIptablesScript ───────────────────────────────────────────────────

describe('generateIptablesScript', () => {
  it('generates valid bash script', () => {
    const script = generateIptablesScript({ outboundPort: 15001, inboundPort: 15006 });
    assert.match(script, /^#!\/bin\/bash/);
    assert.match(script, /iptables -t nat/);
  });

  it('excludes platform service ports', () => {
    const script = generateIptablesScript({});
    assert.match(script, /--dport 3001/); // policy engine
    assert.match(script, /--dport 3000/); // token service
    assert.match(script, /--dport 3002/); // broker
  });

  it('excludes DNS', () => {
    const script = generateIptablesScript({});
    assert.match(script, /--dport 53/);
  });

  it('excludes gateway UID', () => {
    const script = generateIptablesScript({ gatewayUid: 1337 });
    assert.match(script, /--uid-owner 1337/);
  });
});

// ── parseJSON ────────────────────────────────────────────────────────────────

describe('parseJSON', () => {
  it('parses valid JSON', () => {
    assert.deepEqual(parseJSON('{"a":1}', {}), { a: 1 });
  });

  it('returns fallback on invalid JSON', () => {
    assert.deepEqual(parseJSON('not-json', { x: 1 }), { x: 1 });
  });

  it('returns fallback on null', () => {
    assert.deepEqual(parseJSON(null, []), []);
  });
});
