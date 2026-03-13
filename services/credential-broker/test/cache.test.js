const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');

const cache = require('../src/utils/cache');

// =============================================================================
// CredentialCache
// =============================================================================

describe('CredentialCache', () => {
  beforeEach(() => {
    cache.flush();
  });

  it('should return undefined for cache miss', () => {
    assert.equal(cache.get('nonexistent'), undefined);
  });

  it('should store and retrieve a value', () => {
    cache.set('key1', { token: 'abc123' });
    const result = cache.get('key1');
    assert.deepEqual(result, { token: 'abc123' });
  });

  it('should delete a key', () => {
    cache.set('key1', 'value1');
    cache.del('key1');
    assert.equal(cache.get('key1'), undefined);
  });

  it('should flush all keys', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    cache.flush();
    assert.equal(cache.get('key1'), undefined);
    assert.equal(cache.get('key2'), undefined);
  });

  it('should return stats object', () => {
    const stats = cache.getStats();
    assert.ok(typeof stats === 'object', 'stats should be an object');
    assert.ok('hits' in stats, 'stats should have hits');
    assert.ok('misses' in stats, 'stats should have misses');
  });

  it('should return TTL value', () => {
    const ttl = cache.getTTL();
    assert.equal(typeof ttl, 'number');
    assert.ok(ttl > 0, 'TTL should be positive');
  });

  it('should overwrite existing key', () => {
    cache.set('key1', 'old');
    cache.set('key1', 'new');
    assert.equal(cache.get('key1'), 'new');
  });

  it('should handle complex objects', () => {
    const complex = { nested: { key: 'value' }, arr: [1, 2, 3] };
    cache.set('complex', complex);
    const result = cache.get('complex');
    assert.deepEqual(result, complex);
  });
});
