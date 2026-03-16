// =============================================================================
// Credential Cache with TTL
// =============================================================================

const NodeCache = require('node-cache');

const CACHE_TTL = parseInt(process.env.CREDENTIAL_CACHE_TTL || '300');

class CredentialCache {
  constructor() {
    this.cache = new NodeCache({ 
      stdTTL: CACHE_TTL, 
      checkperiod: 60,
      useClones: false 
    });
  }

  get(key) {
    return this.cache.get(key);
  }

  set(key, value) {
    return this.cache.set(key, value);
  }

  del(key) {
    return this.cache.del(key);
  }

  flush() {
    return this.cache.flushAll();
  }

  getStats() {
    return this.cache.getStats();
  }

  getTTL() {
    return CACHE_TTL;
  }

  // --- Tenant-scoped helpers ---

  /**
   * Get a cached value scoped to a specific tenant.
   * @param {string} tenantId
   * @param {string} key - e.g. "stripe:credentials/stripe/api-key"
   */
  tenantGet(tenantId, key) {
    return this.cache.get(`t:${tenantId}:${key}`);
  }

  /**
   * Set a cached value scoped to a specific tenant.
   * @param {string} tenantId
   * @param {string} key
   * @param {*} value
   */
  tenantSet(tenantId, key, value) {
    return this.cache.set(`t:${tenantId}:${key}`, value);
  }

  /**
   * Delete a tenant-scoped cached value.
   * @param {string} tenantId
   * @param {string} key
   */
  tenantDel(tenantId, key) {
    return this.cache.del(`t:${tenantId}:${key}`);
  }
}

module.exports = new CredentialCache();
