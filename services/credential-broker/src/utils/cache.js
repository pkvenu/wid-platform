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
}

module.exports = new CredentialCache();
