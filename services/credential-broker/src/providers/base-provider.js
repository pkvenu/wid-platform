// =============================================================================
// Base Secret Provider - All providers must extend this
// =============================================================================

class BaseSecretProvider {
  constructor(name, config = {}) {
    this.name = name;
    this.config = config;
    this.enabled = false;
    this.client = null;
  }

  async initialize() {
    throw new Error(`${this.name}: initialize() must be implemented`);
  }

  async getSecret(secretPath) {
    throw new Error(`${this.name}: getSecret() must be implemented`);
  }

  // ── Rotation / Lifecycle (optional — override in provider) ──

  async putSecret(secretPath, value) {
    throw new Error(`${this.name}: putSecret() not implemented`);
  }

  async rotateSecret(secretPath, newValue) {
    throw new Error(`${this.name}: rotateSecret() not implemented`);
  }

  async revokeSecret(secretPath, version) {
    throw new Error(`${this.name}: revokeSecret() not implemented`);
  }

  async listSecrets(prefix) {
    throw new Error(`${this.name}: listSecrets() not implemented`);
  }

  supportsRotation() { return false; }
  supportsRevocation() { return false; }
  supportsDynamicSecrets() { return false; }

  async healthCheck() {
    return this.enabled;
  }

  getMetadata() {
    return {
      name: this.name,
      enabled: this.enabled,
      config: this.getSafeConfig()
    };
  }

  getSafeConfig() {
    return { configured: this.enabled };
  }

  log(message) {
    console.log(`  [${this.name}] ${message}`);
  }

  error(message) {
    console.error(`  [${this.name}] ❌ ${message}`);
  }
}

module.exports = BaseSecretProvider;
