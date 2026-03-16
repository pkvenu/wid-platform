// =============================================================================
// Azure Key Vault Provider
// =============================================================================

const BaseSecretProvider = require('./base-provider');
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

class AzureProvider extends BaseSecretProvider {
  constructor() {
    super('Azure Key Vault', {
      vaultUrl: process.env.AZURE_KEYVAULT_URL
    });
  }

  async initialize() {
    if (!this.config.vaultUrl) {
      this.log('Not configured (missing AZURE_KEYVAULT_URL)');
      return false;
    }

    try {
      const credential = new DefaultAzureCredential();
      this.client = new SecretClient(this.config.vaultUrl, credential);

      this.enabled = true;
      this.log('✅ Initialized');
      return true;

    } catch (error) {
      this.error(`Failed to initialize: ${error.message}`);
      return false;
    }
  }

  // Azure Key Vault uses secret names (no slashes) — normalize path to name
  _toSecretName(secretPath) {
    return secretPath.replace(/\//g, '-');
  }

  async getSecret(secretPath) {
    if (!this.enabled) return null;

    try {
      const secretName = this._toSecretName(secretPath);
      const secret = await this.client.getSecret(secretName);
      return secret.value;

    } catch (error) {
      if (error.code === 'SecretNotFound' || error.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  // ── Write / Rotation ────────────────────────────────────────────────────

  async putSecret(secretPath, value) {
    if (!this.enabled) throw new Error('Azure Key Vault not initialized');
    const secretName = this._toSecretName(secretPath);
    const secretValue = typeof value === 'string' ? value : JSON.stringify(value);

    const result = await this.client.setSecret(secretName, secretValue);
    return {
      version: result.properties.version,
      provider: this.name,
    };
  }

  async rotateSecret(secretPath, newValue) {
    if (!this.enabled) throw new Error('Azure Key Vault not initialized');
    const secretName = this._toSecretName(secretPath);

    // Capture current version for audit trail
    let oldVersion = null;
    try {
      const current = await this.client.getSecret(secretName);
      oldVersion = current.properties.version;
    } catch { /* first write — no previous version */ }

    const result = await this.putSecret(secretPath, newValue);
    return { oldVersion, newVersion: result.version, provider: this.name };
  }

  async revokeSecret(secretPath, version) {
    if (!this.enabled) throw new Error('Azure Key Vault not initialized');
    const secretName = this._toSecretName(secretPath);

    if (version) {
      // Disable a specific version by updating its properties
      await this.client.updateSecretProperties(secretName, version, {
        enabled: false,
      });
    } else {
      // Soft-delete the entire secret (Azure recoverable delete)
      await this.client.beginDeleteSecret(secretName);
    }

    return { revoked: true, path: secretPath, version: version || 'all' };
  }

  async listSecrets(prefix) {
    if (!this.enabled) return [];
    try {
      const secrets = [];
      for await (const secretProperties of this.client.listPropertiesOfSecrets()) {
        const name = secretProperties.name;
        // Filter by prefix if provided (compare against normalized name)
        if (prefix) {
          const normalizedPrefix = this._toSecretName(prefix);
          if (!name.startsWith(normalizedPrefix)) continue;
        }
        secrets.push({
          path: name,
          createdOn: secretProperties.createdOn,
          updatedOn: secretProperties.updatedOn,
          enabled: secretProperties.enabled,
          provider: this.name,
        });
      }
      return secrets;
    } catch (error) {
      this.error(`listSecrets failed: ${error.message}`);
      return [];
    }
  }

  supportsRotation() { return true; }
  supportsRevocation() { return true; }

  async healthCheck() {
    if (!this.enabled) return false;
    try {
      // List one secret to verify connection and credentials are valid
      const iter = this.client.listPropertiesOfSecrets();
      await iter.next();
      return true;
    } catch (error) {
      this.error(`Health check failed: ${error.message}`);
      return false;
    }
  }

  getSafeConfig() {
    return {
      vaultUrl: this.config.vaultUrl,
    };
  }
}

module.exports = AzureProvider;
