// =============================================================================
// HashiCorp Vault Provider
// =============================================================================

const BaseSecretProvider = require('./base-provider');
const vault = require('node-vault');

class VaultProvider extends BaseSecretProvider {
  constructor() {
    super('HashiCorp Vault', {
      endpoint: process.env.VAULT_ADDR,
      token: process.env.VAULT_TOKEN,
      mountPath: process.env.VAULT_MOUNT_PATH || 'secret',
      kvVersion: process.env.VAULT_KV_VERSION || '2'
    });
  }

  async initialize() {
    if (!this.config.endpoint) {
      this.log('Not configured (missing VAULT_ADDR)');
      return false;
    }

    try {
      this.client = vault({
        endpoint: this.config.endpoint,
        token: this.config.token,
        apiVersion: 'v1'
      });

      // Test connection
      await this.client.health();
      this.enabled = true;
      this.log('✅ Connected');
      return true;

    } catch (error) {
      this.error(`Failed to connect: ${error.message}`);
      return false;
    }
  }

  async getSecret(secretPath) {
    if (!this.enabled) return null;

    try {
      let result;
      
      if (this.config.kvVersion === '2') {
        // KV v2: secret/data/path
        result = await this.client.read(`${this.config.mountPath}/data/${secretPath}`);
        return result.data.data.credential || 
               result.data.data.value || 
               result.data.data.api_key ||
               result.data.data.password;
      } else {
        // KV v1: secret/path
        result = await this.client.read(`${this.config.mountPath}/${secretPath}`);
        return result.data.credential || 
               result.data.value || 
               result.data.api_key ||
               result.data.password;
      }

    } catch (error) {
      if (error.response?.statusCode === 404) {
        return null; // Secret not found
      }
      throw error;
    }
  }

  // ── Write / Rotation ────────────────────────────────────────────────────

  async putSecret(secretPath, value) {
    if (!this.enabled) throw new Error('Vault not initialized');
    const data = typeof value === 'string' ? { credential: value } : value;

    if (this.config.kvVersion === '2') {
      const result = await this.client.write(`${this.config.mountPath}/data/${secretPath}`, { data });
      return { version: String(result.data?.version || 'unknown'), provider: this.name };
    }
    await this.client.write(`${this.config.mountPath}/${secretPath}`, data);
    return { version: 'v1', provider: this.name };
  }

  async rotateSecret(secretPath, newValue) {
    // Read old version for audit trail
    let oldVersion = null;
    try {
      if (this.config.kvVersion === '2') {
        const meta = await this.client.read(`${this.config.mountPath}/metadata/${secretPath}`);
        oldVersion = String(meta.data?.current_version || 'unknown');
      }
    } catch { /* first write — no previous version */ }

    const result = await this.putSecret(secretPath, newValue);
    return { oldVersion, newVersion: result.version, provider: this.name };
  }

  async revokeSecret(secretPath, version) {
    if (!this.enabled) throw new Error('Vault not initialized');
    if (this.config.kvVersion !== '2') throw new Error('Revocation requires KV v2');

    if (version) {
      // Destroy specific version
      await this.client.write(`${this.config.mountPath}/destroy/${secretPath}`, {
        versions: [parseInt(version)]
      });
    } else {
      // Delete all versions (soft delete)
      await this.client.delete(`${this.config.mountPath}/metadata/${secretPath}`);
    }
    return { revoked: true, path: secretPath, version: version || 'all' };
  }

  async listSecrets(prefix) {
    if (!this.enabled) return [];
    try {
      const listPath = this.config.kvVersion === '2'
        ? `${this.config.mountPath}/metadata/${prefix || ''}`
        : `${this.config.mountPath}/${prefix || ''}`;
      const result = await this.client.list(listPath);
      return (result.data?.keys || []).map(key => ({
        path: `${prefix || ''}${key}`,
        provider: this.name,
      }));
    } catch (error) {
      if (error.response?.statusCode === 404) return [];
      throw error;
    }
  }

  // ── Dynamic secrets (Vault-specific) ──────────────────────────────────

  async getDynamicSecret(engine, role) {
    if (!this.enabled) throw new Error('Vault not initialized');
    // Supports: database/creds/:role, aws/sts/:role, pki/issue/:role
    const result = await this.client.read(`${engine}/creds/${role}`);
    return {
      value: result.data,
      lease_id: result.lease_id,
      lease_duration: result.lease_duration,
      renewable: result.renewable,
      provider: this.name,
    };
  }

  async revokeLease(leaseId) {
    if (!this.enabled) throw new Error('Vault not initialized');
    await this.client.write('sys/leases/revoke', { lease_id: leaseId });
    return { revoked: true, lease_id: leaseId };
  }

  supportsRotation() { return true; }
  supportsRevocation() { return true; }
  supportsDynamicSecrets() { return true; }

  async healthCheck() {
    if (!this.enabled) return false;

    try {
      await this.client.health();
      return true;
    } catch (error) {
      return false;
    }
  }

  getSafeConfig() {
    return {
      endpoint: this.config.endpoint,
      mountPath: this.config.mountPath,
      kvVersion: this.config.kvVersion,
      authenticated: !!this.config.token
    };
  }
}

module.exports = VaultProvider;
