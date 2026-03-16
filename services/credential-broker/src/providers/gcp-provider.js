// =============================================================================
// GCP Secret Manager Provider
// =============================================================================

const BaseSecretProvider = require('./base-provider');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

class GCPProvider extends BaseSecretProvider {
  constructor() {
    super('GCP Secret Manager', {
      projectId: process.env.GCP_PROJECT_ID
    });
  }

  async initialize() {
    if (!this.config.projectId) {
      this.log('Not configured (missing GCP_PROJECT_ID)');
      return false;
    }

    try {
      this.client = new SecretManagerServiceClient({
        projectId: this.config.projectId
      });

      this.enabled = true;
      this.log('✅ Initialized');
      return true;

    } catch (error) {
      this.error(`Failed to initialize: ${error.message}`);
      return false;
    }
  }

  async getSecret(secretPath) {
    if (!this.enabled) return null;

    try {
      const name = `projects/${this.config.projectId}/secrets/${secretPath}/versions/latest`;
      const [version] = await this.client.accessSecretVersion({ name });
      const payload = version.payload.data.toString('utf8');

      // Try to parse as JSON
      try {
        const secret = JSON.parse(payload);
        return secret.credential || 
               secret.value || 
               secret.api_key || 
               secret.password ||
               payload;
      } catch {
        return payload;
      }

    } catch (error) {
      if (error.code === 5) { // NOT_FOUND
        return null;
      }
      throw error;
    }
  }

  // ── Write / Rotation ────────────────────────────────────────────────────

  async putSecret(secretPath, value) {
    if (!this.enabled) throw new Error('GCP SM not initialized');
    const payload = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
    const parent = `projects/${this.config.projectId}/secrets/${secretPath}`;

    // Ensure secret exists
    try {
      await this.client.getSecret({ name: parent });
    } catch (error) {
      if (error.code === 5) {
        await this.client.createSecret({
          parent: `projects/${this.config.projectId}`,
          secretId: secretPath,
          secret: { replication: { automatic: {} } },
        });
      } else { throw error; }
    }

    const [version] = await this.client.addSecretVersion({
      parent,
      payload: { data: payload },
    });
    const versionName = version.name.split('/').pop();
    return { version: versionName, provider: this.name };
  }

  async rotateSecret(secretPath, newValue) {
    if (!this.enabled) throw new Error('GCP SM not initialized');

    // Get current version for audit trail
    let oldVersion = null;
    try {
      const parent = `projects/${this.config.projectId}/secrets/${secretPath}`;
      const [versions] = await this.client.listSecretVersions({
        parent,
        filter: 'state:ENABLED',
        pageSize: 1,
      });
      if (versions.length > 0) {
        oldVersion = versions[0].name.split('/').pop();
      }
    } catch { /* first version */ }

    const result = await this.putSecret(secretPath, newValue);
    return { oldVersion, newVersion: result.version, provider: this.name };
  }

  async revokeSecret(secretPath, version) {
    if (!this.enabled) throw new Error('GCP SM not initialized');
    const name = version
      ? `projects/${this.config.projectId}/secrets/${secretPath}/versions/${version}`
      : `projects/${this.config.projectId}/secrets/${secretPath}/versions/latest`;

    await this.client.disableSecretVersion({ name });
    return { revoked: true, path: secretPath, version: version || 'latest' };
  }

  async listSecrets(prefix) {
    if (!this.enabled) return [];
    try {
      const parent = `projects/${this.config.projectId}`;
      const filter = prefix ? `name:${prefix}` : undefined;
      const [secrets] = await this.client.listSecrets({ parent, filter });
      return (secrets || []).map(s => ({
        path: s.name.split('/').pop(),
        createTime: s.createTime,
        provider: this.name,
      }));
    } catch {
      return [];
    }
  }

  supportsRotation() { return true; }
  supportsRevocation() { return true; }

  async healthCheck() {
    if (!this.enabled) return false;
    try {
      // Verify connection by listing secrets with a page size of 1
      const parent = `projects/${this.config.projectId}`;
      await this.client.listSecrets({ parent, pageSize: 1 });
      return true;
    } catch (error) {
      this.error(`Health check failed: ${error.message}`);
      return false;
    }
  }

  getSafeConfig() {
    return {
      projectId: this.config.projectId
    };
  }
}

module.exports = GCPProvider;
