// =============================================================================
// AWS Secrets Manager Provider
// =============================================================================

const BaseSecretProvider = require('./base-provider');
const {
  SecretsManagerClient, GetSecretValueCommand,
  PutSecretValueCommand, RotateSecretCommand,
  ListSecretsCommand, UpdateSecretVersionStageCommand,
} = require('@aws-sdk/client-secrets-manager');

class AWSProvider extends BaseSecretProvider {
  constructor() {
    super('AWS Secrets Manager', {
      region: process.env.AWS_REGION,
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    });
  }

  async initialize() {
    if (!this.config.region) {
      this.log('Not configured (missing AWS_REGION)');
      return false;
    }

    try {
      this.client = new SecretsManagerClient({
        region: this.config.region,
        credentials: this.config.accessKeyId ? {
          accessKeyId: this.config.accessKeyId,
          secretAccessKey: this.config.secretAccessKey
        } : undefined // Use IAM role if no explicit credentials
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
      const command = new GetSecretValueCommand({
        SecretId: secretPath
      });

      const response = await this.client.send(command);

      if (response.SecretString) {
        // Try to parse as JSON first
        try {
          const secret = JSON.parse(response.SecretString);
          return secret.credential || 
                 secret.value || 
                 secret.api_key || 
                 secret.password ||
                 response.SecretString;
        } catch {
          // Return as-is if not JSON
          return response.SecretString;
        }
      } else if (response.SecretBinary) {
        return Buffer.from(response.SecretBinary, 'base64').toString('ascii');
      }

      return null;

    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        return null; // Secret not found
      }
      throw error;
    }
  }

  // ── Write / Rotation ────────────────────────────────────────────────────

  async putSecret(secretPath, value) {
    if (!this.enabled) throw new Error('AWS SM not initialized');
    const secretString = typeof value === 'string' ? value : JSON.stringify(value);
    const result = await this.client.send(new PutSecretValueCommand({
      SecretId: secretPath,
      SecretString: secretString,
    }));
    return { version: result.VersionId, provider: this.name };
  }

  async rotateSecret(secretPath, newValue) {
    if (!this.enabled) throw new Error('AWS SM not initialized');

    if (newValue) {
      // Manual rotation: write new value
      let oldVersion = null;
      try {
        const old = await this.client.send(new GetSecretValueCommand({ SecretId: secretPath }));
        oldVersion = old.VersionId;
      } catch { /* new secret */ }

      const result = await this.putSecret(secretPath, newValue);
      return { oldVersion, newVersion: result.version, provider: this.name };
    }

    // AWS-managed rotation (requires Lambda rotation function configured)
    const result = await this.client.send(new RotateSecretCommand({
      SecretId: secretPath,
    }));
    return { oldVersion: null, newVersion: result.VersionId, provider: this.name };
  }

  async revokeSecret(secretPath, version) {
    if (!this.enabled) throw new Error('AWS SM not initialized');
    // AWS doesn't truly "revoke" — we remove AWSCURRENT staging label
    if (version) {
      await this.client.send(new UpdateSecretVersionStageCommand({
        SecretId: secretPath,
        VersionStage: 'AWSCURRENT',
        RemoveFromVersionId: version,
      }));
    }
    return { revoked: true, path: secretPath, version: version || 'current' };
  }

  async listSecrets(prefix) {
    if (!this.enabled) return [];
    try {
      const params = {};
      if (prefix) {
        params.Filters = [{ Key: 'name', Values: [prefix] }];
      }
      const result = await this.client.send(new ListSecretsCommand(params));
      return (result.SecretList || []).map(s => ({
        path: s.Name,
        lastRotated: s.LastRotatedDate,
        lastAccessed: s.LastAccessedDate,
        provider: this.name,
      }));
    } catch (error) {
      return [];
    }
  }

  supportsRotation() { return true; }
  supportsRevocation() { return true; }

  async healthCheck() {
    if (!this.enabled) return false;
    try {
      // Verify connection by listing secrets with a max of 1
      await this.client.send(new ListSecretsCommand({ MaxResults: 1 }));
      return true;
    } catch (error) {
      this.error(`Health check failed: ${error.message}`);
      return false;
    }
  }

  getSafeConfig() {
    return {
      region: this.config.region,
      authenticated: !!this.config.accessKeyId || 'IAM Role'
    };
  }
}

module.exports = AWSProvider;
