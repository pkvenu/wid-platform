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

  async getSecret(secretPath) {
    if (!this.enabled) return null;

    try {
      // Azure uses secret name, not path (replace / with -)
      const secretName = secretPath.replace(/\//g, '-');
      const secret = await this.client.getSecret(secretName);
      return secret.value;

    } catch (error) {
      if (error.code === 'SecretNotFound') {
        return null; // Secret not found
      }
      throw error;
    }
  }

  getSafeConfig() {
    return {
      vaultUrl: this.config.vaultUrl
    };
  }
}

module.exports = AzureProvider;
