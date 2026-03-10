// =============================================================================
// Provider Manager - Auto-discovers and loads all provider plugins
// =============================================================================

const fs = require('fs');
const path = require('path');

class ProviderManager {
  constructor() {
    this.providers = new Map();
    this.priority = [];
  }

  async loadProviders() {
    console.log('\n🔐 Loading Secret Provider Plugins...');

    const providersDir = __dirname;
    const files = fs.readdirSync(providersDir);

    // Load all *-provider.js files (SKIP base-provider.js and index.js)
    for (const file of files) {
      // Only load files ending with -provider.js, but NOT base-provider.js
      if (file.endsWith('-provider.js') && file !== 'base-provider.js' && file !== 'index.js') {
        try {
          const ProviderClass = require(path.join(providersDir, file));
          const provider = new ProviderClass();
          
          const initialized = await provider.initialize();
          
          if (initialized) {
            this.providers.set(provider.name.toLowerCase().replace(/\s+/g, '-'), provider);
          }
          
        } catch (error) {
          console.error(`  ❌ Failed to load ${file}:`, error.message);
        }
      }
    }

    // Set priority order
    const priorityEnv = process.env.SECRET_PROVIDER_PRIORITY || 'hashicorp-vault,aws-secrets-manager,azure-key-vault,gcp-secret-manager';
    this.priority = priorityEnv.split(',').map(p => p.trim());

    // Log summary
    const activeProviders = Array.from(this.providers.keys());
    if (activeProviders.length === 0) {
      console.warn('  ⚠️  WARNING: No secret providers loaded!');
    } else {
      console.log(`\n✅ Loaded Providers: ${activeProviders.join(', ')}`);
      console.log(`📋 Priority Order: ${this.priority.join(' → ')}`);
    }
  }

  async getSecret(secretPath) {
    for (const providerKey of this.priority) {
      const provider = this.providers.get(providerKey);
      
      if (!provider || !provider.enabled) {
        continue;
      }

      try {
        const secret = await provider.getSecret(secretPath);
        if (secret) {
          return {
            value: secret,
            provider: provider.name
          };
        }
      } catch (error) {
        console.warn(`  ⚠️  ${provider.name} failed: ${error.message}, trying next...`);
      }
    }

    return null;
  }

  // ── Rotation / Write / Revoke (target specific provider) ──

  getProvider(providerKey) {
    return this.providers.get(providerKey) || null;
  }

  getProviderForPath(secretPath) {
    // Try each provider in priority order and return first that has the secret
    for (const providerKey of this.priority) {
      const provider = this.providers.get(providerKey);
      if (provider?.enabled) return { key: providerKey, provider };
    }
    return null;
  }

  async rotateSecret(providerKey, secretPath, newValue) {
    const provider = this.providers.get(providerKey);
    if (!provider?.enabled) throw new Error(`Provider "${providerKey}" not available`);
    if (!provider.supportsRotation()) throw new Error(`Provider "${providerKey}" does not support rotation`);
    return provider.rotateSecret(secretPath, newValue);
  }

  async putSecret(providerKey, secretPath, value) {
    const provider = this.providers.get(providerKey);
    if (!provider?.enabled) throw new Error(`Provider "${providerKey}" not available`);
    return provider.putSecret(secretPath, value);
  }

  async revokeSecret(providerKey, secretPath, version) {
    const provider = this.providers.get(providerKey);
    if (!provider?.enabled) throw new Error(`Provider "${providerKey}" not available`);
    if (!provider.supportsRevocation()) throw new Error(`Provider "${providerKey}" does not support revocation`);
    return provider.revokeSecret(secretPath, version);
  }

  async listSecrets(providerKey, prefix) {
    const provider = this.providers.get(providerKey);
    if (!provider?.enabled) throw new Error(`Provider "${providerKey}" not available`);
    return provider.listSecrets(prefix);
  }

  getProvidersMetadata() {
    const metadata = [];
    for (const [key, provider] of this.providers) {
      metadata.push({
        key,
        ...provider.getMetadata()
      });
    }
    return metadata;
  }

  async healthCheckAll() {
    const results = {};
    for (const [key, provider] of this.providers) {
      results[key] = await provider.healthCheck();
    }
    return results;
  }
}

module.exports = new ProviderManager();
