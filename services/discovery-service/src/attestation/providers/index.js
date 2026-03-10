// =============================================================================
// Attestation Provider Registry
// =============================================================================
// Auto-discovers attestation providers and integrates them with the
// AttestationEngine. Pluggable architecture — add a new cloud by dropping
// a file in the providers directory.
//
// Usage:
//   const registry = new AttestationProviderRegistry();
//   await registry.initialize();
//   const evidence = await registry.collectEvidence(workload);
//   const result = await registry.verify(evidence, workload);
// =============================================================================

const fs = require('fs');
const path = require('path');
const BaseAttestationProvider = require('./BaseAttestationProvider');

class AttestationProviderRegistry {
  constructor(config = {}) {
    this.config = config;
    this.providers = new Map();     // name -> provider instance
    this.selfPlatform = null;       // Which cloud WE are running on
    this.providersDir = __dirname;
  }

  /**
   * Auto-discover, load, and initialize all providers
   */
  async initialize() {
    console.log('🔐 Discovering attestation providers...\n');

    // Load all provider files from this directory
    const files = fs.readdirSync(this.providersDir)
      .filter(f => f.endsWith('.js') && f !== 'index.js' && f !== 'BaseAttestationProvider.js');

    for (const file of files) {
      try {
        const providerPath = path.join(this.providersDir, file);
        const ProviderClass = require(providerPath);

        // Skip if not a valid provider
        if (typeof ProviderClass !== 'function') continue;

        const instance = new ProviderClass(this.config);

        // Skip BaseAttestationProvider itself
        if (instance.platform === 'unknown') continue;

        this.providers.set(instance.platform, instance);
        console.log(`  ✔ Loaded provider: ${instance.platform} (${instance.getMethods().join(', ')})`);
      } catch (error) {
        console.error(`  ✗ Failed to load provider ${file}: ${error.message}`);
      }
    }

    // Detect which platform we're running on
    await this.detectSelfPlatform();

    console.log(`\n📊 Attestation providers: ${this.providers.size} loaded`);
    if (this.selfPlatform) {
      console.log(`🏠 Running on: ${this.selfPlatform}\n`);
    } else {
      console.log(`🏠 Running on: unknown (no platform detected)\n`);
    }

    return this;
  }

  /**
   * Detect which cloud platform the discovery service is running on
   */
  async detectSelfPlatform() {
    for (const [name, provider] of this.providers) {
      try {
        const detected = await provider.detect();
        if (detected) {
          this.selfPlatform = name;
          console.log(`  🏠 Detected platform: ${name}`);
          return;
        }
      } catch {
        // Provider not available — that's fine
      }
    }
  }

  /**
   * Collect self-attestation evidence (prove our own identity)
   */
  async collectSelfEvidence() {
    if (!this.selfPlatform) return {};
    const provider = this.providers.get(this.selfPlatform);
    if (!provider) return {};
    return provider.collectSelfEvidence();
  }

  /**
   * Collect attestation evidence for a discovered workload
   * @param {Object} workload - The discovered workload
   * @returns {Object} Evidence from the appropriate provider
   */
  async collectEvidence(workload) {
    const provider = this.getProviderForWorkload(workload);
    if (!provider) return {};

    try {
      return await provider.collectWorkloadEvidence(workload);
    } catch (error) {
      console.log(`  ⚠️  Evidence collection failed for ${workload.name}: ${error.message}`);
      return {};
    }
  }

  /**
   * Verify attestation evidence
   * @param {Object} evidence - Evidence to verify
   * @param {Object} workload - The workload being attested
   * @returns {Object} Verification result
   */
  async verify(evidence, workload) {
    // Determine which provider should verify
    const platform = evidence.platform || workload.cloud_provider;
    const provider = this.providers.get(platform);

    if (!provider) {
      return {
        method: 'unknown',
        success: false,
        reason: `No attestation provider for platform: ${platform}`,
        timestamp: new Date().toISOString(),
      };
    }

    return provider.verify(evidence, workload);
  }

  /**
   * Get the appropriate provider for a workload
   */
  getProviderForWorkload(workload) {
    const platform = workload.cloud_provider;
    return this.providers.get(platform) || null;
  }

  /**
   * Get all registered providers
   */
  getProviders() {
    return Array.from(this.providers.values());
  }

  /**
   * Get provider by platform name
   */
  getProvider(platform) {
    return this.providers.get(platform);
  }

  /**
   * Get summary of all providers for API response
   */
  getSummary() {
    const providers = [];
    for (const [name, provider] of this.providers) {
      providers.push({
        ...provider.getMetadata(),
        is_self: name === this.selfPlatform,
      });
    }
    return {
      total: this.providers.size,
      self_platform: this.selfPlatform,
      providers,
    };
  }
}

module.exports = AttestationProviderRegistry;
