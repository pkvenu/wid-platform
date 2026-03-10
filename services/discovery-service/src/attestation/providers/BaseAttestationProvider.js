// =============================================================================
// Base Attestation Provider — Abstract Interface
// =============================================================================
// Each cloud/platform implements this to:
//   1. Detect if running on that platform
//   2. Collect attestation evidence from the platform's metadata service
//   3. Verify attestation evidence from workloads on that platform
//
// The AttestationEngine uses these providers to automatically collect and
// verify evidence without manual input.
// =============================================================================

class BaseAttestationProvider {
  constructor(config = {}) {
    this.config = config;
    this.name = this.constructor.name;
    this.platform = 'unknown';
    this.tier = 1; // Default: cryptographic
  }

  /**
   * Detect if we're currently running on this platform
   * @returns {Promise<boolean>}
   */
  async detect() {
    throw new Error(`${this.name} must implement detect()`);
  }

  /**
   * Collect attestation evidence from the platform's metadata service
   * This is called when WE are running on this platform and need to prove our own identity
   * @returns {Promise<Object>} Evidence object compatible with AttestationEngine
   */
  async collectSelfEvidence() {
    throw new Error(`${this.name} must implement collectSelfEvidence()`);
  }

  /**
   * Collect attestation evidence for a discovered workload on this platform
   * This is called during scan to gather evidence about OTHER workloads
   * @param {Object} workload - The discovered workload
   * @returns {Promise<Object>} Evidence object
   */
  async collectWorkloadEvidence(workload) {
    return {};
  }

  /**
   * Verify attestation evidence from a workload
   * @param {Object} evidence - Evidence to verify
   * @param {Object} workload - The workload being attested
   * @returns {Promise<Object>} Verification result
   */
  async verify(evidence, workload) {
    throw new Error(`${this.name} must implement verify()`);
  }

  /**
   * Get the attestation methods this provider supports
   * @returns {string[]}
   */
  getMethods() {
    return [];
  }

  /**
   * Get provider metadata
   */
  getMetadata() {
    return {
      name: this.name,
      platform: this.platform,
      tier: this.tier,
      methods: this.getMethods(),
    };
  }

  // ── Helpers ──

  async httpGet(url, headers = {}, timeoutMs = 3000) {
    const http = require('http');
    const https = require('https');
    return new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { headers, timeout: timeoutMs, rejectUnauthorized: false }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 400) reject(new Error(`HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
          else resolve(data);
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
  }

  async httpGetJSON(url, headers = {}, timeoutMs = 3000) {
    const data = await this.httpGet(url, headers, timeoutMs);
    return JSON.parse(data);
  }

  decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format');
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url').toString()),
      payload: JSON.parse(Buffer.from(parts[1], 'base64url').toString()),
      signature: parts[2],
    };
  }

  log(message, level = 'info') {
    const prefix = { info: '  ℹ️ ', success: '  ✓', error: '  ✗', warn: '  ⚠️ ' }[level] || '  ';
    console.log(`${prefix} [${this.platform}] ${message}`);
  }
}

module.exports = BaseAttestationProvider;
