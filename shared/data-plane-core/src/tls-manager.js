// =============================================================================
// TLS Manager — mTLS Certificate Management for Hub-Spoke Federation
// =============================================================================
//
// Handles:
//   1. Certificate loading from file paths (PEM format)
//   2. SPIFFE ID extraction from X.509 SAN URI fields
//   3. File watching for automatic certificate rotation (SPIRE SVIDs)
//   4. mTLS https.Agent creation for relay-to-hub connections
//   5. Certificate fingerprint computation (SHA-256 of DER)
//   6. Certificate chain validation utilities
//
// Usage:
//   const { TLSManager } = require('@wid/core');
//   const tls = new TLSManager({
//     certPath: '/run/spire/agent/svid.pem',
//     keyPath:  '/run/spire/agent/svid_key.pem',
//     caPath:   '/run/spire/agent/bundle.pem',
//   });
//   const agent = tls.createMTLSAgent();
//
// =============================================================================

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const { X509Certificate } = require('crypto');

class TLSManager {
  /**
   * @param {Object} opts
   * @param {string} opts.certPath     - Path to client certificate (PEM)
   * @param {string} opts.keyPath      - Path to private key (PEM)
   * @param {string} [opts.caPath]     - Path to CA bundle (PEM) for verifying server cert
   * @param {boolean} [opts.watchFiles] - Watch cert/key files for rotation (default: true)
   * @param {Function} [opts.onRotation] - Callback when cert is rotated
   * @param {Function} [opts.log]       - Logging function (default: console.log)
   */
  constructor(opts = {}) {
    this.certPath = opts.certPath || null;
    this.keyPath = opts.keyPath || null;
    this.caPath = opts.caPath || null;
    this.watchFiles = opts.watchFiles !== false;
    this.onRotation = opts.onRotation || null;
    this.log = opts.log || ((level, msg, meta) => {
      console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }));
    });

    // Loaded state
    this._cert = null;       // PEM string
    this._key = null;        // PEM string
    this._ca = null;         // PEM string
    this._x509 = null;       // X509Certificate instance
    this._fingerprint = null; // SHA-256 hex
    this._spiffeId = null;    // URI from SAN
    this._agent = null;       // https.Agent (invalidated on rotation)
    this._watchers = [];

    // Load certs if paths provided
    if (this.certPath && this.keyPath) {
      this._loadCertificates();
      if (this.watchFiles) {
        this._startWatching();
      }
    }
  }

  // ── Certificate Loading ──────────────────────────────────────────

  _loadCertificates() {
    try {
      this._cert = fs.readFileSync(this.certPath, 'utf8');
      this._key = fs.readFileSync(this.keyPath, 'utf8');
      if (this.caPath && fs.existsSync(this.caPath)) {
        this._ca = fs.readFileSync(this.caPath, 'utf8');
      }

      // Parse X.509 for metadata extraction
      this._x509 = new X509Certificate(this._cert);
      this._fingerprint = this._computeFingerprint(this._cert);
      this._spiffeId = this._extractSpiffeId(this._x509);

      // Invalidate cached agent
      this._agent = null;

      this.log('info', 'TLS certificates loaded', {
        subject: this._x509.subject,
        issuer: this._x509.issuer,
        spiffeId: this._spiffeId,
        fingerprint: this._fingerprint?.substring(0, 16) + '...',
        validFrom: this._x509.validFrom,
        validTo: this._x509.validTo,
        hasCA: !!this._ca,
      });
    } catch (e) {
      this.log('error', 'Failed to load TLS certificates', {
        certPath: this.certPath,
        keyPath: this.keyPath,
        error: e.message,
      });
      throw e;
    }
  }

  // ── SPIFFE ID Extraction ─────────────────────────────────────────

  /**
   * Extract SPIFFE ID from X.509 SAN URI field.
   * SPIFFE IDs are URIs in the Subject Alternative Name extension:
   *   spiffe://trust-domain/path
   */
  _extractSpiffeId(x509) {
    if (!x509) return null;
    try {
      const san = x509.subjectAltName;
      if (!san) return null;

      // subjectAltName format: "URI:spiffe://domain/path, DNS:hostname"
      const parts = san.split(',').map(s => s.trim());
      for (const part of parts) {
        if (part.startsWith('URI:spiffe://')) {
          return part.substring(4); // Remove "URI:" prefix
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  // ── Certificate Fingerprint ──────────────────────────────────────

  /**
   * Compute SHA-256 fingerprint of the DER-encoded certificate.
   * This uniquely identifies the certificate for registration pinning.
   */
  _computeFingerprint(certPem) {
    try {
      // Convert PEM to DER
      const lines = certPem.split('\n')
        .filter(l => !l.startsWith('-----'))
        .join('');
      const der = Buffer.from(lines, 'base64');
      return crypto.createHash('sha256').update(der).digest('hex');
    } catch {
      return null;
    }
  }

  // ── File Watching for Rotation ───────────────────────────────────

  _startWatching() {
    const watchOpts = { persistent: false };
    const reload = (filePath) => {
      this.log('info', 'Certificate file changed, reloading', { file: filePath });
      try {
        this._loadCertificates();
        if (this.onRotation) {
          this.onRotation({
            spiffeId: this._spiffeId,
            fingerprint: this._fingerprint,
            validTo: this._x509?.validTo,
          });
        }
      } catch (e) {
        this.log('error', 'Certificate reload failed', { error: e.message });
      }
    };

    // Debounce: SPIRE writes cert + key in rapid succession
    let debounceTimer = null;
    const debouncedReload = (filePath) => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => reload(filePath), 500);
    };

    try {
      if (this.certPath) {
        const w = fs.watch(this.certPath, watchOpts, () => debouncedReload(this.certPath));
        this._watchers.push(w);
      }
      if (this.keyPath) {
        const w = fs.watch(this.keyPath, watchOpts, () => debouncedReload(this.keyPath));
        this._watchers.push(w);
      }
      if (this.caPath && fs.existsSync(this.caPath)) {
        const w = fs.watch(this.caPath, watchOpts, () => debouncedReload(this.caPath));
        this._watchers.push(w);
      }
    } catch (e) {
      this.log('warn', 'Certificate file watching not available', { error: e.message });
    }
  }

  // ── mTLS Agent Creation ──────────────────────────────────────────

  /**
   * Create an https.Agent configured for mutual TLS.
   * Cached until certificates are rotated.
   */
  createMTLSAgent(extraOpts = {}) {
    if (this._agent && !extraOpts.forceNew) return this._agent;

    if (!this._cert || !this._key) {
      throw new Error('Cannot create mTLS agent: certificates not loaded');
    }

    this._agent = new https.Agent({
      cert: this._cert,
      key: this._key,
      ca: this._ca || undefined,
      rejectUnauthorized: extraOpts.rejectUnauthorized !== false,
      keepAlive: true,
      keepAliveMsecs: 30000,
      maxSockets: extraOpts.maxSockets || 10,
      ...extraOpts,
    });

    return this._agent;
  }

  // ── Certificate Validation ───────────────────────────────────────

  /**
   * Validate a peer certificate against our CA bundle.
   * Used by the hub to verify incoming relay certificates.
   *
   * @param {string|Buffer} peerCertPem - PEM-encoded certificate to validate
   * @returns {{ valid: boolean, spiffeId: string|null, fingerprint: string, subject: string, issuer: string, error?: string }}
   */
  validatePeerCert(peerCertPem) {
    try {
      const peerX509 = new X509Certificate(peerCertPem);
      const fingerprint = this._computeFingerprint(
        typeof peerCertPem === 'string' ? peerCertPem : peerCertPem.toString('utf8')
      );
      const spiffeId = this._extractSpiffeId(peerX509);

      // Check expiry
      const now = new Date();
      const validFrom = new Date(peerX509.validFrom);
      const validTo = new Date(peerX509.validTo);
      if (now < validFrom || now > validTo) {
        return {
          valid: false,
          spiffeId,
          fingerprint,
          subject: peerX509.subject,
          issuer: peerX509.issuer,
          error: `Certificate expired or not yet valid (valid: ${peerX509.validFrom} to ${peerX509.validTo})`,
        };
      }

      // Verify against CA if available
      if (this._ca) {
        const caX509 = new X509Certificate(this._ca);
        if (!peerX509.checkIssued(caX509)) {
          return {
            valid: false,
            spiffeId,
            fingerprint,
            subject: peerX509.subject,
            issuer: peerX509.issuer,
            error: 'Certificate not issued by trusted CA',
          };
        }
      }

      return {
        valid: true,
        spiffeId,
        fingerprint,
        subject: peerX509.subject,
        issuer: peerX509.issuer,
        validFrom: peerX509.validFrom,
        validTo: peerX509.validTo,
      };
    } catch (e) {
      return {
        valid: false,
        spiffeId: null,
        fingerprint: null,
        subject: null,
        issuer: null,
        error: e.message,
      };
    }
  }

  // ── Certificate Info ─────────────────────────────────────────────

  /**
   * Check if the loaded certificate is expiring soon.
   * @param {number} thresholdMs - Threshold in ms (default: 1 hour)
   */
  isExpiringSoon(thresholdMs = 3600000) {
    if (!this._x509) return true;
    const validTo = new Date(this._x509.validTo);
    return (validTo.getTime() - Date.now()) < thresholdMs;
  }

  /**
   * Get remaining validity in seconds.
   */
  getRemainingValiditySec() {
    if (!this._x509) return 0;
    const validTo = new Date(this._x509.validTo);
    return Math.max(0, Math.round((validTo.getTime() - Date.now()) / 1000));
  }

  // ── Accessors ────────────────────────────────────────────────────

  get spiffeId()     { return this._spiffeId; }
  get fingerprint()  { return this._fingerprint; }
  get certificate()  { return this._cert; }
  get isLoaded()     { return !!this._cert && !!this._key; }
  get certInfo() {
    if (!this._x509) return null;
    return {
      subject: this._x509.subject,
      issuer: this._x509.issuer,
      spiffeId: this._spiffeId,
      fingerprint: this._fingerprint,
      validFrom: this._x509.validFrom,
      validTo: this._x509.validTo,
      serialNumber: this._x509.serialNumber,
    };
  }

  // ── Cleanup ──────────────────────────────────────────────────────

  destroy() {
    for (const w of this._watchers) {
      try { w.close(); } catch { /* ignore */ }
    }
    this._watchers = [];
    if (this._agent) {
      this._agent.destroy();
      this._agent = null;
    }
  }
}

// ── Federation CA ────────────────────────────────────────────────────
// Lightweight internal CA for signing relay client certificates
// when SPIRE is not available (bootstrap flow).

class FederationCA {
  /**
   * @param {Object} opts
   * @param {string} opts.caKeyPath  - Path to CA private key (PEM)
   * @param {string} opts.caCertPath - Path to CA certificate (PEM)
   * @param {Function} [opts.log]
   */
  constructor(opts = {}) {
    this.caKeyPath = opts.caKeyPath || null;
    this.caCertPath = opts.caCertPath || null;
    this.log = opts.log || console.log;

    this._caKey = null;
    this._caCert = null;

    if (this.caKeyPath && this.caCertPath) {
      this._loadCA();
    }
  }

  _loadCA() {
    try {
      this._caKey = fs.readFileSync(this.caKeyPath, 'utf8');
      this._caCert = fs.readFileSync(this.caCertPath, 'utf8');
    } catch (e) {
      this.log('warn', `Federation CA not loaded: ${e.message}`);
    }
  }

  get isLoaded() { return !!this._caKey && !!this._caCert; }
  get caCertPem() { return this._caCert; }

  /**
   * Generate a self-signed CA keypair for federation.
   * Only used for initial setup (generate-federation-ca.sh calls this).
   */
  static generateCA(opts = {}) {
    const { generateKeyPairSync, createSign, X509Certificate } = crypto;
    const commonName = opts.commonName || 'WID Federation CA';
    const validDays = opts.validDays || 365;

    const { publicKey, privateKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    return { publicKey, privateKey, commonName };
  }
}

module.exports = { TLSManager, FederationCA };
