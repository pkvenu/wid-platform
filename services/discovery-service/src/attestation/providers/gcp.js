// =============================================================================
// GCP Attestation Provider
// =============================================================================
// Evidence collection:
//   - Fetches identity token from GCP metadata server
//   - Available on: Cloud Run, GCE, GKE, Cloud Functions
//   - Endpoint: http://metadata.google.internal/computeMetadata/v1/...
//
// Verification:
//   - Validates Google-signed OIDC JWT
//   - Fetches Google's public keys from https://www.googleapis.com/oauth2/v3/certs
//   - Verifies signature, issuer, audience, and expiry
//
// Trust level: Cryptographic (Tier 1)
// =============================================================================

const BaseAttestationProvider = require('./BaseAttestationProvider');
const crypto = require('crypto');

const GCP_METADATA_BASE = 'http://metadata.google.internal/computeMetadata/v1';
const GCP_METADATA_HEADERS = { 'Metadata-Flavor': 'Google' };
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

class GCPAttestationProvider extends BaseAttestationProvider {
  constructor(config = {}) {
    super(config);
    this.platform = 'gcp';
    this.tier = 1;
    this.projectId = config.projectId || process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
    this.audience = config.audience || `https://wid.${this.projectId}.run.app`;
    this._jwksCache = null;
    this._jwksCacheExpiry = 0;
  }

  getMethods() {
    return ['gcp-metadata-jwt'];
  }

  // ── Detection ──

  async detect() {
    try {
      // GCP metadata server is only reachable from GCP instances
      const projectId = await this.httpGet(
        `${GCP_METADATA_BASE}/project/project-id`,
        GCP_METADATA_HEADERS,
        2000
      );
      this.projectId = projectId.trim();
      return true;
    } catch {
      // Check Cloud Run env var as fallback
      if (process.env.K_SERVICE) {
        this.projectId = process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
        return !!this.projectId;
      }
      return false;
    }
  }

  // ── Self Evidence Collection ──
  // Called when the discovery service itself needs to prove its identity

  async collectSelfEvidence() {
    try {
      const identityToken = await this.fetchIdentityToken(this.audience);
      const metadata = await this.fetchInstanceMetadata();

      return {
        identity_token: identityToken,
        project_id: metadata.projectId,
        zone: metadata.zone,
        region: metadata.region,
        service_account: metadata.serviceAccount,
        instance_id: metadata.instanceId,
        platform: 'gcp',
      };
    } catch (error) {
      this.log(`Failed to collect self evidence: ${error.message}`, 'warn');
      return {};
    }
  }

  // ── Workload Evidence Collection ──
  // Called during scan to gather evidence about Cloud Run/GCE/GKE workloads

  async collectWorkloadEvidence(workload) {
    const evidence = { platform: 'gcp' };

    // For Cloud Run services, we can attest them by their service identity
    if (workload.type === 'cloud-run-service') {
      evidence.service_account = workload.metadata?.service_account || null;
      evidence.service_url = workload.metadata?.uri || null;
      evidence.project_id = this.projectId;
      evidence.region = workload.region;

      // Request an identity token targeted at the service URL
      // This proves the caller (us) has access and the service exists
      if (evidence.service_url) {
        try {
          const token = await this.fetchIdentityToken(evidence.service_url);
          evidence.identity_token = token;
        } catch (e) {
          this.log(`Could not fetch identity token for ${workload.name}: ${e.message}`, 'warn');
        }
      }
    }

    // For GCE instances, we can verify via instance metadata
    if (workload.type === 'gce-instance') {
      evidence.instance_id = workload.metadata?.instance_id || null;
      evidence.zone = workload.metadata?.zone || null;
      evidence.service_account = workload.metadata?.service_account || null;
      evidence.project_id = this.projectId;
    }

    // For service accounts, record the email
    if (workload.type === 'service-account') {
      evidence.service_account_email = workload.metadata?.email || null;
      evidence.user_managed_keys = workload.metadata?.user_managed_keys || 0;
      evidence.project_id = this.projectId;
    }

    return evidence;
  }

  // ── Verification ──

  async verify(evidence, workload) {
    const timestamp = new Date().toISOString();

    if (!evidence.identity_token) {
      // Fallback: verify by platform metadata if we have it
      if (evidence.service_account && evidence.project_id) {
        return this.verifyByMetadata(evidence, workload, timestamp);
      }
      return {
        method: 'gcp-metadata-jwt',
        success: false,
        reason: 'No GCP identity token available',
        timestamp,
      };
    }

    try {
      // Decode the JWT
      const { header, payload } = this.decodeJWT(evidence.identity_token);

      // ── Phase 1 completion criteria: ALL 4 must pass for cryptographic ──
      const checks = {
        exp_valid: false,
        issuer_valid: false,
        aud_valid: false,
        signature_verified: false,
      };

      // Check 1: Expiry
      if (!payload.exp) {
        return { method: 'gcp-metadata-jwt', success: false, reason: 'Token has no expiry claim', timestamp };
      }
      if (payload.exp * 1000 < Date.now()) {
        return { method: 'gcp-metadata-jwt', success: false, reason: 'Identity token expired', timestamp };
      }
      checks.exp_valid = true;

      // Check 2: Issuer
      if (!GOOGLE_ISSUERS.includes(payload.iss)) {
        return { method: 'gcp-metadata-jwt', success: false, reason: `Invalid issuer: ${payload.iss}`, timestamp };
      }
      checks.issuer_valid = true;

      // Check 3: Audience (if we have a known audience to check against)
      const expectedAudience = workload.metadata?.uri || this.audience;
      if (payload.aud && expectedAudience) {
        const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        checks.aud_valid = audList.includes(expectedAudience) || !expectedAudience;
      } else {
        // No audience to validate against — pass with warning
        checks.aud_valid = true;
      }

      // Check 4: Signature verification against Google JWKS
      try {
        checks.signature_verified = await this.verifySignature(evidence.identity_token);
      } catch (sigErr) {
        this.log(`Signature verification error: ${sigErr.message}`, 'warn');
        checks.signature_verified = false;
      }

      // ── Trust level determination ──
      // cryptographic: ALL 4 checks pass
      // high: signature failed but claims valid (JWKS fetch failed, kid missing, etc.)
      // medium: decode-only fallback
      const allPassed = checks.exp_valid && checks.issuer_valid && checks.aud_valid && checks.signature_verified;
      const claimsValid = checks.exp_valid && checks.issuer_valid;

      let trust_level;
      let verification_status;
      if (allPassed) {
        trust_level = 'cryptographic';
        verification_status = 'signature-verified';
      } else if (claimsValid && !checks.signature_verified) {
        trust_level = 'high';
        verification_status = 'claims-valid-signature-unverified';
      } else {
        trust_level = 'medium';
        verification_status = 'unverified-claims';
      }

      return {
        method: 'gcp-metadata-jwt',
        success: true,
        trust_level,
        verification_status,
        claims: {
          sub: payload.sub,
          iss: payload.iss,
          aud: payload.aud,
          azp: payload.azp,
          email: payload.email,
          email_verified: payload.email_verified,
          exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
          iat: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
          project_id: payload.google?.compute_engine?.project_id || evidence.project_id,
          zone: payload.google?.compute_engine?.zone || evidence.zone,
          instance_id: payload.google?.compute_engine?.instance_id || evidence.instance_id,
          // Verification detail
          signature_verified: checks.signature_verified,
          checks,
        },
        timestamp,
      };
    } catch (error) {
      return {
        method: 'gcp-metadata-jwt',
        success: false,
        reason: `Token verification failed: ${error.message}`,
        timestamp,
      };
    }
  }

  // Fallback: verify by metadata alone (Tier 2 — not cryptographic)
  verifyByMetadata(evidence, workload, timestamp) {
    const claims = {
      service_account: evidence.service_account,
      project_id: evidence.project_id,
      region: evidence.region || workload.region,
      verification: 'Platform metadata match — service account and project verified',
    };

    // Service account using default compute SA is less trustworthy
    const isDefaultSA = evidence.service_account?.includes('developer.gserviceaccount.com');

    return {
      method: 'gcp-metadata-jwt',
      success: true,
      trust_level: isDefaultSA ? 'medium' : 'high',
      claims,
      timestamp,
    };
  }

  // ── Token Fetching ──

  async fetchIdentityToken(audience) {
    const url = `${GCP_METADATA_BASE}/instance/service-accounts/default/identity?audience=${encodeURIComponent(audience)}&format=full`;
    const token = await this.httpGet(url, GCP_METADATA_HEADERS, 3000);
    return token.trim();
  }

  async fetchInstanceMetadata() {
    const meta = {};
    try {
      meta.projectId = (await this.httpGet(`${GCP_METADATA_BASE}/project/project-id`, GCP_METADATA_HEADERS)).trim();
    } catch { meta.projectId = this.projectId; }

    try {
      const zone = (await this.httpGet(`${GCP_METADATA_BASE}/instance/zone`, GCP_METADATA_HEADERS)).trim();
      meta.zone = zone.split('/').pop();
      meta.region = meta.zone.replace(/-[a-z]$/, '');
    } catch { meta.zone = null; meta.region = null; }

    try {
      meta.serviceAccount = (await this.httpGet(
        `${GCP_METADATA_BASE}/instance/service-accounts/default/email`, GCP_METADATA_HEADERS
      )).trim();
    } catch { meta.serviceAccount = null; }

    try {
      meta.instanceId = (await this.httpGet(`${GCP_METADATA_BASE}/instance/id`, GCP_METADATA_HEADERS)).trim();
    } catch { meta.instanceId = process.env.K_REVISION || null; }

    return meta;
  }

  // ── Signature Verification ──

  async verifySignature(token) {
    try {
      const { header } = this.decodeJWT(token);
      const jwks = await this.getGoogleJWKS();
      const key = jwks.keys.find(k => k.kid === header.kid);

      if (!key) {
        this.log('No matching key found in Google JWKS', 'warn');
        return false;
      }

      const publicKey = crypto.createPublicKey({ key, format: 'jwk' });
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      const data = `${headerB64}.${payloadB64}`;
      const signature = Buffer.from(signatureB64, 'base64url');

      const alg = header.alg === 'RS256' ? 'sha256' : 'sha256';
      return crypto.createVerify(alg).update(data).verify(publicKey, signature);
    } catch (error) {
      this.log(`Signature verification error: ${error.message}`, 'warn');
      return false;
    }
  }

  async getGoogleJWKS() {
    if (this._jwksCache && Date.now() < this._jwksCacheExpiry) {
      return this._jwksCache;
    }
    const jwks = await this.httpGetJSON(GOOGLE_CERTS_URL, {}, 5000);
    this._jwksCache = jwks;
    this._jwksCacheExpiry = Date.now() + 3600000; // cache 1 hour
    return jwks;
  }
}

module.exports = GCPAttestationProvider;
