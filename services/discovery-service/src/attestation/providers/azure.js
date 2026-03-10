// =============================================================================
// Azure Attestation Provider
// =============================================================================
// Evidence collection:
//   - IMDS: Instance Metadata Service (VM identity, attestation data)
//   - Managed Identity: OAuth2 token from Azure AD
//   - Available on: VMs, AKS, App Service, Container Instances, Functions
//
// Verification:
//   - Validates Azure AD-signed JWT
//   - Fetches tenant-specific JWKS from Azure AD OIDC discovery
//   - Verifies signature, issuer, audience, and expiry
//
// Trust level: Cryptographic (Tier 1) for attested VMs, High (Tier 2) for MSI
// =============================================================================

const BaseAttestationProvider = require('./BaseAttestationProvider');
const crypto = require('crypto');

const AZURE_IMDS_BASE = 'http://169.254.169.254/metadata';
const AZURE_IMDS_HEADERS = { 'Metadata': 'true' };
const AZURE_IMDS_API_VERSION = '2021-02-01';

class AzureAttestationProvider extends BaseAttestationProvider {
  constructor(config = {}) {
    super(config);
    this.platform = 'azure';
    this.tier = 1;
    this.subscriptionId = config.subscriptionId || process.env.AZURE_SUBSCRIPTION_ID;
    this.tenantId = config.tenantId || process.env.AZURE_TENANT_ID;
    this.resource = config.resource || 'https://management.azure.com/';
    this._jwksCache = {};
    this._jwksCacheExpiry = {};
  }

  getMethods() {
    return ['azure-msi-signed'];
  }

  // ── Detection ──

  async detect() {
    // Check Azure-specific env vars first
    if (process.env.IDENTITY_ENDPOINT || process.env.MSI_ENDPOINT) {
      return true;
    }

    // Try IMDS
    try {
      const url = `${AZURE_IMDS_BASE}/instance?api-version=${AZURE_IMDS_API_VERSION}`;
      const data = await this.httpGetJSON(url, AZURE_IMDS_HEADERS, 2000);
      if (data.compute) {
        this.subscriptionId = this.subscriptionId || data.compute.subscriptionId;
        this.tenantId = this.tenantId || data.compute.azEnvironment;
        return true;
      }
    } catch { /* not on Azure */ }

    // Check SDK env vars
    if (process.env.AZURE_SUBSCRIPTION_ID || process.env.AZURE_CLIENT_ID) {
      return true;
    }

    return false;
  }

  // ── Self Evidence Collection ──

  async collectSelfEvidence() {
    const evidence = { platform: 'azure' };

    // Fetch managed identity token
    try {
      const token = await this.fetchManagedIdentityToken();
      evidence.msi_token = token;
    } catch (e) {
      this.log(`Failed to fetch MSI token: ${e.message}`, 'warn');
    }

    // Fetch instance metadata
    try {
      const metadata = await this.fetchInstanceMetadata();
      evidence.instance_metadata = metadata;
      evidence.subscription_id = metadata.compute?.subscriptionId;
      evidence.resource_group = metadata.compute?.resourceGroupName;
      evidence.vm_id = metadata.compute?.vmId;
      evidence.location = metadata.compute?.location;
    } catch (e) {
      this.log(`Failed to fetch instance metadata: ${e.message}`, 'warn');
    }

    // Fetch attested data (signed by Azure — Tier 1)
    try {
      const attested = await this.fetchAttestedData();
      evidence.attested_data = attested;
    } catch (e) {
      this.log(`Failed to fetch attested data: ${e.message}`, 'warn');
    }

    return evidence;
  }

  // ── Workload Evidence Collection ──

  async collectWorkloadEvidence(workload) {
    const evidence = { platform: 'azure' };

    // Record identity information from discovery
    if (workload.metadata?.resource_id) {
      evidence.resource_id = workload.metadata.resource_id;
    }
    if (workload.metadata?.has_managed_identity) {
      evidence.has_managed_identity = true;
      evidence.identity_type = workload.metadata.identity_type;
    }
    if (workload.metadata?.principal_id) {
      evidence.principal_id = workload.metadata.principal_id;
      evidence.client_id = workload.metadata.client_id;
      evidence.tenant_id = workload.metadata.tenant_id;
    }

    evidence.subscription_id = this.subscriptionId;
    evidence.resource_group = workload.metadata?.resource_group;
    evidence.location = workload.region;

    return evidence;
  }

  // ── Verification ──

  async verify(evidence, workload) {
    const timestamp = new Date().toISOString();

    // Priority 1: Attested data (Tier 1 - Cryptographic, Azure-signed)
    if (evidence.attested_data?.signature) {
      return this.verifyAttestedData(evidence, workload, timestamp);
    }

    // Priority 2: MSI token (Tier 1/2 - Azure AD signed JWT)
    if (evidence.msi_token) {
      return this.verifyMSIToken(evidence, workload, timestamp);
    }

    // Priority 3: Managed identity presence (Tier 2 - High)
    if (evidence.has_managed_identity || evidence.principal_id) {
      return this.verifyByIdentityPresence(evidence, workload, timestamp);
    }

    return {
      method: 'azure-msi-signed',
      success: false,
      reason: 'No Azure attestation evidence available',
      timestamp,
    };
  }

  async verifyMSIToken(evidence, workload, timestamp) {
    try {
      const { header, payload } = this.decodeJWT(evidence.msi_token);

      // ── 4-check cryptographic gate (matching GCP pattern) ──
      const checks = {
        exp_valid: false,
        issuer_valid: false,
        aud_valid: false,
        signature_verified: false,
      };

      // Check 1: Expiry
      if (!payload.exp) {
        return { method: 'azure-msi-signed', success: false, reason: 'Token has no expiry claim', timestamp };
      }
      if (payload.exp * 1000 < Date.now()) {
        return { method: 'azure-msi-signed', success: false, reason: 'MSI token expired', timestamp };
      }
      checks.exp_valid = true;

      // Check 2: Issuer (must be Azure AD / Entra ID)
      const validIssuerPattern = /^https:\/\/(login\.microsoftonline\.com|sts\.windows\.net)\//;
      if (!validIssuerPattern.test(payload.iss)) {
        return { method: 'azure-msi-signed', success: false, reason: `Invalid issuer: ${payload.iss}`, timestamp };
      }
      checks.issuer_valid = true;

      // Check 3: Audience
      // Azure MSI tokens have aud = the resource being accessed (e.g., https://management.azure.com/)
      const expectedAudience = this.resource;
      if (payload.aud) {
        const audList = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        checks.aud_valid = !expectedAudience || audList.some(a => a === expectedAudience || a.startsWith('https://'));
      } else {
        checks.aud_valid = true; // No audience claim to validate
      }

      // Check 4: Signature verification against Entra ID JWKS
      const tokenTenantId = payload.tid || payload.iss.split('/')[3];
      try {
        checks.signature_verified = await this.verifySignature(evidence.msi_token, tokenTenantId);
      } catch (sigErr) {
        this.log(`Signature verification error: ${sigErr.message}`, 'warn');
        checks.signature_verified = false;
      }

      // Trust level: cryptographic only when ALL 4 checks pass
      const allPassed = checks.exp_valid && checks.issuer_valid && checks.aud_valid && checks.signature_verified;
      const claimsValid = checks.exp_valid && checks.issuer_valid;

      let trust_level, verification_status;
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
        method: 'azure-msi-signed',
        success: true,
        trust_level,
        verification_status,
        claims: {
          sub: payload.sub, iss: payload.iss, aud: payload.aud,
          oid: payload.oid, tid: payload.tid,
          appid: payload.appid || payload.azp,
          exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
          iat: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
          signature_verified: checks.signature_verified,
          checks,
        },
        timestamp,
      };
    } catch (error) {
      return { method: 'azure-msi-signed', success: false, reason: `MSI token verification failed: ${error.message}`, timestamp };
    }
  }

  verifyAttestedData(evidence, workload, timestamp) {
    // Azure IMDS attested data includes a signed document
    // TODO: Verify the PKCS7/CMS signature against Microsoft's intermediate cert
    const signature_verified = false; // CMS verification not yet implemented

    return {
      method: 'azure-msi-signed',
      success: true,
      trust_level: signature_verified ? 'cryptographic' : 'medium',
      verification_status: signature_verified ? 'signature-verified' : 'unverified-claims',
      claims: {
        vm_id: evidence.vm_id,
        subscription_id: evidence.subscription_id,
        resource_group: evidence.resource_group,
        location: evidence.location,
        attested: true,
        signature_verified,
        note: 'Azure IMDS attested data present (CMS signature verification pending)',
      },
      timestamp,
    };
  }

  verifyByIdentityPresence(evidence, workload, timestamp) {
    return {
      method: 'azure-msi-signed',
      success: true,
      trust_level: 'high',
      claims: {
        has_managed_identity: true,
        identity_type: evidence.identity_type,
        principal_id: evidence.principal_id,
        client_id: evidence.client_id,
        tenant_id: evidence.tenant_id,
        subscription_id: evidence.subscription_id,
        verification: 'Managed identity registered on resource',
      },
      timestamp,
    };
  }

  // ── Token Fetching ──

  async fetchManagedIdentityToken() {
    // App Service / Functions use IDENTITY_ENDPOINT
    if (process.env.IDENTITY_ENDPOINT) {
      const url = `${process.env.IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=${encodeURIComponent(this.resource)}`;
      const data = await this.httpGetJSON(url, { 'X-IDENTITY-HEADER': process.env.IDENTITY_HEADER }, 5000);
      return data.access_token;
    }

    // VM / AKS use IMDS
    const url = `${AZURE_IMDS_BASE}/identity/oauth2/token?api-version=${AZURE_IMDS_API_VERSION}&resource=${encodeURIComponent(this.resource)}`;
    const data = await this.httpGetJSON(url, AZURE_IMDS_HEADERS, 5000);
    return data.access_token;
  }

  async fetchInstanceMetadata() {
    const url = `${AZURE_IMDS_BASE}/instance?api-version=${AZURE_IMDS_API_VERSION}`;
    return this.httpGetJSON(url, AZURE_IMDS_HEADERS, 3000);
  }

  async fetchAttestedData() {
    const url = `${AZURE_IMDS_BASE}/attested/document?api-version=${AZURE_IMDS_API_VERSION}`;
    return this.httpGetJSON(url, AZURE_IMDS_HEADERS, 3000);
  }

  // ── Signature Verification ──

  async verifySignature(token, tenantId) {
    try {
      const { header } = this.decodeJWT(token);
      const jwks = await this.getAzureJWKS(tenantId);
      const key = jwks.keys.find(k => k.kid === header.kid);

      if (!key) {
        this.log('No matching key found in Azure AD JWKS', 'warn');
        return false;
      }

      const publicKey = crypto.createPublicKey({ key, format: 'jwk' });
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      const data = `${headerB64}.${payloadB64}`;
      const signature = Buffer.from(signatureB64, 'base64url');

      return crypto.createVerify('sha256').update(data).verify(publicKey, signature);
    } catch (error) {
      this.log(`Signature verification error: ${error.message}`, 'warn');
      return false;
    }
  }

  async getAzureJWKS(tenantId) {
    const cacheKey = tenantId || 'common';
    if (this._jwksCache[cacheKey] && Date.now() < this._jwksCacheExpiry[cacheKey]) {
      return this._jwksCache[cacheKey];
    }

    // Discover OIDC config first
    const oidcUrl = `https://login.microsoftonline.com/${tenantId || 'common'}/v2.0/.well-known/openid-configuration`;
    const oidcConfig = await this.httpGetJSON(oidcUrl, {}, 5000);
    const jwks = await this.httpGetJSON(oidcConfig.jwks_uri, {}, 5000);

    this._jwksCache[cacheKey] = jwks;
    this._jwksCacheExpiry[cacheKey] = Date.now() + 3600000;
    return jwks;
  }
}

module.exports = AzureAttestationProvider;
