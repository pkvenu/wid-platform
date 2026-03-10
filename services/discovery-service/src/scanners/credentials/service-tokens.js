// =============================================================================
// Service Token Scanner - Discovers OAuth Clients, JWTs & mTLS Certificates
// =============================================================================
// Scans for:
// 1. OAuth2 client credentials registered in the platform's token service
// 2. JWT issuers and their public keys
// 3. mTLS certificates used for workload-to-workload auth
// 4. SPIFFE SVIDs (if SPIRE is available)

const BaseScanner = require('../base/BaseScanner');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

class ServiceTokenScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'internal';
    this.version = '1.0.0';
    this.tokenServiceUrl = config.tokenServiceUrl || process.env.TOKEN_SERVICE_URL || 'http://token-service:3000';
    this.certsDir = config.certsDir || process.env.CERTS_DIR || '/etc/workload-certs';
    this.spireSocketPath = config.spireSocketPath || process.env.SPIRE_AGENT_SOCKET || '/tmp/spire-agent/public/api.sock';
  }

  getRequiredCredentials() {
    return [
      { name: 'TOKEN_SERVICE_URL', description: 'WID token service URL (default: http://token-service:3000)' },
      { name: 'CERTS_DIR', description: 'mTLS certificates directory (default: /etc/workload-certs)' },
      { name: 'SPIRE_AGENT_SOCKET', description: 'SPIRE agent socket path (optional)' },
    ];
  }

  async validate() {
    // At least one source should be available
    let sources = 0;
    
    // Check token service
    try {
      await this.httpGet(`${this.tokenServiceUrl}/health`);
      this.log('Token service reachable', 'success');
      this.tokenServiceAvailable = true;
      sources++;
    } catch {
      this.tokenServiceAvailable = false;
    }

    // Check certs directory
    if (fs.existsSync(this.certsDir)) {
      this.log(`Certs directory found: ${this.certsDir}`, 'success');
      this.certsAvailable = true;
      sources++;
    } else {
      this.certsAvailable = false;
    }

    // Check SPIRE agent
    if (fs.existsSync(this.spireSocketPath)) {
      this.log('SPIRE agent socket found', 'success');
      this.spireAvailable = true;
      sources++;
    } else {
      this.spireAvailable = false;
    }

    if (sources === 0) {
      this.log('No token/cert sources available', 'warn');
      this.enabled = false;
      this.disabledReason = 'Requires token service, certificate directory, or SPIRE agent';
      return false;
    }

    return true;
  }

  getCapabilities() {
    return ['discover', 'oauth-clients', 'jwt-issuers', 'mtls-certs', 'spiffe-svids'];
  }

  async discover() {
    this.log('Starting service token & certificate discovery', 'info');
    const workloads = [];

    // Discover OAuth clients from token service
    if (this.tokenServiceAvailable) {
      const oauthClients = await this.discoverOAuthClients();
      workloads.push(...oauthClients);
      this.log(`Found ${oauthClients.length} OAuth clients`, 'success');
    }

    // Discover mTLS certificates
    if (this.certsAvailable) {
      const certs = await this.discoverCertificates();
      workloads.push(...certs);
      this.log(`Found ${certs.length} certificates`, 'success');
    }

    // Discover well-known OIDC/JWT endpoints on the local network
    const jwtIssuers = await this.discoverJWTIssuers();
    workloads.push(...jwtIssuers);
    this.log(`Found ${jwtIssuers.length} JWT issuers`, 'success');

    return workloads;
  }

  async discoverOAuthClients() {
    try {
      // Try to list registered OAuth clients from the token service
      const response = await this.httpGet(`${this.tokenServiceUrl}/api/v1/clients`);
      const clients = response.clients || [];
      const workloads = [];

      for (const client of clients) {
        const createdAt = client.created_at ? new Date(client.created_at) : null;
        const ageDays = createdAt ? Math.floor((Date.now() - createdAt.getTime()) / 86400000) : null;
        const lastUsed = client.last_used ? new Date(client.last_used) : null;
        const daysSinceUse = lastUsed ? Math.floor((Date.now() - lastUsed.getTime()) / 86400000) : null;

        const workload = {
          name: client.client_id || client.name,
          type: 'oauth-client',
          namespace: 'token-service',
          environment: client.environment || 'unknown',

          category: 'service-token',
          subcategory: client.grant_type || 'client_credentials',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            client_id: client.client_id,
            grant_type: client.grant_type || 'client_credentials',
            scope: Array.isArray(client.scopes) ? client.scopes.join(', ') : (client.scope || ''),
            active: String(client.active !== false)
          },
          metadata: {
            client_id: client.client_id,
            grant_type: client.grant_type || 'client_credentials',
            scopes: client.scopes || [],
            redirect_uris: client.redirect_uris || [],
            created_at: client.created_at,
            last_used: client.last_used || null,
            age_days: ageDays,
            days_since_use: daysSinceUse,
            active: client.active !== false,
            token_endpoint_auth_method: client.token_endpoint_auth_method || 'client_secret_basic'
          },

          cloud_provider: 'internal',
          region: 'local',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'internal://token-service',
          cluster_id: 'local',

          owner: client.owner || null,
          team: client.team || null,
          is_shadow: !client.owner && daysSinceUse > 90,
          shadow_score: this.calculateOAuthShadowScore(client, daysSinceUse),

          discovered_by: 'service-token-scanner'
        };

        workload.security_score = this.calculateOAuthSecurityScore(workload, daysSinceUse, ageDays);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering OAuth clients: ${error.message}`, 'warn');
      return [];
    }
  }

  async discoverCertificates() {
    try {
      const workloads = [];
      const certFiles = this.findCertFiles(this.certsDir);

      for (const certPath of certFiles) {
        try {
          const certPem = fs.readFileSync(certPath, 'utf8');
          const certInfo = this.parseCertificate(certPem);
          if (!certInfo) continue;

          const daysUntilExpiry = certInfo.validTo
            ? Math.floor((new Date(certInfo.validTo).getTime() - Date.now()) / 86400000)
            : null;

          const isExpired = daysUntilExpiry !== null && daysUntilExpiry < 0;
          const isExpiringSoon = daysUntilExpiry !== null && daysUntilExpiry < 30;

          // Check if it's a SPIFFE SVID
          const spiffeId = certInfo.subjectAltNames?.find(san => san.startsWith('spiffe://'));

          const workload = {
            name: certInfo.commonName || path.basename(certPath, path.extname(certPath)),
            type: spiffeId ? 'spiffe-svid' : 'mtls-certificate',
            namespace: 'certificates',
            environment: 'unknown',

            spiffe_id: spiffeId || null,
            category: 'certificate',
            subcategory: spiffeId ? 'spiffe-x509' : (certInfo.isCA ? 'ca-certificate' : 'workload-certificate'),
            is_ai_agent: false,
            is_mcp_server: false,

            labels: {
              common_name: certInfo.commonName || '',
              issuer: certInfo.issuer || '',
              serial: certInfo.serial || '',
              is_ca: String(certInfo.isCA || false),
              is_expired: String(isExpired),
              key_algorithm: certInfo.keyAlgorithm || 'unknown'
            },
            metadata: {
              file_path: certPath,
              subject: certInfo.subject,
              issuer: certInfo.issuer,
              common_name: certInfo.commonName,
              serial: certInfo.serial,
              valid_from: certInfo.validFrom,
              valid_to: certInfo.validTo,
              days_until_expiry: daysUntilExpiry,
              is_expired: isExpired,
              is_expiring_soon: isExpiringSoon,
              is_ca: certInfo.isCA || false,
              subject_alt_names: certInfo.subjectAltNames || [],
              key_algorithm: certInfo.keyAlgorithm,
              signature_algorithm: certInfo.signatureAlgorithm,
              fingerprint: certInfo.fingerprint
            },

            cloud_provider: 'internal',
            region: 'local',
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: spiffeId ? 'spiffe://certificate-authority' : 'internal://certificate-authority',
            cluster_id: 'local',

            owner: null,
            team: null,
            is_shadow: isExpired,
            shadow_score: isExpired ? 90 : (isExpiringSoon ? 60 : 20),

            discovered_by: 'service-token-scanner'
          };

          workload.security_score = this.calculateCertSecurityScore(workload, isExpired, isExpiringSoon, daysUntilExpiry);
          workloads.push(workload);
        } catch (e) {
          this.log(`Error parsing cert ${certPath}: ${e.message}`, 'warn');
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering certificates: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverJWTIssuers() {
    // Probe common local OIDC/JWT discovery endpoints
    const endpoints = [
      { url: `${this.tokenServiceUrl}/.well-known/openid-configuration`, name: 'token-service' },
      { url: 'http://localhost:8080/.well-known/openid-configuration', name: 'local-idp' },
      { url: 'http://keycloak:8080/realms/master/.well-known/openid-configuration', name: 'keycloak' },
    ];

    const workloads = [];

    for (const ep of endpoints) {
      try {
        const config = await this.httpGet(ep.url);
        if (config.issuer) {
          const workload = {
            name: `jwt-issuer-${ep.name}`,
            type: 'jwt-issuer',
            namespace: 'auth',
            environment: 'unknown',

            category: 'auth-service',
            subcategory: 'oidc-provider',
            is_ai_agent: false,
            is_mcp_server: false,

            labels: {
              issuer: 'oidc://local-idp',
              token_endpoint: config.token_endpoint || '',
              jwks_uri: config.jwks_uri || '',
              supported_grants: (config.grant_types_supported || []).join(', ')
            },
            metadata: {
              issuer: 'oidc://local-idp',
              authorization_endpoint: config.authorization_endpoint,
              token_endpoint: config.token_endpoint,
              jwks_uri: config.jwks_uri,
              scopes_supported: config.scopes_supported,
              grant_types_supported: config.grant_types_supported,
              response_types_supported: config.response_types_supported
            },

            cloud_provider: 'internal',
            region: 'local',
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: 'oidc://local-idp',
            cluster_id: 'local',

            owner: null,
            team: null,
            is_shadow: false,
            shadow_score: 10,

            discovered_by: 'service-token-scanner'
          };

          workload.security_score = 70; // Known OIDC providers get decent baseline
          workloads.push(workload);
        }
      } catch {
        // Endpoint not available — that's fine
      }
    }

    return workloads;
  }

  // ── Helpers ──

  findCertFiles(dir, maxDepth = 3, depth = 0) {
    if (depth >= maxDepth) return [];
    const files = [];
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          files.push(...this.findCertFiles(fullPath, maxDepth, depth + 1));
        } else if (/\.(pem|crt|cert|cer)$/i.test(entry.name)) {
          files.push(fullPath);
        }
      }
    } catch (e) { /* permission denied */ }
    return files;
  }

  parseCertificate(pem) {
    try {
      const cert = new crypto.X509Certificate(pem);
      return {
        subject: cert.subject,
        issuer: cert.issuer,
        commonName: cert.subject.match(/CN=([^,\n]+)/)?.[1] || null,
        serial: cert.serialNumber,
        validFrom: cert.validFrom,
        validTo: cert.validTo,
        isCA: cert.ca,
        subjectAltNames: cert.subjectAltName?.split(', ').map(s => s.replace(/^(URI|DNS|IP Address):/, '')) || [],
        keyAlgorithm: cert.publicKey?.asymmetricKeyType || 'unknown',
        signatureAlgorithm: cert.sigAlgName || 'unknown',
        fingerprint: cert.fingerprint256
      };
    } catch {
      return null;
    }
  }

  calculateOAuthShadowScore(client, daysSinceUse) {
    let score = 0;
    if (!client.owner) score += 30;
    if (daysSinceUse > 180) score += 30;
    else if (daysSinceUse > 90) score += 15;
    if (!client.scopes || client.scopes.length === 0) score += 15;
    return Math.min(100, score);
  }

  calculateOAuthSecurityScore(workload, daysSinceUse, ageDays) {
    let score = 50;
    if (workload.owner) score += 15;
    if (daysSinceUse !== null && daysSinceUse < 30) score += 15;
    if (daysSinceUse !== null && daysSinceUse > 180) score -= 20;
    if (ageDays !== null && ageDays > 365) score -= 10;
    return Math.max(0, Math.min(100, score));
  }

  calculateCertSecurityScore(workload, isExpired, isExpiringSoon, daysUntilExpiry) {
    let score = 60;
    if (isExpired) score -= 40;
    else if (isExpiringSoon) score -= 20;
    if (daysUntilExpiry > 90) score += 20;
    if (workload.metadata.is_ca) score += 10; // CA certs are infrastructure
    return Math.max(0, Math.min(100, score));
  }

  httpGet(url) {
    return new Promise((resolve, reject) => {
      const mod = url.startsWith('https') ? https : http;
      const req = mod.get(url, { timeout: 5000, rejectUnauthorized: false }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            reject(new Error('Invalid JSON'));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
  }
}

module.exports = ServiceTokenScanner;