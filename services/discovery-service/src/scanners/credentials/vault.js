// =============================================================================
// Vault Scanner - Discovers Secrets, Tokens & Credentials from HashiCorp Vault
// =============================================================================

const BaseScanner = require('../base/BaseScanner');
const https = require('https');
const http = require('http');

class VaultScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'vault';
    this.version = '1.0.0';
    this.vaultAddr = config.vaultAddr || process.env.VAULT_ADDR || 'http://vault:8200';
    this.vaultToken = config.vaultToken || process.env.VAULT_TOKEN;

    if (!this.vaultToken) {
      this.enabled = false;
      this.disabledReason = 'Requires VAULT_ADDR + VAULT_TOKEN';
    }
  }

  getRequiredCredentials() {
    return [
      { name: 'VAULT_ADDR', description: 'Vault server URL (default: http://vault:8200)' },
      { name: 'VAULT_TOKEN', description: 'Vault access token' },
    ];
  }

  async validate() {
    if (!this.vaultToken) {
      this.log('VAULT_TOKEN not set', 'warn');
      return false;
    }
    try {
      const status = await this.vaultRequest('GET', '/v1/sys/health');
      this.log(`Vault connected: ${status.cluster_name || 'local'} (version ${status.version})`, 'success');
      return !status.sealed;
    } catch (error) {
      this.log(`Vault validation failed: ${error.message}`, 'warn');
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'secrets', 'tokens', 'auth-methods', 'leases'];
  }

  async discover() {
    this.log('Starting Vault secrets discovery', 'info');
    const workloads = [];

    // Discover secret engines
    const engines = await this.discoverSecretEngines();
    workloads.push(...engines);
    this.log(`Found ${engines.length} secret engines`, 'success');

    // Discover auth methods (each is an NHI entry point)
    const authMethods = await this.discoverAuthMethods();
    workloads.push(...authMethods);
    this.log(`Found ${authMethods.length} auth methods`, 'success');

    // Discover secrets in KV engines
    const secrets = await this.discoverKVSecrets();
    workloads.push(...secrets);
    this.log(`Found ${secrets.length} KV secrets`, 'success');

    return workloads;
  }

  async discoverSecretEngines() {
    try {
      const mounts = await this.vaultRequest('GET', '/v1/sys/mounts');
      const workloads = [];

      for (const [path, engine] of Object.entries(mounts.data || mounts)) {
        // Skip system and internal mounts
        if (path.startsWith('sys/') || path === 'cubbyhole/' || path === 'identity/') continue;
        // Skip non-object entries (request_id, lease_id, etc from top-level response)
        if (typeof engine !== 'object' || engine === null || !engine.type) continue;

        const workload = {
          name: `vault-engine-${path.replace(/\//g, '-').replace(/-$/, '')}`,
          type: 'secret-engine',
          namespace: 'vault',
          environment: 'unknown',

          category: 'secrets-manager',
          subcategory: engine.type || 'generic',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            engine_type: engine.type,
            vault_path: path,
            local: String(engine.local || false),
            seal_wrap: String(engine.seal_wrap || false)
          },
          metadata: {
            path: path,
            type: engine.type,
            description: engine.description || null,
            config: engine.config || {},
            options: engine.options || {},
            accessor: engine.accessor,
            uuid: engine.uuid,
            running_plugin_version: engine.running_plugin_version || null
          },

          cloud_provider: 'vault',
          region: 'local',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'vault://vault-local',
          cluster_id: 'vault-local',

          owner: null,
          team: null,

          is_shadow: !engine.description,
          shadow_score: !engine.description ? 60 : 20,

          discovered_by: 'vault-scanner'
        };

        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering secret engines: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverAuthMethods() {
    try {
      const auths = await this.vaultRequest('GET', '/v1/sys/auth');
      const workloads = [];

      for (const [path, method] of Object.entries(auths.data || auths)) {
        if (path === 'token/') continue; // Skip default token auth

        const workload = {
          name: `vault-auth-${path.replace(/\//g, '-').replace(/-$/, '')}`,
          type: 'auth-method',
          namespace: 'vault',
          environment: 'unknown',

          category: 'auth-service',
          subcategory: method.type,
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            auth_type: method.type,
            vault_path: `auth/${path}`,
            local: String(method.local || false)
          },
          metadata: {
            path: `auth/${path}`,
            type: method.type,
            description: method.description || null,
            accessor: method.accessor,
            config: method.config || {},
            uuid: method.uuid
          },

          cloud_provider: 'vault',
          region: 'local',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'vault://vault-local',
          cluster_id: 'vault-local',

          owner: null,
          team: null,
          is_shadow: false,
          shadow_score: 20,

          discovered_by: 'vault-scanner'
        };

        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering auth methods: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverKVSecrets() {
    try {
      // First find all KV v2 engines
      const mounts = await this.vaultRequest('GET', '/v1/sys/mounts');
      const kvEngines = Object.entries(mounts.data || mounts)
        .filter(([_, e]) => typeof e === 'object' && e !== null && e.type === 'kv')
        .map(([path]) => path);

      const workloads = [];

      for (const enginePath of kvEngines) {
        // List secrets in this engine (only top level, don't recurse deep for security)
        try {
          const secrets = await this.vaultRequest('LIST', `/v1/${enginePath}metadata/`);
          const keys = secrets.data?.keys || [];

          for (const key of keys) {
            // Get metadata (not the actual secret value)
            let secretMeta = {};
            try {
              const meta = await this.vaultRequest('GET', `/v1/${enginePath}metadata/${key}`);
              secretMeta = meta.data || {};
            } catch (e) { /* permission denied */ }

            const currentVersion = secretMeta.current_version || 0;
            const createdTime = secretMeta.created_time || null;
            const updatedTime = secretMeta.updated_time || null;
            const versions = secretMeta.versions || {};

            // Determine age
            const ageMs = updatedTime ? Date.now() - new Date(updatedTime).getTime() : null;
            const ageDays = ageMs ? Math.floor(ageMs / 86400000) : null;
            const isStale = ageDays !== null && ageDays > 180;

            const workload = {
              name: `${enginePath.replace(/\/$/, '')}/${key.replace(/\/$/, '')}`,
              type: 'secret',
              namespace: 'vault',
              environment: this.inferSecretEnvironment(key, enginePath),

              category: 'secret',
              subcategory: this.inferSecretType(key),
              is_ai_agent: false,
              is_mcp_server: false,

              labels: {
                engine: enginePath.replace(/\/$/, ''),
                secret_key: key.replace(/\/$/, ''),
                version_count: String(Object.keys(versions).length),
                is_stale: String(isStale)
              },
              metadata: {
                engine_path: enginePath,
                key: key,
                current_version: currentVersion,
                created_time: createdTime,
                updated_time: updatedTime,
                max_versions: secretMeta.max_versions || 0,
                age_days: ageDays,
                is_folder: key.endsWith('/')
              },

              cloud_provider: 'vault',
              region: 'local',
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: 'vault://vault-local',
              cluster_id: 'vault-local',

              owner: null,
              team: null,
              is_shadow: isStale,
              shadow_score: isStale ? 70 : 30,

              discovered_by: 'vault-scanner'
            };

            workload.security_score = this.calculateSecretSecurityScore(workload, isStale, ageDays);
            workloads.push(workload);
          }
        } catch (error) {
          // 404 means no secrets in this engine yet — not an error
          if (error.message?.includes('404')) {
            this.log(`No secrets in ${enginePath} (empty)`, 'info');
          } else {
            this.log(`Error listing secrets in ${enginePath}: ${error.message}`, 'warn');
          }
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering KV secrets: ${error.message}`, 'error');
      return [];
    }
  }

  // ── Helpers ──

  inferSecretEnvironment(key, enginePath) {
    const haystack = `${key} ${enginePath}`.toLowerCase();
    if (/prod/.test(haystack)) return 'production';
    if (/stag/.test(haystack)) return 'staging';
    if (/dev/.test(haystack)) return 'development';
    return 'unknown';
  }

  inferSecretType(key) {
    const k = key.toLowerCase();
    if (/api[_-]?key/.test(k)) return 'api-key';
    if (/database|db|postgres|mysql|mongo/.test(k)) return 'database-credential';
    if (/ssh/.test(k)) return 'ssh-key';
    if (/tls|cert|certificate/.test(k)) return 'certificate';
    if (/token/.test(k)) return 'token';
    if (/password|passwd/.test(k)) return 'password';
    if (/aws|cloud/.test(k)) return 'cloud-credential';
    if (/oauth|client[_-]?secret/.test(k)) return 'oauth-credential';
    return 'generic-secret';
  }

  calculateSecretSecurityScore(workload, isStale, ageDays) {
    let score = 50;
    if (!isStale) score += 20;
    if (ageDays !== null && ageDays < 90) score += 15;
    if (ageDays !== null && ageDays > 365) score -= 20;
    if (workload.environment !== 'unknown') score += 10;
    return Math.max(0, Math.min(100, score));
  }

  async vaultRequest(method, path) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.vaultAddr);
      const mod = url.protocol === 'https:' ? https : http;

      const opts = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: method === 'LIST' ? 'GET' : method,
        headers: {
          'X-Vault-Token': this.vaultToken,
          'Content-Type': 'application/json'
        },
        rejectUnauthorized: false
      };

      if (method === 'LIST') {
        opts.path += '?list=true';
      }

      const req = mod.request(opts, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            if (res.statusCode >= 400) {
              reject(new Error(`Vault ${res.statusCode}: ${data.slice(0, 200)}`));
            } else {
              resolve(JSON.parse(data));
            }
          } catch (e) {
            reject(new Error(`Invalid Vault response: ${e.message}`));
          }
        });
      });

      req.on('error', reject);
      req.setTimeout(10000, () => { req.destroy(); reject(new Error('Vault request timeout')); });
      req.end();
    });
  }
}

module.exports = VaultScanner;