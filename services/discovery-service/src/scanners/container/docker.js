const BaseScanner = require('../base/BaseScanner');
const Docker = require('dockerode');
const os = require('os');

class DockerScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'docker';
    this.version = '1.0.0';
    this.socketPath = config.socketPath || process.env.DOCKER_HOST || '/var/run/docker.sock';
    try {
      this.docker = new Docker({ socketPath: this.socketPath });
    } catch {
      this.docker = null;
    }
  }

  getRequiredCredentials() {
    return [
      { name: 'DOCKER_HOST', description: 'Docker socket path (default: /var/run/docker.sock)' },
    ];
  }

  async validate() {
    if (!this.docker) {
      this.enabled = false;
      this.disabledReason = 'Docker socket not available';
      return false;
    }
    try {
      await this.docker.ping();
      return true;
    } catch (error) {
      this.enabled = false;
      this.disabledReason = 'Docker daemon not reachable — ensure Docker is running';
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'container'];
  }

  async discover() {
    this.log('Starting Docker container discovery', 'info');
    
    try {
      const containers = await this.docker.listContainers();
      const workloads = [];

      for (const container of containers) {
        const inspect = await this.docker.getContainer(container.Id).inspect();
        const labels = inspect.Config.Labels || {};

        // Extract env vars and detect credential-bearing variables
        const envVars = {};
        const credentials = [];
        for (const envLine of (inspect.Config.Env || [])) {
          const eqIdx = envLine.indexOf('=');
          if (eqIdx === -1) continue;
          const key = envLine.substring(0, eqIdx);
          const val = envLine.substring(eqIdx + 1);
          envVars[key] = val;

          // Detect credential-bearing env vars (skip system/runtime vars)
          if (/TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIALS|PRIVATE_KEY/i.test(key) &&
              !/^(NODE_|NPM_|PATH$|HOME$|HOSTNAME$|LANG$)/i.test(key)) {
            const isStatic = !val.startsWith('vault:') && !val.startsWith('arn:aws:secretsmanager');
            credentials.push({
              name: key,
              key: key,
              type: /TOKEN/i.test(key) ? 'token' : /SECRET/i.test(key) ? 'secret-key' : 'api-key',
              is_static: isStatic,
              source: 'env-var',
              value_prefix: val.substring(0, 4) + '...',
              redacted: true,
            });
          }
        }

        const workload = {
          name: container.Names[0].replace('/', ''),
          type: 'container',
          namespace: labels.namespace || 'docker',
          environment: labels.environment || 'unknown',

          container_id: container.Id,
          image: container.Image,

          category: this.categorizeWorkload(labels, inspect),
          subcategory: this.determineSubcategory(labels, inspect),
          is_ai_agent: this.isAIAgent(labels, inspect),
          is_mcp_server: this.isMCPServer(labels, inspect),

          labels,
          metadata: {
            image: container.Image,
            state: container.State,
            status: container.Status,
            ports: container.Ports,
            created: container.Created,
            env: envVars,
            credentials: credentials,
            mounts: (inspect.Mounts || []).map(m => ({
              type: m.Type,
              source: m.Source,
              destination: m.Destination,
              readOnly: m.RW === false,
            })),
            networks: Object.keys(inspect.NetworkSettings?.Networks || {}),
            command: (inspect.Config.Cmd || []).join(' '),
          },
          
          cloud_provider: 'docker',
          region: 'local',
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `docker://${os.hostname()}`,
          cluster_id: os.hostname(),
          
          owner: labels.owner || null,
          team: labels.team || null,
          
          is_shadow: this.isShadowService(labels, inspect),
          shadow_score: this.calculateShadowScore(labels, inspect),
          
          discovered_by: 'docker-scanner'
        };
        
        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      this.log(`Found ${workloads.length} Docker containers`, 'success');
      return workloads;
      
    } catch (error) {
      this.log(`Docker discovery error: ${error.message}`, 'error');
      return [];
    }
  }

  getResourceName(resource) {
    return resource.Name || 
           resource.Names?.[0]?.replace('/', '') || 
           resource.Id || 
           'unknown';
  }
}

module.exports = DockerScanner;
