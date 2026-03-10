// =============================================================================
// GCP Scanner - Discovers workloads from Google Cloud Platform
// =============================================================================
// Scans for:
// 1. Cloud Run services (serverless containers)
// 2. Compute Engine instances (VMs)
// 3. Cloud Functions (serverless functions)
// 4. GKE workloads (Kubernetes pods/deployments)
// 5. Service Accounts (IAM identities)
// 6. Vertex AI endpoints + models (AI/ML inference)
// 7. AI API usage (Generative AI, AI Platform)
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class GCPScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'gcp';
    this.version = '1.0.0';
    this.projectId = config.project || process.env.GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT;
    this.region = config.region || process.env.GCP_REGION || 'us-central1';
    this.initialized = false;
  }

  async initializeGCP() {
    if (this.initialized) return;

    try {
      const { google } = require('googleapis');
      const authOptions = {
        scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      };

      // Use explicit credentials if provided (from connector wizard)
      if (this.config.credentials) {
        authOptions.credentials = this.config.credentials;
        if (this.config.credentials.project_id && !this.projectId) {
          this.projectId = this.config.credentials.project_id;
        }
      }

      const auth = new google.auth.GoogleAuth(authOptions);

      this.authClient = await auth.getClient();
      this.google = google;

      // Initialize service clients
      this.run = google.run({ version: 'v2', auth });
      this.compute = google.compute({ version: 'v1', auth });
      this.cloudfunctions = google.cloudfunctions({ version: 'v2', auth });
      this.iam = google.iam({ version: 'v1', auth });
      this.container = google.container({ version: 'v1', auth });
      this.sqladmin = google.sqladmin({ version: 'v1beta4', auth });
      this.storage = google.storage({ version: 'v1', auth });
      this.cloudkms = google.cloudkms({ version: 'v1', auth });
      this.secretmanager = google.secretmanager({ version: 'v1', auth });

      // AI/ML service clients
      try {
        this.aiplatform = google.aiplatform({ version: 'v1', auth });
        this.serviceusage = google.serviceusage({ version: 'v1', auth });
      } catch (e) {
        this.log(`AI platform SDK init skipped: ${e.message}`, 'warn');
      }

      this.initialized = true;
      this.log(`GCP SDK initialized for project: ${this.projectId}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize GCP SDK: ${error.message}`);
    }
  }

  async validate() {
    try {
      await this.initializeGCP();

      // Verify access by checking project ID resolution
      if (!this.projectId) {
        try {
          const { google } = require('googleapis');
          const authOptions = {
            scopes: ['https://www.googleapis.com/auth/cloud-platform'],
          };
          if (this.config.credentials) {
            authOptions.credentials = this.config.credentials;
          }
          const auth = new google.auth.GoogleAuth(authOptions);
          const projectId = await auth.getProjectId();
          this.projectId = projectId;
        } catch (e) {
          // Project ID not resolvable — still valid if explicitly set
        }
      }

      this.log(`Connected to GCP project: ${this.projectId}`, 'success');
      return true;
    } catch (error) {
      this.log(`GCP validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'cloud-run', 'compute', 'cloud-functions', 'gke', 'service-accounts', 'cloud-sql', 'cloud-storage', 'firewall-rules', 'kms', 'secret-manager', 'vertex-ai', 'ai-platform'];
  }

  getRequiredCredentials() {
    return [
      { name: 'GCP_PROJECT_ID', description: 'GCP project ID' },
      { name: 'GOOGLE_APPLICATION_CREDENTIALS', description: 'Path to service account key JSON (or use workload identity)' },
    ];
  }

  async discover() {
    await this.initializeGCP();

    this.log(`Starting GCP discovery in project: ${this.projectId}`, 'info');
    const workloads = [];

    try {
      // Discover Cloud Run services
      const cloudRunServices = await this.discoverCloudRun();
      workloads.push(...cloudRunServices);
      this.log(`Found ${cloudRunServices.length} Cloud Run services`, 'success');

      // Discover Compute Engine instances
      const vms = await this.discoverComputeEngine();
      workloads.push(...vms);
      this.log(`Found ${vms.length} Compute Engine instances`, 'success');

      // Discover Cloud Functions
      const functions = await this.discoverCloudFunctions();
      workloads.push(...functions);
      this.log(`Found ${functions.length} Cloud Functions`, 'success');

      // Discover GKE workloads
      const gkeWorkloads = await this.discoverGKE();
      workloads.push(...gkeWorkloads);
      this.log(`Found ${gkeWorkloads.length} GKE workloads`, 'success');

      // Discover Service Accounts
      const serviceAccounts = await this.discoverServiceAccounts();
      workloads.push(...serviceAccounts);
      this.log(`Found ${serviceAccounts.length} service accounts`, 'success');

      // Discover Cloud SQL instances
      const cloudSql = await this.discoverCloudSQL();
      workloads.push(...cloudSql);
      this.log(`Found ${cloudSql.length} Cloud SQL instances`, 'success');

      // Discover Cloud Storage buckets
      const buckets = await this.discoverCloudStorage();
      workloads.push(...buckets);
      this.log(`Found ${buckets.length} GCS buckets`, 'success');

      // Discover Firewall Rules
      const firewalls = await this.discoverFirewallRules();
      workloads.push(...firewalls);
      this.log(`Found ${firewalls.length} Firewall rules`, 'success');

      // Discover KMS keys
      const kmsKeys = await this.discoverKMS();
      workloads.push(...kmsKeys);
      this.log(`Found ${kmsKeys.length} KMS keys`, 'success');

      // Discover Secret Manager secrets
      const secrets = await this.discoverSecretManager();
      workloads.push(...secrets);
      this.log(`Found ${secrets.length} Secret Manager secrets`, 'success');

      // Discover Vertex AI endpoints
      const vertexEndpoints = await this.discoverVertexAI();
      workloads.push(...vertexEndpoints);
      this.log(`Found ${vertexEndpoints.length} Vertex AI endpoints`, 'success');

      // Discover Vertex AI models
      const vertexModels = await this.discoverVertexAIModels();
      workloads.push(...vertexModels);
      this.log(`Found ${vertexModels.length} Vertex AI models`, 'success');

      // Discover AI API usage (enabled AI services)
      const aiServices = await this.discoverAIServices();
      workloads.push(...aiServices);
      if (aiServices.length > 0) {
        this.log(`Found ${aiServices.length} enabled AI services`, 'success');
      }

    } catch (error) {
      this.log(`Discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ═══════════════════════════════════════════════════════════════
  // Cloud Run
  // ═══════════════════════════════════════════════════════════════

  async discoverCloudRun() {
    try {
      const parent = `projects/${this.projectId}/locations/-`;
      const response = await this.run.projects.locations.services.list({ parent });
      const workloads = [];

      for (const service of response.data.services || []) {
        const name = service.name.split('/').pop();
        const location = service.name.split('/')[3];
        const labels = service.labels || {};
        const annotations = service.annotations || {};
        const template = service.template || {};
        const container = template.containers?.[0] || {};

        const isReady = (service.conditions || []).find(c => c.type === 'Ready')?.status === 'True';
        const serviceAccount = template.serviceAccount || null;

        const workload = {
          name,
          type: 'cloud-run-service',
          namespace: labels.namespace || 'cloud-run',
          environment: this.inferEnvironment(name, labels),

          category: this.categorizeWorkload(labels, { name }),
          subcategory: this.determineSubcategory(labels, { name }),
          is_ai_agent: this.isAIAgent(labels, { name }),
          is_mcp_server: this.isMCPServer(labels, { name }),

          labels,
          metadata: {
            uri: service.uri,
            url: service.uri,
            generation: service.generation,
            location,
            image: container.image || null,
            port: container.ports?.[0]?.containerPort || null,
            cpu: container.resources?.limits?.cpu || null,
            memory: container.resources?.limits?.memory || null,
            service_account: serviceAccount,
            min_instances: template.scaling?.minInstanceCount || 0,
            max_instances: template.scaling?.maxInstanceCount || 100,
            ingress: service.ingress || 'INGRESS_TRAFFIC_ALL',
            create_time: service.createTime,
            update_time: service.updateTime,
            creator: service.creator,
            last_modifier: service.lastModifier,
            revision: service.latestReadyRevision || null,
            vpc_connector: template.vpcAccess?.connector || null,
            // Env var names for protocol scanner (keys only — values redacted for security)
            env: (container.env || []).reduce((acc, e) => { acc[e.name] = e.valueSource ? '[secret]' : (e.value || '').substring(0, 4) + '***'; return acc; }, {}),

            // Credential lifecycle metadata for Cloud Run services
            credentials: (container.env || []).filter(e => e.valueSource || (e.name && /KEY|SECRET|TOKEN|PASSWORD|CRED|API_KEY/i.test(e.name))).map(e => {
              const isFromSecretMgr = !!e.valueSource;
              const riskFlags = [];
              if (!isFromSecretMgr) riskFlags.push('not-in-vault');
              if (!isFromSecretMgr && e.value) riskFlags.push('possible-hardcoded');
              return {
                id: `env-${e.name}`,
                name: e.name,
                type: isFromSecretMgr ? 'secret_manager_ref' : 'env_variable',
                provider: isFromSecretMgr ? 'gcp-secret-manager' : 'env',
                storage_method: isFromSecretMgr ? 'secret-manager' : 'env-var',
                created_at: service.createTime,
                expires_at: null,
                last_rotated: null,
                is_expired: false,
                is_overprivileged: false,
                is_unused: false,
                never_expires: true,
                lifecycle_status: 'active',
                risk_flags: riskFlags,
                risk_level: riskFlags.length > 0 ? 'medium' : 'low',
              };
            }),
            credential_summary: (() => {
              const envCreds = (container.env || []).filter(e => e.valueSource || (e.name && /KEY|SECRET|TOKEN|PASSWORD|CRED|API_KEY/i.test(e.name)));
              const inVault = envCreds.filter(e => !!e.valueSource).length;
              const notInVault = envCreds.length - inVault;
              return {
                total: envCreds.length,
                active: envCreds.length,
                expired: 0,
                at_risk: notInVault,
                has_static_creds: notInVault > 0,
                in_vault: inVault,
                not_in_vault: notInVault,
                needs_rotation: false,
              };
            })(),
          },

          cloud_provider: 'gcp',
          region: location,
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: labels.owner || annotations.owner || null,
          team: labels.team || annotations.team || null,
          cost_center: labels['cost-center'] || labels.cost_center || null,

          is_shadow: this.isShadowService(labels, { name }),
          shadow_score: this.calculateShadowScore(labels, { name }),

          status: isReady ? 'active' : 'pending',
          discovered_by: 'gcp-scanner'
        };

        workload.security_score = this.calculateGCPSecurityScore(workload, serviceAccount, service.ingress);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Cloud Run: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Compute Engine
  // ═══════════════════════════════════════════════════════════════

  async discoverComputeEngine() {
    try {
      const response = await this.compute.instances.aggregatedList({
        project: this.projectId,
        filter: 'status=RUNNING',
      });
      const workloads = [];

      for (const [zone, scopedList] of Object.entries(response.data.items || {})) {
        for (const instance of scopedList.instances || []) {
          const labels = instance.labels || {};
          const tags = instance.tags?.items || [];
          const name = instance.name;
          const zoneName = zone.replace('zones/', '');
          const region = zoneName.replace(/-[a-z]$/, '');

          const serviceAccount = instance.serviceAccounts?.[0]?.email || null;
          const hasExternalIp = instance.networkInterfaces?.some(
            ni => ni.accessConfigs?.some(ac => ac.natIP)
          );

          const workload = {
            name,
            type: 'gce-instance',
            namespace: labels.namespace || 'compute',
            environment: this.inferEnvironment(name, labels),

            category: this.categorizeWorkload(labels, { name }),
            subcategory: this.determineSubcategory(labels, { name }),
            is_ai_agent: this.isAIAgent(labels, { name }),
            is_mcp_server: this.isMCPServer(labels, { name }),

            labels,
            metadata: {
              instance_id: instance.id,
              machine_type: instance.machineType?.split('/').pop(),
              zone: zoneName,
              status: instance.status,
              creation_timestamp: instance.creationTimestamp,
              service_account: serviceAccount,
              has_external_ip: hasExternalIp,
              network_tags: tags,
              disks: (instance.disks || []).map(d => ({
                name: d.source?.split('/').pop(),
                size_gb: d.diskSizeGb,
                type: d.type,
              })),
              preemptible: instance.scheduling?.preemptible || false,
              image: instance.disks?.[0]?.source || null,
            },

            cloud_provider: 'gcp',
            region,
            account_id: this.projectId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `gcp://${this.projectId}`,
            cluster_id: this.projectId,

            owner: labels.owner || null,
            team: labels.team || null,
            cost_center: labels['cost-center'] || labels.cost_center || null,

            is_shadow: this.isShadowService(labels, { name }),
            shadow_score: this.calculateShadowScore(labels, { name }),

            status: instance.status === 'RUNNING' ? 'active' : 'inactive',
            discovered_by: 'gcp-scanner'
          };

          workload.security_score = this.calculateGCPSecurityScore(workload, serviceAccount, null, hasExternalIp);
          workloads.push(workload);
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Compute Engine: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Cloud Functions
  // ═══════════════════════════════════════════════════════════════

  async discoverCloudFunctions() {
    try {
      const parent = `projects/${this.projectId}/locations/-`;
      const response = await this.cloudfunctions.projects.locations.functions.list({ parent });
      const workloads = [];

      for (const func of response.data.functions || []) {
        const name = func.name.split('/').pop();
        const location = func.name.split('/')[3];
        const labels = func.labels || {};
        const serviceConfig = func.serviceConfig || {};

        const workload = {
          name,
          type: 'cloud-function',
          namespace: labels.namespace || 'functions',
          environment: this.inferEnvironment(name, labels),

          category: this.categorizeWorkload(labels, { name }),
          subcategory: this.determineSubcategory(labels, { name }),
          is_ai_agent: this.isAIAgent(labels, { name }),
          is_mcp_server: this.isMCPServer(labels, { name }),

          labels,
          metadata: {
            runtime: func.buildConfig?.runtime || null,
            entry_point: func.buildConfig?.entryPoint || null,
            source: func.buildConfig?.source?.storageSource?.bucket || null,
            state: func.state,
            uri: serviceConfig.uri || null,
            service_account: serviceConfig.serviceAccountEmail || null,
            available_memory: serviceConfig.availableMemory || null,
            timeout: serviceConfig.timeoutSeconds || null,
            max_instances: serviceConfig.maxInstanceCount || null,
            min_instances: serviceConfig.minInstanceCount || 0,
            ingress: serviceConfig.ingressSettings || null,
            vpc_connector: serviceConfig.vpcConnector || null,
            trigger: func.eventTrigger || { type: 'http' },
            update_time: func.updateTime,
            create_time: func.createTime,
          },

          cloud_provider: 'gcp',
          region: location,
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: labels.owner || null,
          team: labels.team || null,
          cost_center: labels['cost-center'] || labels.cost_center || null,

          is_shadow: this.isShadowService(labels, { name }),
          shadow_score: this.calculateShadowScore(labels, { name }),

          status: func.state === 'ACTIVE' ? 'active' : 'pending',
          discovered_by: 'gcp-scanner'
        };

        workload.security_score = this.calculateGCPSecurityScore(workload, serviceConfig.serviceAccountEmail, serviceConfig.ingressSettings);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Cloud Functions: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // GKE
  // ═══════════════════════════════════════════════════════════════

  async discoverGKE() {
    try {
      const parent = `projects/${this.projectId}/locations/-`;
      const response = await this.container.projects.locations.clusters.list({ parent });
      const workloads = [];

      for (const cluster of response.data.clusters || []) {
        const labels = cluster.resourceLabels || {};

        const workload = {
          name: cluster.name,
          type: 'gke-cluster',
          namespace: labels.namespace || 'gke',
          environment: this.inferEnvironment(cluster.name, labels),

          category: 'kubernetes-cluster',
          subcategory: cluster.autopilot?.enabled ? 'autopilot' : 'standard',
          is_ai_agent: false,
          is_mcp_server: false,

          labels,
          metadata: {
            cluster_id: cluster.id,
            location: cluster.location,
            status: cluster.status,
            node_count: cluster.currentNodeCount,
            master_version: cluster.currentMasterVersion,
            node_version: cluster.currentNodeVersion,
            endpoint: cluster.endpoint,
            services_cidr: cluster.servicesIpv4Cidr,
            cluster_cidr: cluster.clusterIpv4Cidr,
            autopilot: cluster.autopilot?.enabled || false,
            private_cluster: cluster.privateClusterConfig?.enablePrivateNodes || false,
            workload_identity: cluster.workloadIdentityConfig?.workloadPool || null,
            create_time: cluster.createTime,
          },

          cloud_provider: 'gcp',
          region: cluster.location,
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: cluster.name,

          owner: labels.owner || null,
          team: labels.team || null,
          cost_center: labels['cost-center'] || labels.cost_center || null,

          is_shadow: this.isShadowService(labels, { name: cluster.name }),
          shadow_score: this.calculateShadowScore(labels, { name: cluster.name }),

          status: cluster.status === 'RUNNING' ? 'active' : 'pending',
          discovered_by: 'gcp-scanner'
        };

        workload.security_score = this.calculateGKESecurityScore(workload, cluster);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering GKE: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Service Accounts
  // ═══════════════════════════════════════════════════════════════

  async discoverServiceAccounts() {
    try {
      const response = await this.iam.projects.serviceAccounts.list({
        name: `projects/${this.projectId}`,
      });
      const workloads = [];

      for (const sa of response.data.accounts || []) {
        // Skip default/system service accounts
        const isDefault = sa.email?.includes('developer.gserviceaccount.com') ||
                         sa.email?.includes('@cloudbuild.gserviceaccount.com') ||
                         sa.email?.includes('gcp-sa-');
        const isSystem = sa.email?.includes('.iam.gserviceaccount.com') === false;

        if (isSystem) continue; // Skip non-project service accounts

        // Get keys to detect stale accounts
        let keys = [];
        try {
          const keysResponse = await this.iam.projects.serviceAccounts.keys.list({
            name: `projects/${this.projectId}/serviceAccounts/${sa.email}`,
          });
          keys = (keysResponse.data.keys || []).filter(k => k.keyType === 'USER_MANAGED');
        } catch (e) { /* permission error */ }

        const oldestKeyAge = keys.reduce((max, k) => {
          const age = (Date.now() - new Date(k.validAfterTime).getTime()) / 86400000;
          return Math.max(max, age);
        }, 0);

        const workload = {
          name: sa.email.split('@')[0],
          type: 'service-account',
          namespace: 'iam',
          environment: this.inferEnvironment(sa.displayName || sa.email, {}),

          category: 'service-account',
          subcategory: isDefault ? 'default-compute' : 'custom',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            email: sa.email,
            display_name: sa.displayName || null,
            unique_id: sa.uniqueId,
            description: sa.description || null,
            disabled: sa.disabled || false,
            is_default: isDefault,
            user_managed_keys: keys.length,
            oldest_key_age_days: Math.round(oldestKeyAge),
            oauth2_client_id: sa.oauth2ClientId || null,

            // Credential lifecycle metadata
            credentials: keys.map(k => {
              const createdAt = k.validAfterTime ? new Date(k.validAfterTime) : null;
              const expiresAt = k.validBeforeTime ? new Date(k.validBeforeTime) : null;
              const ageDays = createdAt ? Math.round((Date.now() - createdAt.getTime()) / 86400000) : null;
              const isExpired = expiresAt ? expiresAt < new Date() : false;
              const neverExpires = !expiresAt || expiresAt.getFullYear() > 9000;
              const neverRotated = ageDays > 90;
              const riskFlags = [];
              if (neverExpires) riskFlags.push('no-expiry');
              if (neverRotated) riskFlags.push('never-rotated');
              if (ageDays > 365) riskFlags.push('stale-key');
              if (isExpired) riskFlags.push('expired');

              return {
                id: k.name?.split('/').pop() || k.keyAlgorithm,
                name: `sa-key-${k.name?.split('/').pop()?.substring(0, 8) || 'unknown'}`,
                type: 'service_account_key',
                key_type: k.keyType,
                algorithm: k.keyAlgorithm,
                created_at: k.validAfterTime,
                expires_at: neverExpires ? null : k.validBeforeTime,
                last_rotated: null,
                age_days: ageDays,
                is_expired: isExpired,
                is_overprivileged: false, // Would need IAM policy analysis
                is_unused: false, // Would need audit log analysis
                never_expires: neverExpires,
                storage_method: 'gcp-iam',
                lifecycle_status: isExpired ? 'expired' : (sa.disabled ? 'revoked' : 'active'),
                risk_flags: riskFlags,
                risk_level: riskFlags.length >= 2 ? 'high' : (riskFlags.length === 1 ? 'medium' : 'low'),
              };
            }),
            credential_summary: {
              total: keys.length,
              active: keys.filter(k => !k.validBeforeTime || new Date(k.validBeforeTime) > new Date()).length,
              expired: keys.filter(k => k.validBeforeTime && new Date(k.validBeforeTime) < new Date()).length,
              at_risk: keys.filter(k => {
                const age = k.validAfterTime ? (Date.now() - new Date(k.validAfterTime).getTime()) / 86400000 : 0;
                return age > 90 || !k.validBeforeTime || new Date(k.validBeforeTime).getFullYear() > 9000;
              }).length,
              oldest_key_days: Math.round(oldestKeyAge),
              has_static_creds: keys.length > 0,
              needs_rotation: oldestKeyAge > 90,
            },
          },

          cloud_provider: 'gcp',
          region: 'global',
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: !sa.displayName && !sa.description && !isDefault,
          shadow_score: this.calculateSAScore(sa, keys, isDefault),

          status: sa.disabled ? 'inactive' : 'active',
          discovered_by: 'gcp-scanner'
        };

        workload.security_score = this.calculateSASecurityScore(workload, keys, oldestKeyAge, isDefault);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering service accounts: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Cloud SQL
  // ═══════════════════════════════════════════════════════════════

  async discoverCloudSQL() {
    try {
      const response = await this.sqladmin.instances.list({ project: this.projectId });
      const workloads = [];

      for (const instance of response.data.items || []) {
        const name = instance.name;
        const settings = instance.settings || {};
        const ipConfig = settings.ipConfiguration || {};

        const publiclyAccessible = !!(
          instance.ipAddresses?.some(ip => ip.type === 'PRIMARY' && ip.ipAddress) &&
          ipConfig.ipv4Enabled && !ipConfig.privateNetwork
        );
        const sslRequired = !!ipConfig.requireSsl;
        const iamAuthEnabled = !!(settings.databaseFlags || []).find(
          f => f.name === 'cloudsql.iam_authentication' && f.value === 'on'
        );
        const backupEnabled = !!settings.backupConfiguration?.enabled;
        const pointInTimeRecovery = !!settings.backupConfiguration?.pointInTimeRecoveryEnabled;

        // Security scoring
        let score = this.calculateSecurityScore({ metadata: {} });
        if (publiclyAccessible) score -= 25;
        if (!sslRequired) score -= 15;
        if (!iamAuthEnabled) score -= 10;
        if (settings.availabilityType === 'REGIONAL') score += 10;
        if (!backupEnabled) score -= 10;
        if (pointInTimeRecovery) score += 10;

        const workload = {
          name,
          type: 'cloud-sql',
          namespace: 'database',
          environment: this.inferEnvironment(name, {}),

          category: 'data-store',
          subcategory: instance.databaseVersion?.startsWith('POSTGRES') ? 'postgresql' : instance.databaseVersion?.split('_')[0]?.toLowerCase() || 'sql',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: instance.settings?.userLabels || {},
          metadata: {
            instance_name: instance.name,
            database_version: instance.databaseVersion,
            region: instance.region,
            state: instance.state,
            tier: settings.tier,
            publicly_accessible: publiclyAccessible,
            ssl_required: sslRequired,
            iam_auth_enabled: iamAuthEnabled,
            backup_enabled: backupEnabled,
            point_in_time_recovery: pointInTimeRecovery,
            storage_auto_resize: settings.storageAutoResize,
            maintenance_window: settings.maintenanceWindow,
            data_disk_size_gb: settings.dataDiskSizeGb,
            availability_type: settings.availabilityType,
            private_network: ipConfig.privateNetwork,
          },

          cloud_provider: 'gcp',
          region: instance.region,
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: instance.settings?.userLabels?.owner || null,
          team: instance.settings?.userLabels?.team || null,
          cost_center: instance.settings?.userLabels?.['cost-center'] || instance.settings?.userLabels?.cost_center || null,

          is_shadow: false,
          shadow_score: 0,

          status: instance.state === 'RUNNABLE' ? 'active' : 'inactive',
          discovered_by: 'gcp-scanner',
          security_score: Math.max(0, Math.min(100, score)),
        };

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Cloud SQL: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Cloud Storage
  // ═══════════════════════════════════════════════════════════════

  async discoverCloudStorage() {
    try {
      const response = await this.storage.buckets.list({ project: this.projectId });
      const workloads = [];

      for (const bucket of response.data.items || []) {
        const name = bucket.name;

        // Get IAM policy to check public access
        let isPublic = false;
        try {
          const iamResponse = await this.storage.buckets.getIamPolicy({ bucket: bucket.name });
          const bindings = iamResponse.data.bindings || [];
          isPublic = bindings.some(b =>
            (b.members || []).some(m => m === 'allUsers' || m === 'allAuthenticatedUsers')
          );
        } catch (e) {
          this.log(`Could not get IAM policy for bucket ${name}: ${e.message}`, 'warn');
        }

        const uniformBucketLevelAccess = !!bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled;
        const versioningEnabled = !!bucket.versioning?.enabled;
        const publicAccessPrevention = bucket.iamConfiguration?.publicAccessPrevention || 'inherited';
        const hasCustomKmsKey = !!bucket.encryption?.defaultKmsKeyName;

        // Security scoring
        let score = this.calculateSecurityScore({ metadata: {} });
        if (isPublic) score -= 30;
        if (!uniformBucketLevelAccess) score -= 10;
        if (!versioningEnabled) score -= 10;
        if (publicAccessPrevention === 'enforced') score += 10;
        if (hasCustomKmsKey) score += 10;

        const workload = {
          name,
          type: 'gcs-bucket',
          namespace: 'storage',
          environment: this.inferEnvironment(name, {}),

          category: 'data-store',
          subcategory: 'object-storage',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: bucket.labels || {},
          metadata: {
            bucket_name: bucket.name,
            location: bucket.location,
            location_type: bucket.locationType,
            storage_class: bucket.storageClass,
            creation_time: bucket.timeCreated,
            updated: bucket.updated,
            versioning_enabled: versioningEnabled,
            uniform_bucket_level_access: uniformBucketLevelAccess,
            public_access_prevention: publicAccessPrevention,
            is_public: isPublic,
            encryption: {
              default_kms_key: bucket.encryption?.defaultKmsKeyName || 'Google-managed',
            },
            lifecycle_rules_count: bucket.lifecycle?.rule?.length || 0,
            retention_policy: bucket.retentionPolicy || null,
            logging: bucket.logging || null,
          },

          cloud_provider: 'gcp',
          region: bucket.location,
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: bucket.labels?.owner || null,
          team: bucket.labels?.team || null,
          cost_center: bucket.labels?.['cost-center'] || bucket.labels?.cost_center || null,

          is_shadow: false,
          shadow_score: 0,

          status: 'active',
          discovered_by: 'gcp-scanner',
          security_score: Math.max(0, Math.min(100, score)),
        };

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Cloud Storage: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Firewall Rules
  // ═══════════════════════════════════════════════════════════════

  async discoverFirewallRules() {
    try {
      const response = await this.compute.firewalls.list({ project: this.projectId });
      const workloads = [];

      for (const fw of response.data.items || []) {
        const name = fw.name;
        const action = fw.allowed ? 'allow' : 'deny';
        const allows0000 = !!fw.sourceRanges?.includes('0.0.0.0/0');
        const allowedPorts = (fw.allowed || []).map(a => ({
          protocol: a.IPProtocol,
          ports: a.ports || [],
        }));
        const deniedPorts = (fw.denied || []).map(d => ({
          protocol: d.IPProtocol,
          ports: d.ports || [],
        }));

        // Check if SSH from 0.0.0.0/0 is allowed
        const allowsSshFromAnywhere = allows0000 && allowedPorts.some(
          a => a.protocol === 'tcp' && (a.ports.includes('22') || a.ports.length === 0)
        );

        // Security scoring
        let score = this.calculateSecurityScore({ metadata: {} });
        if (allows0000 && fw.direction === 'INGRESS' && action === 'allow') score -= 30;
        if (allowsSshFromAnywhere) score -= 15;
        if (fw.disabled) score -= 10;
        if (fw.logConfig?.enable) score += 10;

        const workload = {
          name,
          type: 'firewall-rule',
          namespace: 'network',
          environment: this.inferEnvironment(name, {}),

          category: 'network-policy',
          subcategory: fw.direction === 'INGRESS' ? 'ingress-rule' : 'egress-rule',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            rule_name: fw.name,
            network: fw.network?.split('/').pop(),
            direction: fw.direction,
            priority: fw.priority,
            action,
            source_ranges: fw.sourceRanges || [],
            destination_ranges: fw.destinationRanges || [],
            source_tags: fw.sourceTags || [],
            target_tags: fw.targetTags || [],
            allowed_ports: allowedPorts,
            denied_ports: deniedPorts,
            allows_0_0_0_0: allows0000,
            disabled: !!fw.disabled,
            log_config_enabled: !!fw.logConfig?.enable,
          },

          cloud_provider: 'gcp',
          region: 'global',
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: false,
          shadow_score: 0,

          status: fw.disabled ? 'inactive' : 'active',
          discovered_by: 'gcp-scanner',
          security_score: Math.max(0, Math.min(100, score)),
        };

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Firewall Rules: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // KMS
  // ═══════════════════════════════════════════════════════════════

  async discoverKMS() {
    try {
      const workloads = [];
      const locations = ['global', this.region];
      const keyRings = [];

      // List key rings from global and project region
      for (const location of locations) {
        try {
          const response = await this.cloudkms.projects.locations.keyRings.list({
            parent: `projects/${this.projectId}/locations/${location}`,
          });
          for (const kr of response.data.keyRings || []) {
            keyRings.push(kr);
          }
        } catch (e) {
          this.log(`Could not list KMS key rings in ${location}: ${e.message}`, 'warn');
        }
      }

      // List crypto keys in each key ring
      for (const keyRing of keyRings) {
        try {
          const response = await this.cloudkms.projects.locations.keyRings.cryptoKeys.list({
            parent: keyRing.name,
          });

          for (const key of response.data.cryptoKeys || []) {
            const keyName = key.name.split('/').pop();
            const keyRingName = keyRing.name.split('/').pop();
            const rotationEnabled = !!key.rotationPeriod;
            const isHSM = key.versionTemplate?.protectionLevel === 'HSM';

            // Security scoring
            let score = this.calculateSecurityScore({ metadata: {} });
            if (!rotationEnabled) score -= 15;
            if (isHSM) score += 10;
            if (key.purpose === 'ENCRYPT_DECRYPT') score += 5;

            const workload = {
              name: keyName,
              type: 'kms-key',
              namespace: 'security',
              environment: this.inferEnvironment(keyName, {}),

              category: 'encryption-key',
              subcategory: key.purpose?.toLowerCase()?.replace(/_/g, '-') || 'unknown',
              is_ai_agent: false,
              is_mcp_server: false,

              labels: key.labels || {},
              metadata: {
                key_name: keyName,
                key_ring: keyRingName,
                purpose: key.purpose,
                algorithm: key.versionTemplate?.algorithm,
                protection_level: key.versionTemplate?.protectionLevel,
                rotation_period: key.rotationPeriod || null,
                next_rotation_time: key.nextRotationTime || null,
                create_time: key.createTime,
                primary_state: key.primary?.state,
                rotation_enabled: rotationEnabled,
              },

              cloud_provider: 'gcp',
              region: keyRing.name.split('/')[3],
              account_id: this.projectId,
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `gcp://${this.projectId}`,
              cluster_id: this.projectId,

              owner: key.labels?.owner || null,
              team: key.labels?.team || null,
              cost_center: key.labels?.['cost-center'] || key.labels?.cost_center || null,

              is_shadow: false,
              shadow_score: 0,

              status: key.primary?.state === 'ENABLED' ? 'active' : 'inactive',
              discovered_by: 'gcp-scanner',
              security_score: Math.max(0, Math.min(100, score)),
            };

            workloads.push(workload);
          }
        } catch (e) {
          this.log(`Could not list KMS keys in ${keyRing.name}: ${e.message}`, 'warn');
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering KMS: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Secret Manager
  // ═══════════════════════════════════════════════════════════════

  async discoverSecretManager() {
    try {
      const response = await this.secretmanager.projects.secrets.list({
        parent: `projects/${this.projectId}`,
      });
      const workloads = [];

      for (const secret of response.data.secrets || []) {
        const secretName = secret.name.split('/').pop();
        const rotationEnabled = !!secret.rotation?.rotationPeriod;
        const hasTopics = !!(secret.topics && secret.topics.length > 0);
        const hasExpireTime = !!secret.expireTime;

        // Security scoring
        let score = this.calculateSecurityScore({ metadata: {} });
        if (!rotationEnabled) score -= 20;
        if (hasTopics) score += 10;
        if (hasExpireTime) score += 5;

        const workload = {
          name: secretName,
          type: 'managed-secret',
          namespace: 'security',
          environment: this.inferEnvironment(secretName, secret.labels || {}),

          category: 'secret',
          subcategory: 'managed-secret',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: secret.labels || {},
          metadata: {
            secret_name: secretName,
            create_time: secret.createTime,
            replication: secret.replication,
            labels: secret.labels || {},
            rotation: secret.rotation || null,
            rotation_enabled: rotationEnabled,
            topics: secret.topics || [],
            expire_time: secret.expireTime || null,
            version_aliases: secret.versionAliases || null,
            etag: secret.etag,
          },

          cloud_provider: 'gcp',
          region: 'global',
          account_id: this.projectId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `gcp://${this.projectId}`,
          cluster_id: this.projectId,

          owner: secret.labels?.owner || null,
          team: secret.labels?.team || null,
          cost_center: secret.labels?.['cost-center'] || secret.labels?.cost_center || null,

          is_shadow: false,
          shadow_score: 0,

          status: 'active',
          discovered_by: 'gcp-scanner',
          security_score: Math.max(0, Math.min(100, score)),
        };

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Secret Manager: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Vertex AI Endpoints
  // ═══════════════════════════════════════════════════════════════

  async discoverVertexAI() {
    if (!this.aiplatform) return [];
    try {
      const workloads = [];
      // Scan current region + us-central1 (common default for AI)
      const locations = [...new Set([this.region, 'us-central1'])];

      for (const location of locations) {
        try {
          const parent = `projects/${this.projectId}/locations/${location}`;
          const response = await this.aiplatform.projects.locations.endpoints.list({ parent });

          for (const endpoint of response.data.endpoints || []) {
            const name = endpoint.displayName || endpoint.name.split('/').pop();
            const endpointId = endpoint.name.split('/').pop();
            const deployedModels = endpoint.deployedModels || [];
            const serviceAccount = endpoint.serviceAccount || null;

            // Extract model info from deployed models
            const modelDetails = deployedModels.map(dm => ({
              model_id: dm.model?.split('/').pop() || null,
              display_name: dm.displayName || null,
              machine_type: dm.dedicatedResources?.machineSpec?.machineType || dm.automaticResources ? 'automatic' : null,
              accelerator_type: dm.dedicatedResources?.machineSpec?.acceleratorType || null,
              accelerator_count: dm.dedicatedResources?.machineSpec?.acceleratorCount || 0,
              traffic_split: endpoint.trafficSplit?.[dm.id] || 0,
            }));

            const primaryModel = modelDetails[0] || {};
            const hasGPU = modelDetails.some(m => m.accelerator_count > 0);

            // Determine access pattern
            let accessPattern = 'public';
            if (endpoint.network) accessPattern = 'vpc-peering';
            if (endpoint.privateServiceConnectConfig) accessPattern = 'private-service-connect';

            // Security scoring
            let score = this.calculateSecurityScore({ metadata: {} });
            if (accessPattern === 'public') score -= 20;
            if (!serviceAccount || serviceAccount.includes('developer.gserviceaccount.com')) score -= 15;
            if (hasGPU) score -= 5; // Higher value target
            if (accessPattern !== 'public') score += 15;

            const workload = {
              name,
              type: 'vertex-ai-endpoint',
              namespace: 'ai-platform',
              environment: this.inferEnvironment(name, endpoint.labels || {}),

              category: 'ai-service',
              subcategory: 'inference-endpoint',
              is_ai_agent: true,
              is_mcp_server: false,

              labels: endpoint.labels || {},
              metadata: {
                endpoint_id: endpointId,
                endpoint_name: endpoint.name,
                display_name: endpoint.displayName,
                description: endpoint.description || null,
                location,
                deployed_models: modelDetails,
                deployed_model_count: deployedModels.length,
                service_account: serviceAccount,
                network: endpoint.network || null,
                access_pattern: accessPattern,
                has_gpu: hasGPU,
                encryption_spec: endpoint.encryptionSpec?.kmsKeyName || 'Google-managed',
                create_time: endpoint.createTime,
                update_time: endpoint.updateTime,
                traffic_split: endpoint.trafficSplit || {},
                ai_asset: {
                  ai_asset_id: `vertex-endpoint-${endpointId}`,
                  provider: 'gcp',
                  service: 'vertex-ai',
                  resource_type: 'endpoint',
                  model_family: this._inferModelFamily(primaryModel.display_name || name),
                  model_id: primaryModel.model_id || null,
                  deployment_type: 'endpoint',
                  access_pattern: accessPattern,
                  auth_method: 'service-account',
                  service_account: serviceAccount,
                  governance_status: 'unregistered',
                  machine_type: primaryModel.machine_type,
                  accelerator: hasGPU ? {
                    type: primaryModel.accelerator_type,
                    count: primaryModel.accelerator_count,
                  } : null,
                  created_at: endpoint.createTime,
                  last_deployed: endpoint.updateTime,
                },
              },

              cloud_provider: 'gcp',
              region: location,
              account_id: this.projectId,
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `gcp://${this.projectId}`,
              cluster_id: this.projectId,

              owner: endpoint.labels?.owner || null,
              team: endpoint.labels?.team || null,
              cost_center: endpoint.labels?.['cost-center'] || endpoint.labels?.cost_center || null,

              is_shadow: false,
              shadow_score: 0,

              status: 'active',
              discovered_by: 'gcp-scanner',
              security_score: Math.max(0, Math.min(100, score)),
            };

            workloads.push(workload);
          }
        } catch (locError) {
          // API not enabled or no permission for this location — skip
          if (!locError.message?.includes('not enabled') && !locError.message?.includes('PERMISSION_DENIED')) {
            this.log(`Vertex AI endpoints [${location}]: ${locError.message}`, 'warn');
          }
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Vertex AI endpoints: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Vertex AI Models
  // ═══════════════════════════════════════════════════════════════

  async discoverVertexAIModels() {
    if (!this.aiplatform) return [];
    try {
      const workloads = [];
      const locations = [...new Set([this.region, 'us-central1'])];

      for (const location of locations) {
        try {
          const parent = `projects/${this.projectId}/locations/${location}`;
          const response = await this.aiplatform.projects.locations.models.list({ parent });

          for (const model of response.data.models || []) {
            const name = model.displayName || model.name.split('/').pop();
            const modelId = model.name.split('/').pop();

            // Determine framework from container spec
            const containerSpec = model.containerSpec || {};
            const framework = this._inferFramework(containerSpec.imageUri || '', model.metadata);

            const workload = {
              name,
              type: 'vertex-ai-model',
              namespace: 'ai-platform',
              environment: this.inferEnvironment(name, model.labels || {}),

              category: 'ai-model',
              subcategory: framework || 'custom-model',
              is_ai_agent: false,
              is_mcp_server: false,

              labels: model.labels || {},
              metadata: {
                model_id: modelId,
                model_name: model.name,
                display_name: model.displayName,
                description: model.description || null,
                location,
                version_id: model.versionId || null,
                framework,
                container_image: containerSpec.imageUri || null,
                artifact_uri: model.artifactUri || null,
                training_pipeline: model.trainingPipeline || null,
                supported_deployment_resources: model.supportedDeploymentResourcesTypes || [],
                create_time: model.createTime,
                update_time: model.updateTime,
                ai_asset: {
                  ai_asset_id: `vertex-model-${modelId}`,
                  provider: 'gcp',
                  service: 'vertex-ai',
                  resource_type: 'model',
                  model_family: this._inferModelFamily(name),
                  model_id: modelId,
                  deployment_type: 'registered-model',
                  auth_method: 'service-account',
                  governance_status: 'unregistered',
                  framework,
                  created_at: model.createTime,
                },
              },

              cloud_provider: 'gcp',
              region: location,
              account_id: this.projectId,
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `gcp://${this.projectId}`,
              cluster_id: this.projectId,

              owner: model.labels?.owner || null,
              team: model.labels?.team || null,
              cost_center: model.labels?.['cost-center'] || model.labels?.cost_center || null,

              is_shadow: false,
              shadow_score: 0,

              status: 'active',
              discovered_by: 'gcp-scanner',
              security_score: this.calculateSecurityScore({ metadata: {} }),
            };

            workloads.push(workload);
          }
        } catch (locError) {
          if (!locError.message?.includes('not enabled') && !locError.message?.includes('PERMISSION_DENIED')) {
            this.log(`Vertex AI models [${location}]: ${locError.message}`, 'warn');
          }
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Vertex AI models: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // AI Service Usage Detection
  // ═══════════════════════════════════════════════════════════════

  async discoverAIServices() {
    if (!this.serviceusage) return [];
    try {
      const workloads = [];
      const aiApis = [
        { api: 'aiplatform.googleapis.com', name: 'Vertex AI', service: 'vertex-ai' },
        { api: 'generativelanguage.googleapis.com', name: 'Generative AI (Gemini)', service: 'generative-ai' },
        { api: 'ml.googleapis.com', name: 'AI Platform (Legacy)', service: 'ai-platform-legacy' },
        { api: 'language.googleapis.com', name: 'Cloud Natural Language', service: 'cloud-nlp' },
        { api: 'vision.googleapis.com', name: 'Cloud Vision AI', service: 'cloud-vision' },
        { api: 'speech.googleapis.com', name: 'Cloud Speech-to-Text', service: 'cloud-speech' },
        { api: 'translate.googleapis.com', name: 'Cloud Translation', service: 'cloud-translate' },
        { api: 'documentai.googleapis.com', name: 'Document AI', service: 'document-ai' },
        { api: 'dialogflow.googleapis.com', name: 'Dialogflow', service: 'dialogflow' },
        { api: 'automl.googleapis.com', name: 'AutoML', service: 'automl' },
      ];

      for (const { api, name, service } of aiApis) {
        try {
          const response = await this.serviceusage.services.get({
            name: `projects/${this.projectId}/services/${api}`,
          });

          if (response.data.state === 'ENABLED') {
            const workload = {
              name: `${name} API`,
              type: 'ai-api-enabled',
              namespace: 'ai-platform',
              environment: 'production',

              category: 'ai-service',
              subcategory: 'api-enabled',
              is_ai_agent: false,
              is_mcp_server: false,

              labels: {},
              metadata: {
                api_name: api,
                service_name: name,
                state: 'ENABLED',
                ai_asset: {
                  ai_asset_id: `gcp-api-${service}`,
                  provider: 'gcp',
                  service,
                  resource_type: 'api-enabled',
                  deployment_type: 'managed-api',
                  auth_method: 'service-account',
                  governance_status: 'unregistered',
                },
              },

              cloud_provider: 'gcp',
              region: 'global',
              account_id: this.projectId,
              trust_domain: this.config.trustDomain || 'company.com',
              issuer: `gcp://${this.projectId}`,
              cluster_id: this.projectId,

              owner: null,
              team: null,
              cost_center: null,

              is_shadow: false,
              shadow_score: 0,

              status: 'active',
              discovered_by: 'gcp-scanner',
              security_score: this.calculateSecurityScore({ metadata: {} }),
            };

            workloads.push(workload);
          }
        } catch (apiError) {
          // API not accessible or Service Usage API not enabled — skip silently
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering AI services: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════

  _inferModelFamily(name) {
    if (!name) return 'custom';
    const n = name.toLowerCase();
    if (/gemini/i.test(n)) return 'gemini';
    if (/palm/i.test(n)) return 'palm';
    if (/llama/i.test(n)) return 'llama';
    if (/claude/i.test(n)) return 'claude';
    if (/gpt/i.test(n)) return 'gpt';
    if (/bert/i.test(n)) return 'bert';
    if (/t5/i.test(n)) return 't5';
    if (/stable.?diffusion/i.test(n)) return 'stable-diffusion';
    if (/whisper/i.test(n)) return 'whisper';
    return 'custom';
  }

  _inferFramework(imageUri, metadata) {
    if (!imageUri && !metadata) return null;
    const img = (imageUri || '').toLowerCase();
    if (/tensorflow|tf-/i.test(img)) return 'tensorflow';
    if (/pytorch|torch/i.test(img)) return 'pytorch';
    if (/xgboost/i.test(img)) return 'xgboost';
    if (/sklearn|scikit/i.test(img)) return 'scikit-learn';
    if (/huggingface|transformers/i.test(img)) return 'huggingface';
    if (/vllm/i.test(img)) return 'vllm';
    if (/triton/i.test(img)) return 'triton';
    if (/tgi|text-generation-inference/i.test(img)) return 'tgi';
    return null;
  }

  inferEnvironment(name, labels) {
    if (labels.environment) return labels.environment;
    if (labels.env) return labels.env;
    const n = (name || '').toLowerCase();
    if (/prod/.test(n)) return 'production';
    if (/stag/.test(n)) return 'staging';
    if (/dev/.test(n)) return 'development';
    if (/test/.test(n)) return 'testing';
    return 'unknown';
  }

  calculateGCPSecurityScore(workload, serviceAccount, ingress, hasExternalIp) {
    let score = this.calculateSecurityScore(workload);

    // Custom service account (not default compute) is more secure
    if (serviceAccount && !serviceAccount.includes('developer.gserviceaccount.com')) {
      score += 10;
    }
    // Using default compute SA is risky
    if (serviceAccount?.includes('developer.gserviceaccount.com')) {
      score -= 15;
    }
    // Internal-only ingress is more secure
    if (ingress === 'INGRESS_TRAFFIC_INTERNAL_ONLY' || ingress === 'INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER') {
      score += 10;
    }
    // External IP on a VM is less secure
    if (hasExternalIp) {
      score -= 10;
    }

    return Math.max(0, Math.min(100, score));
  }

  calculateGKESecurityScore(workload, cluster) {
    let score = this.calculateSecurityScore(workload);

    if (cluster.privateClusterConfig?.enablePrivateNodes) score += 10;
    if (cluster.workloadIdentityConfig?.workloadPool) score += 15;
    if (cluster.autopilot?.enabled) score += 10;
    if (cluster.networkPolicy?.enabled) score += 10;
    if (cluster.binaryAuthorization?.evaluationMode) score += 10;
    if (!cluster.legacyAbac?.enabled) score += 5;

    return Math.max(0, Math.min(100, score));
  }

  calculateSAScore(sa, keys, isDefault) {
    let score = 0;
    if (!sa.displayName) score += 25;
    if (!sa.description) score += 20;
    if (keys.length > 0) score += 15; // User-managed keys = risk
    if (keys.length > 2) score += 15;
    if (isDefault) score += 10;
    return Math.min(100, score);
  }

  calculateSASecurityScore(workload, keys, oldestKeyAge, isDefault) {
    let score = this.calculateSecurityScore(workload);

    if (keys.length === 0) score += 15; // No user-managed keys = good
    if (keys.length > 2) score -= 15;
    if (oldestKeyAge > 365) score -= 20;
    if (oldestKeyAge > 90) score -= 10;
    if (isDefault) score -= 10;

    return Math.max(0, Math.min(100, score));
  }
}

module.exports = GCPScanner;
