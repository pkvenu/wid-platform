// =============================================================================
// Azure Scanner - Discovers workloads from Microsoft Azure
// =============================================================================
// Scans for:
// 1. Virtual Machines
// 2. Container Instances (ACI)
// 3. App Service / Web Apps
// 4. Azure Functions
// 5. AKS clusters
// 6. Managed Identities
// 7. Storage Accounts
// 8. Azure SQL Servers
// 9. Network Security Groups (NSGs)
// 10. Key Vaults
// 11. Role Assignments (privilege accumulation)
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class AzureScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'azure';
    this.version = '1.0.0';
    this.subscriptionId = config.subscriptionId || process.env.AZURE_SUBSCRIPTION_ID;
    this.resourceGroup = config.resourceGroup || process.env.AZURE_RESOURCE_GROUP;
    this.initialized = false;

    if (!this.subscriptionId) {
      this.enabled = false;
      this.disabledReason = 'Requires AZURE_SUBSCRIPTION_ID + Azure credentials (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)';
    }
  }

  getRequiredCredentials() {
    return [
      { name: 'AZURE_SUBSCRIPTION_ID', description: 'Azure subscription ID' },
      { name: 'AZURE_CLIENT_ID', description: 'Azure AD app client ID' },
      { name: 'AZURE_TENANT_ID', description: 'Azure AD tenant ID' },
      { name: 'AZURE_CLIENT_SECRET', description: 'Azure AD app client secret' },
      { name: 'AZURE_RESOURCE_GROUP', description: 'Resource group to scope (optional)' },
    ];
  }

  async initializeAzure() {
    if (this.initialized) return;

    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { ComputeManagementClient } = require('@azure/arm-compute');
      const { ContainerInstanceManagementClient } = require('@azure/arm-containerinstance');
      const { WebSiteManagementClient } = require('@azure/arm-appservice');
      const { ContainerServiceClient } = require('@azure/arm-containerservice');
      const { ManagedServiceIdentityClient } = require('@azure/arm-msi');
      const { StorageManagementClient } = require('@azure/arm-storage');
      const { SqlManagementClient } = require('@azure/arm-sql');
      const { NetworkManagementClient } = require('@azure/arm-network');
      const { KeyVaultManagementClient } = require('@azure/arm-keyvault');
      const { AuthorizationManagementClient } = require('@azure/arm-authorization');

      this.credential = new DefaultAzureCredential();
      this.computeClient = new ComputeManagementClient(this.credential, this.subscriptionId);
      this.containerClient = new ContainerInstanceManagementClient(this.credential, this.subscriptionId);
      this.webClient = new WebSiteManagementClient(this.credential, this.subscriptionId);
      this.aksClient = new ContainerServiceClient(this.credential, this.subscriptionId);
      this.msiClient = new ManagedServiceIdentityClient(this.credential, this.subscriptionId);
      this.storageClient = new StorageManagementClient(this.credential, this.subscriptionId);
      this.sqlClient = new SqlManagementClient(this.credential, this.subscriptionId);
      this.networkClient = new NetworkManagementClient(this.credential, this.subscriptionId);
      this.keyVaultClient = new KeyVaultManagementClient(this.credential, this.subscriptionId);
      this.authClient = new AuthorizationManagementClient(this.credential, this.subscriptionId);

      this.initialized = true;
      this.log(`Azure SDK initialized for subscription: ${this.subscriptionId}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize Azure SDK: ${error.message}`);
    }
  }

  async validate() {
    if (!this.subscriptionId) {
      this.log('AZURE_SUBSCRIPTION_ID not set', 'error');
      return false;
    }
    try {
      await this.initializeAzure();
      this.log(`Connected to Azure subscription: ${this.subscriptionId}`, 'success');
      return true;
    } catch (error) {
      this.log(`Azure validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'vm', 'container-instances', 'app-service', 'functions', 'aks', 'managed-identities', 'storage-accounts', 'azure-sql', 'nsgs', 'key-vaults', 'role-assignments'];
  }

  async discover() {
    await this.initializeAzure();

    this.log(`Starting Azure discovery in subscription: ${this.subscriptionId}`, 'info');
    const workloads = [];

    try {
      const vms = await this.discoverVirtualMachines();
      workloads.push(...vms);
      this.log(`Found ${vms.length} Virtual Machines`, 'success');

      const containers = await this.discoverContainerInstances();
      workloads.push(...containers);
      this.log(`Found ${containers.length} Container Instances`, 'success');

      const webApps = await this.discoverAppService();
      workloads.push(...webApps);
      this.log(`Found ${webApps.length} App Service apps`, 'success');

      const aksClusters = await this.discoverAKS();
      workloads.push(...aksClusters);
      this.log(`Found ${aksClusters.length} AKS clusters`, 'success');

      const identities = await this.discoverManagedIdentities();
      workloads.push(...identities);
      this.log(`Found ${identities.length} Managed Identities`, 'success');

      const storageAccounts = await this.discoverStorageAccounts();
      workloads.push(...storageAccounts);
      this.log(`Found ${storageAccounts.length} Storage Accounts`, 'success');

      const sqlServers = await this.discoverSQLServers();
      workloads.push(...sqlServers);
      this.log(`Found ${sqlServers.length} SQL Servers/DBs`, 'success');

      const nsgs = await this.discoverNSGs();
      workloads.push(...nsgs);
      this.log(`Found ${nsgs.length} Network Security Groups`, 'success');

      const keyVaults = await this.discoverKeyVaults();
      workloads.push(...keyVaults);
      this.log(`Found ${keyVaults.length} Key Vaults`, 'success');

      const roleAssignments = await this.discoverRoleAssignments();
      workloads.push(...roleAssignments);
      this.log(`Found ${roleAssignments.length} Role Assignments`, 'success');

    } catch (error) {
      this.log(`Discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ═══════════════════════════════════════════════════════════════
  // Virtual Machines
  // ═══════════════════════════════════════════════════════════════

  async discoverVirtualMachines() {
    try {
      const workloads = [];

      for await (const vm of this.computeClient.virtualMachines.listAll()) {
        const tags = vm.tags || {};
        const name = vm.name;
        const location = vm.location;
        const rg = vm.id?.split('/')[4] || this.resourceGroup;

        const hasIdentity = !!vm.identity;
        const identityType = vm.identity?.type || 'None';

        const workload = {
          name,
          type: 'azure-vm',
          namespace: tags.namespace || rg || 'compute',
          environment: this.inferEnvironment(name, tags),

          category: this.categorizeWorkload(tags, { name }),
          subcategory: this.determineSubcategory(tags, { name }),
          is_ai_agent: this.isAIAgent(tags, { name }),
          is_mcp_server: this.isMCPServer(tags, { name }),

          labels: tags,
          metadata: {
            resource_id: vm.id,
            resource_group: rg,
            vm_size: vm.hardwareProfile?.vmSize,
            location,
            os_type: vm.storageProfile?.osDisk?.osType,
            os_image: vm.storageProfile?.imageReference?.offer || null,
            provisioning_state: vm.provisioningState,
            has_managed_identity: hasIdentity,
            identity_type: identityType,
            availability_set: vm.availabilitySet?.id?.split('/').pop() || null,
            network_interfaces: (vm.networkProfile?.networkInterfaces || []).map(
              ni => ni.id?.split('/').pop()
            ),
          },

          cloud_provider: 'azure',
          region: location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: vm.provisioningState === 'Succeeded' ? 'active' : 'pending',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateAzureSecurityScore(workload, hasIdentity, identityType);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering VMs: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Container Instances
  // ═══════════════════════════════════════════════════════════════

  async discoverContainerInstances() {
    try {
      const workloads = [];

      for await (const group of this.containerClient.containerGroups.list()) {
        const tags = group.tags || {};
        const rg = group.id?.split('/')[4] || this.resourceGroup;

        for (const container of group.containers || []) {
          const name = container.name;

          const workload = {
            name,
            type: 'azure-container-instance',
            namespace: tags.namespace || rg || 'aci',
            environment: this.inferEnvironment(name, tags),

            category: this.categorizeWorkload(tags, { name }),
            subcategory: this.determineSubcategory(tags, { name }),
            is_ai_agent: this.isAIAgent(tags, { name }),
            is_mcp_server: this.isMCPServer(tags, { name }),

            labels: tags,
            metadata: {
              resource_id: group.id,
              resource_group: rg,
              group_name: group.name,
              image: container.image,
              cpu: container.resources?.requests?.cpu,
              memory_gb: container.resources?.requests?.memoryInGB,
              location: group.location,
              os_type: group.osType,
              ip_address: group.ipAddress?.ip || null,
              restart_policy: group.restartPolicy,
              provisioning_state: group.provisioningState,
              ports: (container.ports || []).map(p => p.port),
            },

            cloud_provider: 'azure',
            region: group.location,
            account_id: this.subscriptionId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `azure://${this.subscriptionId}`,
            cluster_id: this.subscriptionId,

            owner: tags.owner || tags.Owner || null,
            team: tags.team || tags.Team || null,
            cost_center: tags.CostCenter || tags['cost-center'] || null,

            is_shadow: this.isShadowService(tags, { name }),
            shadow_score: this.calculateShadowScore(tags, { name }),

            status: group.provisioningState === 'Succeeded' ? 'active' : 'pending',
            discovered_by: 'azure-scanner'
          };

          workload.security_score = this.calculateSecurityScore(workload);
          workloads.push(workload);
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Container Instances: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // App Service / Web Apps
  // ═══════════════════════════════════════════════════════════════

  async discoverAppService() {
    try {
      const workloads = [];

      for await (const app of this.webClient.webApps.list()) {
        const tags = app.tags || {};
        const name = app.name;
        const rg = app.id?.split('/')[4] || this.resourceGroup;
        const kind = app.kind || ''; // 'app', 'functionapp', 'app,linux'

        const isFunctionApp = kind.includes('functionapp');
        const hasIdentity = !!app.identity;

        const workload = {
          name,
          type: isFunctionApp ? 'azure-function' : 'azure-app-service',
          namespace: tags.namespace || rg || 'app-service',
          environment: this.inferEnvironment(name, tags),

          category: this.categorizeWorkload(tags, { name }),
          subcategory: isFunctionApp ? 'function-app' : (kind.includes('linux') ? 'linux-web-app' : 'windows-web-app'),
          is_ai_agent: this.isAIAgent(tags, { name }),
          is_mcp_server: this.isMCPServer(tags, { name }),

          labels: tags,
          metadata: {
            resource_id: app.id,
            resource_group: rg,
            kind,
            location: app.location,
            state: app.state,
            default_hostname: app.defaultHostName,
            https_only: app.httpsOnly || false,
            has_managed_identity: hasIdentity,
            identity_type: app.identity?.type || 'None',
            client_cert_enabled: app.clientCertEnabled || false,
            enabled: app.enabled,
            sku: app.sku?.name || null,
          },

          cloud_provider: 'azure',
          region: app.location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: app.state === 'Running' ? 'active' : 'inactive',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateAppServiceScore(workload, app);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering App Service: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // AKS
  // ═══════════════════════════════════════════════════════════════

  async discoverAKS() {
    try {
      const workloads = [];

      for await (const cluster of this.aksClient.managedClusters.list()) {
        const tags = cluster.tags || {};
        const name = cluster.name;
        const rg = cluster.id?.split('/')[4] || this.resourceGroup;

        const workload = {
          name,
          type: 'aks-cluster',
          namespace: tags.namespace || rg || 'aks',
          environment: this.inferEnvironment(name, tags),

          category: 'kubernetes-cluster',
          subcategory: 'aks',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: cluster.id,
            resource_group: rg,
            location: cluster.location,
            kubernetes_version: cluster.kubernetesVersion,
            provisioning_state: cluster.provisioningState,
            power_state: cluster.powerState?.code,
            node_count: (cluster.agentPoolProfiles || []).reduce((sum, p) => sum + (p.count || 0), 0),
            node_pools: (cluster.agentPoolProfiles || []).map(p => ({
              name: p.name, count: p.count, vm_size: p.vmSize, mode: p.mode,
            })),
            fqdn: cluster.fqdn,
            network_plugin: cluster.networkProfile?.networkPlugin,
            network_policy: cluster.networkProfile?.networkPolicy || 'none',
            private_cluster: cluster.apiServerAccessProfile?.enablePrivateCluster || false,
            rbac_enabled: cluster.enableRBAC !== false,
            aad_enabled: !!cluster.aadProfile,
            workload_identity: cluster.oidcIssuerProfile?.enabled || false,
          },

          cloud_provider: 'azure',
          region: cluster.location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: cluster.name,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: cluster.provisioningState === 'Succeeded' ? 'active' : 'pending',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateAKSSecurityScore(workload, cluster);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering AKS: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Managed Identities
  // ═══════════════════════════════════════════════════════════════

  async discoverManagedIdentities() {
    try {
      const workloads = [];

      for await (const identity of this.msiClient.userAssignedIdentities.listBySubscription()) {
        const tags = identity.tags || {};
        const name = identity.name;
        const rg = identity.id?.split('/')[4] || this.resourceGroup;

        const workload = {
          name,
          type: 'managed-identity',
          namespace: tags.namespace || rg || 'iam',
          environment: this.inferEnvironment(name, tags),

          category: 'service-account',
          subcategory: 'user-assigned-managed-identity',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: identity.id,
            resource_group: rg,
            location: identity.location,
            client_id: identity.clientId,
            principal_id: identity.principalId,
            tenant_id: identity.tenantId,
          },

          cloud_provider: 'azure',
          region: identity.location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: 'active',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Managed Identities: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Storage Accounts
  // ═══════════════════════════════════════════════════════════════

  async discoverStorageAccounts() {
    try {
      const workloads = [];

      for await (const account of this.storageClient.storageAccounts.list()) {
        const tags = account.tags || {};
        const name = account.name;
        const location = account.location;
        const rg = account.id?.split('/')[4] || this.resourceGroup;

        const allowBlobPublicAccess = account.allowBlobPublicAccess || false;
        const httpsOnly = account.enableHttpsTrafficOnly !== false;
        const networkDefaultAction = account.networkRuleSet?.defaultAction || 'Allow';
        const minimumTlsVersion = account.minimumTlsVersion || 'TLS1_0';
        const allowSharedKeyAccess = account.allowSharedKeyAccess !== false;
        const encryptionServices = account.encryption?.services || {};
        const hasPrivateEndpoints = (account.privateEndpointConnections?.length || 0) > 0;

        const workload = {
          name,
          type: 'storage-account',
          namespace: tags.namespace || rg || 'storage',
          environment: this.inferEnvironment(name, tags),

          category: 'data-store',
          subcategory: 'storage-account',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: account.id,
            resource_group: rg,
            location,
            kind: account.kind,
            sku_name: account.sku?.name,
            access_tier: account.accessTier,
            https_only: httpsOnly,
            minimum_tls_version: minimumTlsVersion,
            allow_blob_public_access: allowBlobPublicAccess,
            allow_shared_key_access: allowSharedKeyAccess,
            network_default_action: networkDefaultAction,
            encryption_services: {
              blob: encryptionServices.blob?.enabled || false,
              file: encryptionServices.file?.enabled || false,
              table: encryptionServices.table?.enabled || false,
              queue: encryptionServices.queue?.enabled || false,
            },
            has_private_endpoints: hasPrivateEndpoints,
            creation_time: account.creationTime,
          },

          cloud_provider: 'azure',
          region: location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: 'active',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateStorageAccountScore(workload, {
          allowBlobPublicAccess,
          httpsOnly,
          networkDefaultAction,
          minimumTlsVersion,
          allowSharedKeyAccess,
        });
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Storage Accounts: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // SQL Servers
  // ═══════════════════════════════════════════════════════════════

  async discoverSQLServers() {
    try {
      const workloads = [];

      for await (const server of this.sqlClient.servers.list()) {
        const tags = server.tags || {};
        const name = server.name;
        const location = server.location;
        const rg = server.id?.split('/')[4] || this.resourceGroup;

        // List databases for this server
        let databases = [];
        try {
          for await (const db of this.sqlClient.databases.listByServer(rg, server.name)) {
            databases.push({
              name: db.name,
              status: db.status,
              max_size_bytes: db.maxSizeBytes,
              creation_date: db.creationDate,
              earliest_restore_date: db.earliestRestoreDate,
            });
          }
        } catch (dbError) {
          this.log(`Error listing databases for SQL server ${name}: ${dbError.message}`, 'warn');
        }

        const publicNetworkAccess = server.publicNetworkAccess || 'Enabled';
        const minimumTlsVersion = server.minimumTlsVersion || '1.0';

        const workload = {
          name,
          type: 'azure-sql',
          namespace: tags.namespace || rg || 'database',
          environment: this.inferEnvironment(name, tags),

          category: 'data-store',
          subcategory: 'azure-sql',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: server.id,
            resource_group: rg,
            location,
            fqdn: server.fullyQualifiedDomainName,
            state: server.state,
            version: server.version,
            admin_login: server.administratorLogin,
            public_network_access: publicNetworkAccess,
            minimum_tls_version: minimumTlsVersion,
            databases,
            database_count: databases.length,
          },

          cloud_provider: 'azure',
          region: location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: server.state === 'Ready' ? 'active' : 'pending',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateSQLServerScore(workload, {
          publicNetworkAccess,
          minimumTlsVersion,
          databaseCount: databases.length,
        });
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering SQL Servers: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Network Security Groups (NSGs)
  // ═══════════════════════════════════════════════════════════════

  async discoverNSGs() {
    try {
      const workloads = [];

      for await (const nsg of this.networkClient.networkSecurityGroups.listAll()) {
        const tags = nsg.tags || {};
        const name = nsg.name;
        const location = nsg.location;
        const rg = nsg.id?.split('/')[4] || this.resourceGroup;

        const securityRules = (nsg.securityRules || []).map(rule => ({
          name: rule.name,
          priority: rule.priority,
          direction: rule.direction,
          access: rule.access,
          protocol: rule.protocol,
          source_address_prefix: rule.sourceAddressPrefix,
          destination_address_prefix: rule.destinationAddressPrefix,
          source_port_range: rule.sourcePortRange,
          destination_port_range: rule.destinationPortRange,
        }));

        // Detect public ingress rules
        const publicIngressRules = securityRules.filter(r =>
          r.direction === 'Inbound' &&
          r.access === 'Allow' &&
          (r.source_address_prefix === '*' || r.source_address_prefix === 'Internet')
        );
        const allowsPublicIngress = publicIngressRules.length > 0;
        const publicPorts = publicIngressRules.map(r => r.destination_port_range).filter(Boolean);

        const associatedSubnets = (nsg.subnets || []).map(s => s.id?.split('/').pop());
        const associatedNics = (nsg.networkInterfaces || []).map(n => n.id?.split('/').pop());

        // Check for SSH (22) or RDP (3389) from public
        const allowsSshRdpPublic = publicIngressRules.some(r =>
          r.destination_port_range === '22' ||
          r.destination_port_range === '3389' ||
          r.destination_port_range === '*'
        );

        // Check if allows all inbound from *
        const allowsAllInbound = publicIngressRules.some(r =>
          r.destination_port_range === '*' && r.source_address_prefix === '*'
        );

        const workload = {
          name,
          type: 'nsg',
          namespace: tags.namespace || rg || 'network',
          environment: this.inferEnvironment(name, tags),

          category: 'network-policy',
          subcategory: 'nsg',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: nsg.id,
            resource_group: rg,
            location,
            security_rules: securityRules,
            allows_public_ingress: allowsPublicIngress,
            public_ports: publicPorts,
            associated_subnets: associatedSubnets,
            associated_nics: associatedNics,
            rule_count: securityRules.length,
          },

          cloud_provider: 'azure',
          region: location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: 'active',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateNSGSecurityScore(workload, {
          allowsAllInbound,
          allowsSshRdpPublic,
          allowsPublicIngress,
        });
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering NSGs: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Key Vaults
  // ═══════════════════════════════════════════════════════════════

  async discoverKeyVaults() {
    try {
      const workloads = [];

      for await (const vault of this.keyVaultClient.vaults.listBySubscription()) {
        const tags = vault.tags || {};
        const name = vault.name;
        const location = vault.location;
        const rg = vault.id?.split('/')[4] || this.resourceGroup;

        const props = vault.properties || {};
        const rbacAuthorization = props.enableRbacAuthorization || false;
        const purgeProtection = props.enablePurgeProtection || false;
        const softDelete = props.enableSoftDelete !== false;
        const networkDefaultAction = props.networkAcls?.defaultAction || 'Allow';
        const skuName = props.sku?.name || 'standard';
        const hasPrivateEndpoints = (props.privateEndpointConnections?.length || 0) > 0;

        const workload = {
          name,
          type: 'key-vault',
          namespace: tags.namespace || rg || 'security',
          environment: this.inferEnvironment(name, tags),

          category: 'encryption',
          subcategory: 'key-vault',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            resource_id: vault.id,
            resource_group: rg,
            location,
            vault_uri: props.vaultUri,
            sku: skuName,
            soft_delete_enabled: softDelete,
            purge_protection_enabled: purgeProtection,
            rbac_authorization: rbacAuthorization,
            network_default_action: networkDefaultAction,
            has_private_endpoints: hasPrivateEndpoints,
            tenant_id: props.tenantId,
          },

          cloud_provider: 'azure',
          region: location,
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name }),
          shadow_score: this.calculateShadowScore(tags, { name }),

          status: 'active',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateKeyVaultSecurityScore(workload, {
          rbacAuthorization,
          purgeProtection,
          softDelete,
          networkDefaultAction,
          skuName,
        });
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Key Vaults: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Role Assignments (privilege accumulation analysis)
  // ═══════════════════════════════════════════════════════════════

  async discoverRoleAssignments() {
    try {
      const workloads = [];
      const principalMap = new Map();

      // Collect all role assignments grouped by principalId
      for await (const assignment of this.authClient.roleAssignments.listForSubscription()) {
        const principalId = assignment.principalId;
        if (!principalId) continue;

        if (!principalMap.has(principalId)) {
          principalMap.set(principalId, {
            principalType: assignment.principalType || 'Unknown',
            assignments: [],
          });
        }

        principalMap.get(principalId).assignments.push({
          role_definition_id: assignment.roleDefinitionId,
          scope: assignment.scope,
          created_on: assignment.createdOn,
        });
      }

      // Known built-in role definition ID suffixes for Owner and Contributor
      const ownerRoleSuffix = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';
      const contributorRoleSuffix = 'b24988ac-6180-42a0-ab88-20f7382dd24c';
      const readerRoleSuffix = 'acdd72a7-3385-48ef-bd42-f606fba81ae7';
      const subscriptionScope = `/subscriptions/${this.subscriptionId}`;

      // Only emit workloads for principals with 2+ assignments
      for (const [principalId, data] of principalMap.entries()) {
        if (data.assignments.length < 2) continue;

        const roleDefinitionIds = data.assignments.map(a => a.role_definition_id);
        const scopes = [...new Set(data.assignments.map(a => a.scope))];
        const hasSubscriptionScope = data.assignments.some(a =>
          a.scope === subscriptionScope || a.scope === '/'
        );

        const isOwnerOrContributor = roleDefinitionIds.some(id =>
          id?.endsWith(ownerRoleSuffix) || id?.endsWith(contributorRoleSuffix)
        );

        const allReader = roleDefinitionIds.every(id => id?.endsWith(readerRoleSuffix));

        const name = `principal-${principalId.substring(0, 8)}`;

        const workload = {
          name,
          type: 'role-assignment',
          namespace: 'iam',
          environment: 'production',

          category: 'permission',
          subcategory: 'role-assignment',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            principal_id: principalId,
            principal_type: data.principalType,
            role_definition_ids: roleDefinitionIds,
            scope_count: scopes.length,
            assignments: data.assignments,
            assignment_count: data.assignments.length,
            has_subscription_scope: hasSubscriptionScope,
            is_owner_or_contributor: isOwnerOrContributor,
          },

          cloud_provider: 'azure',
          region: 'global',
          account_id: this.subscriptionId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure://${this.subscriptionId}`,
          cluster_id: this.subscriptionId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: false,
          shadow_score: 0,

          status: 'active',
          discovered_by: 'azure-scanner'
        };

        workload.security_score = this.calculateRoleAssignmentScore(workload, {
          assignmentCount: data.assignments.length,
          hasSubscriptionScope,
          isOwnerOrContributor,
          allReader,
        });
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Role Assignments: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════

  inferEnvironment(name, tags) {
    if (tags.environment) return tags.environment;
    if (tags.Environment) return tags.Environment;
    if (tags.env) return tags.env;
    const n = (name || '').toLowerCase();
    if (/prod/.test(n)) return 'production';
    if (/stag/.test(n)) return 'staging';
    if (/dev/.test(n)) return 'development';
    if (/test/.test(n)) return 'testing';
    return 'unknown';
  }

  calculateAzureSecurityScore(workload, hasIdentity, identityType) {
    let score = this.calculateSecurityScore(workload);

    if (hasIdentity) score += 15;
    if (identityType === 'SystemAssigned' || identityType === 'SystemAssigned, UserAssigned') score += 5;
    if (!hasIdentity) score -= 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateAppServiceScore(workload, app) {
    let score = this.calculateSecurityScore(workload);

    if (app.httpsOnly) score += 10;
    if (app.clientCertEnabled) score += 10;
    if (app.identity) score += 10;
    if (!app.httpsOnly) score -= 15;

    return Math.max(0, Math.min(100, score));
  }

  calculateAKSSecurityScore(workload, cluster) {
    let score = this.calculateSecurityScore(workload);

    if (cluster.enableRBAC !== false) score += 10;
    if (cluster.aadProfile) score += 10;
    if (cluster.apiServerAccessProfile?.enablePrivateCluster) score += 10;
    if (cluster.networkProfile?.networkPolicy && cluster.networkProfile.networkPolicy !== 'none') score += 10;
    if (cluster.oidcIssuerProfile?.enabled) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateStorageAccountScore(workload, opts) {
    let score = this.calculateSecurityScore(workload);

    if (opts.allowBlobPublicAccess) score -= 20;
    if (!opts.httpsOnly) score -= 15;
    if (opts.networkDefaultAction === 'Allow') score -= 10;
    if (opts.minimumTlsVersion >= 'TLS1_2') score += 10;
    if (opts.allowSharedKeyAccess) score -= 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateSQLServerScore(workload, opts) {
    let score = this.calculateSecurityScore(workload);

    if (opts.publicNetworkAccess === 'Enabled') score -= 20;
    if (opts.minimumTlsVersion >= '1.2') score += 10;
    if (opts.databaseCount === 0) score -= 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateNSGSecurityScore(workload, opts) {
    let score = this.calculateSecurityScore(workload);

    if (opts.allowsAllInbound) score -= 25;
    if (opts.allowsSshRdpPublic) score -= 15;
    if (!opts.allowsPublicIngress) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateKeyVaultSecurityScore(workload, opts) {
    let score = this.calculateSecurityScore(workload);

    if (opts.rbacAuthorization) score += 10;
    if (!opts.purgeProtection) score -= 15;
    if (opts.networkDefaultAction === 'Allow') score -= 10;
    if (opts.skuName === 'premium') score += 10;
    if (opts.softDelete) score += 5;

    return Math.max(0, Math.min(100, score));
  }

  calculateRoleAssignmentScore(workload, opts) {
    let score = this.calculateSecurityScore(workload);

    if (opts.assignmentCount > 5) score -= 20;
    if (opts.hasSubscriptionScope && opts.isOwnerOrContributor) score -= 15;
    if (opts.allReader) score += 10;

    return Math.max(0, Math.min(100, score));
  }
}

module.exports = AzureScanner;
