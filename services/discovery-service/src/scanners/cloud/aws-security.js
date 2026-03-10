// =============================================================================
// AWS Security Scanner - Discovers KMS Keys, Secrets Manager, CloudTrail
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class AWSSecurityScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'aws';
    this.region = config.region || process.env.AWS_DEFAULT_REGION || 'us-east-1';
    this.version = '1.0.0';

    // Only initialize AWS SDK if credentials are available
    this.initialized = false;
  }

  /**
   * Initialize AWS SDK v3 (lazy loading)
   */
  async initializeAWS() {
    if (this.initialized) return;

    try {
      // AWS SDK v3 - import only what we need
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
      const {
        KMSClient,
        ListKeysCommand,
        DescribeKeyCommand,
        GetKeyRotationStatusCommand,
        GetKeyPolicyCommand,
        ListResourceTagsCommand
      } = require('@aws-sdk/client-kms');
      const {
        SecretsManagerClient,
        ListSecretsCommand,
        DescribeSecretCommand
      } = require('@aws-sdk/client-secrets-manager');
      const {
        CloudTrailClient,
        DescribeTrailsCommand,
        GetTrailStatusCommand,
        GetEventSelectorsCommand
      } = require('@aws-sdk/client-cloudtrail');

      // Create clients with region
      const clientConfig = { region: this.region };

      this.stsClient = new STSClient(clientConfig);
      this.kmsClient = new KMSClient(clientConfig);
      this.secretsClient = new SecretsManagerClient(clientConfig);
      this.cloudTrailClient = new CloudTrailClient(clientConfig);

      // Store command classes for later use
      this.STSCommands = { GetCallerIdentityCommand };
      this.KMSCommands = {
        ListKeysCommand,
        DescribeKeyCommand,
        GetKeyRotationStatusCommand,
        GetKeyPolicyCommand,
        ListResourceTagsCommand
      };
      this.SecretsCommands = { ListSecretsCommand, DescribeSecretCommand };
      this.CloudTrailCommands = { DescribeTrailsCommand, GetTrailStatusCommand, GetEventSelectorsCommand };

      this.initialized = true;
      this.log(`AWS Security SDK v3 initialized for region: ${this.region}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize AWS Security SDK v3: ${error.message}`);
    }
  }

  /**
   * Validate AWS configuration
   */
  async validate() {
    try {
      await this.initializeAWS();

      // Test credentials
      const command = new this.STSCommands.GetCallerIdentityCommand({});
      const response = await this.stsClient.send(command);

      this.accountId = response.Account;
      this.log(`Connected to AWS account: ${response.Account}`, 'success');
      return true;
    } catch (error) {
      this.log(`AWS Security validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  /**
   * Get scanner capabilities
   */
  getCapabilities() {
    return ['discover', 'kms', 'secrets-manager', 'cloudtrail'];
  }

  getRequiredCredentials() {
    return [
      { name: 'AWS_ACCESS_KEY_ID', description: 'AWS access key' },
      { name: 'AWS_SECRET_ACCESS_KEY', description: 'AWS secret key' },
      { name: 'AWS_DEFAULT_REGION', description: 'AWS region (e.g. us-east-1)' },
    ];
  }

  /**
   * Main discovery method
   */
  async discover() {
    await this.initializeAWS();

    this.log(`Starting AWS Security discovery in region: ${this.region}`, 'info');

    const workloads = [];

    try {
      // Discover KMS Keys
      const kmsKeys = await this.discoverKMSKeys();
      workloads.push(...kmsKeys);
      this.log(`Found ${kmsKeys.length} customer-managed KMS keys`, 'success');

      // Discover Secrets Manager secrets
      const secrets = await this.discoverSecrets();
      workloads.push(...secrets);
      this.log(`Found ${secrets.length} Secrets Manager secrets`, 'success');

      // Discover CloudTrail trails
      const trails = await this.discoverCloudTrails();
      workloads.push(...trails);
      this.log(`Found ${trails.length} CloudTrail trails`, 'success');

    } catch (error) {
      this.log(`Security discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ==========================================================================
  // KMS Key Scanning
  // ==========================================================================

  async discoverKMSKeys() {
    try {
      // Paginate through all keys using Marker/NextMarker
      const allKeys = await this.paginateAll(
        async (token) => {
          const params = {};
          if (token) params.Marker = token;
          const command = new this.KMSCommands.ListKeysCommand(params);
          return this.kmsClient.send(command);
        },
        'Keys',
        'NextMarker',
        'Marker'
      );

      const workloads = [];

      for (const key of allKeys) {
        try {
          // Describe the key to get full metadata
          const describeCommand = new this.KMSCommands.DescribeKeyCommand({
            KeyId: key.KeyId
          });
          const describeResult = await this.kmsClient.send(describeCommand);
          const keyMeta = describeResult.KeyMetadata;

          // Skip AWS-managed keys — only scan customer-managed
          if (keyMeta.KeyManager === 'AWS') continue;

          // Skip keys that are not enabled
          if (keyMeta.KeyState !== 'Enabled') continue;

          // Get rotation status
          let rotationEnabled = false;
          try {
            const rotationCommand = new this.KMSCommands.GetKeyRotationStatusCommand({
              KeyId: key.KeyId
            });
            const rotationResult = await this.kmsClient.send(rotationCommand);
            rotationEnabled = rotationResult.KeyRotationEnabled === true;
          } catch (rotErr) {
            this.log(`Could not get rotation status for ${key.KeyId}: ${rotErr.message}`, 'warn');
          }

          // Get key policy
          let policyAllowsCrossAccount = false;
          try {
            const policyCommand = new this.KMSCommands.GetKeyPolicyCommand({
              KeyId: key.KeyId,
              PolicyName: 'default'
            });
            const policyResult = await this.kmsClient.send(policyCommand);
            policyAllowsCrossAccount = this._checkCrossAccountAccess(policyResult.Policy, this.accountId);
          } catch (polErr) {
            this.log(`Could not get key policy for ${key.KeyId}: ${polErr.message}`, 'warn');
          }

          // Get tags
          let tags = {};
          try {
            const tagsCommand = new this.KMSCommands.ListResourceTagsCommand({
              KeyId: key.KeyId
            });
            const tagsResult = await this.kmsClient.send(tagsCommand);
            tags = this.parseTags(tagsResult.Tags);
          } catch (tagErr) {
            this.log(`Could not get tags for ${key.KeyId}: ${tagErr.message}`, 'warn');
          }

          const name = tags.Name || keyMeta.Description || key.KeyId;

          const workload = {
            name,
            type: 'kms-key',
            namespace: 'security',
            environment: tags.environment || tags.Environment || 'unknown',

            category: 'encryption-key',
            subcategory: tags.subcategory || null,
            is_ai_agent: false,
            is_mcp_server: false,

            labels: tags,
            metadata: {
              arn: keyMeta.Arn,
              key_id: key.KeyId,
              key_manager: 'CUSTOMER',
              key_state: keyMeta.KeyState,
              key_spec: keyMeta.CustomerMasterKeySpec,
              key_usage: keyMeta.KeyUsage,
              creation_date: keyMeta.CreationDate,
              rotation_enabled: rotationEnabled,
              description: keyMeta.Description || null,
              origin: keyMeta.Origin,
              policy_allows_cross_account: policyAllowsCrossAccount,
              multi_region: keyMeta.MultiRegion === true
            },

            cloud_provider: 'aws',
            region: this.region,
            account_id: this.accountId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `aws://${this.region}`,
            cluster_id: this.region,

            owner: tags.owner || tags.Owner || null,
            team: tags.team || tags.Team || null,
            cost_center: tags.CostCenter || tags['cost-center'] || null,

            is_shadow: this.isShadowService(tags, { name }),
            shadow_score: this.calculateShadowScore(tags, { name }),

            discovered_by: 'aws-security-scanner'
          };

          workload.security_score = this._calculateKMSSecurityScore(workload);
          workloads.push(workload);
        } catch (keyErr) {
          this.log(`Error processing KMS key ${key.KeyId}: ${keyErr.message}`, 'error');
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering KMS keys: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Parse key policy JSON and check for external account ARNs in Principal
   */
  _checkCrossAccountAccess(policyJson, ownAccountId) {
    try {
      const policy = JSON.parse(policyJson);
      const statements = policy.Statement || [];

      for (const stmt of statements) {
        if (stmt.Effect !== 'Allow') continue;

        const principals = this._extractPrincipals(stmt.Principal);
        for (const principal of principals) {
          // Match arn:aws:iam::ACCOUNT_ID: patterns
          const arnMatch = principal.match(/arn:aws:iam::(\d+):/);
          if (arnMatch && arnMatch[1] !== ownAccountId) {
            return true;
          }
          // Check for wildcard principal
          if (principal === '*') {
            return true;
          }
        }
      }

      return false;
    } catch (e) {
      // If we cannot parse the policy, assume safe
      return false;
    }
  }

  /**
   * Extract all principal ARN strings from a policy Principal field
   */
  _extractPrincipals(principal) {
    if (!principal) return [];
    if (typeof principal === 'string') return [principal];
    if (Array.isArray(principal)) return principal;

    // principal is an object like { AWS: [...] } or { Service: [...] }
    const results = [];
    for (const key of Object.keys(principal)) {
      const val = principal[key];
      if (typeof val === 'string') {
        results.push(val);
      } else if (Array.isArray(val)) {
        results.push(...val);
      }
    }
    return results;
  }

  /**
   * KMS-specific security scoring
   */
  _calculateKMSSecurityScore(workload) {
    let score = this.calculateSecurityScore(workload);
    const meta = workload.metadata;

    if (!meta.rotation_enabled) score -= 20;
    if (meta.policy_allows_cross_account) score -= 15;
    if (meta.multi_region) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  // ==========================================================================
  // Secrets Manager Scanning
  // ==========================================================================

  async discoverSecrets() {
    try {
      // Paginate through all secrets using NextToken
      const allSecrets = await this.paginateAll(
        async (token) => {
          const params = {};
          if (token) params.NextToken = token;
          const command = new this.SecretsCommands.ListSecretsCommand(params);
          return this.secretsClient.send(command);
        },
        'SecretList',
        'NextToken',
        'NextToken'
      );

      const workloads = [];

      for (const secret of allSecrets) {
        try {
          // Describe each secret for full metadata
          const describeCommand = new this.SecretsCommands.DescribeSecretCommand({
            SecretId: secret.ARN
          });
          const detail = await this.secretsClient.send(describeCommand);

          const tags = this.parseTags(detail.Tags);
          const name = tags.Name || detail.Name;

          const now = new Date();

          // Calculate days since rotation
          const rotationAnchor = detail.LastRotatedDate || detail.CreatedDate;
          const daysSinceRotation = rotationAnchor
            ? Math.floor((now - new Date(rotationAnchor)) / (1000 * 60 * 60 * 24))
            : null;

          // Calculate days since last access
          const daysSinceAccess = detail.LastAccessedDate
            ? Math.floor((now - new Date(detail.LastAccessedDate)) / (1000 * 60 * 60 * 24))
            : null;

          const isStale = daysSinceRotation !== null && daysSinceRotation > 90;

          const workload = {
            name,
            type: 'managed-secret',
            namespace: 'security',
            environment: tags.environment || tags.Environment || 'unknown',

            category: 'secret',
            subcategory: tags.subcategory || null,
            is_ai_agent: false,
            is_mcp_server: false,

            labels: tags,
            metadata: {
              arn: detail.ARN,
              description: detail.Description || null,
              rotation_enabled: detail.RotationEnabled === true,
              rotation_lambda_arn: detail.RotationLambdaARN || null,
              rotation_rules: detail.RotationRules || null,
              last_rotated: detail.LastRotatedDate || null,
              last_accessed: detail.LastAccessedDate || null,
              last_changed: detail.LastChangedDate || null,
              created_date: detail.CreatedDate || null,
              days_since_rotation: daysSinceRotation,
              days_since_access: daysSinceAccess,
              is_stale: isStale,
              owning_service: detail.OwningService || null,
              primary_region: detail.PrimaryRegion || null,
              replication_status: detail.ReplicationStatus || null
            },

            cloud_provider: 'aws',
            region: this.region,
            account_id: this.accountId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `aws://${this.region}`,
            cluster_id: this.region,

            owner: tags.owner || tags.Owner || null,
            team: tags.team || tags.Team || null,
            cost_center: tags.CostCenter || tags['cost-center'] || null,

            is_shadow: this.isShadowService(tags, { name }),
            shadow_score: this.calculateShadowScore(tags, { name }),

            discovered_by: 'aws-security-scanner'
          };

          workload.security_score = this._calculateSecretSecurityScore(workload);
          workloads.push(workload);
        } catch (secErr) {
          this.log(`Error processing secret ${secret.Name}: ${secErr.message}`, 'error');
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Secrets Manager secrets: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Secrets Manager-specific security scoring
   */
  _calculateSecretSecurityScore(workload) {
    let score = this.calculateSecurityScore(workload);
    const meta = workload.metadata;

    if (!meta.rotation_enabled) score -= 25;
    if (meta.is_stale) score -= 15;
    if (meta.days_since_access !== null && meta.days_since_access > 180) score -= 10;
    if (meta.rotation_enabled && meta.rotation_lambda_arn) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  // ==========================================================================
  // CloudTrail Scanning
  // ==========================================================================

  async discoverCloudTrails() {
    try {
      const describeCommand = new this.CloudTrailCommands.DescribeTrailsCommand({});
      const describeResult = await this.cloudTrailClient.send(describeCommand);
      const trails = describeResult.trailList || [];

      const workloads = [];

      for (const trail of trails) {
        try {
          // Get trail status
          let isLogging = false;
          let latestDeliveryTime = null;
          try {
            const statusCommand = new this.CloudTrailCommands.GetTrailStatusCommand({
              Name: trail.TrailARN
            });
            const statusResult = await this.cloudTrailClient.send(statusCommand);
            isLogging = statusResult.IsLogging === true;
            latestDeliveryTime = statusResult.LatestDeliveryTime || null;
          } catch (statusErr) {
            this.log(`Could not get trail status for ${trail.Name}: ${statusErr.message}`, 'warn');
          }

          // Get event selectors
          let hasManagementEvents = false;
          let hasDataEvents = false;
          let hasInsightSelectors = false;
          try {
            const selectorsCommand = new this.CloudTrailCommands.GetEventSelectorsCommand({
              TrailName: trail.TrailARN
            });
            const selectorsResult = await this.cloudTrailClient.send(selectorsCommand);

            const eventSelectors = selectorsResult.EventSelectors || [];
            for (const selector of eventSelectors) {
              if (selector.IncludeManagementEvents === true) {
                hasManagementEvents = true;
              }
              if (selector.DataResources && selector.DataResources.length > 0) {
                hasDataEvents = true;
              }
            }

            // Advanced event selectors also indicate data events
            const advancedSelectors = selectorsResult.AdvancedEventSelectors || [];
            if (advancedSelectors.length > 0) {
              hasDataEvents = true;
            }

            hasInsightSelectors = Array.isArray(selectorsResult.InsightSelectors) &&
              selectorsResult.InsightSelectors.length > 0;
          } catch (selErr) {
            this.log(`Could not get event selectors for ${trail.Name}: ${selErr.message}`, 'warn');
          }

          const name = trail.Name;

          const workload = {
            name,
            type: 'cloudtrail',
            namespace: 'security',
            environment: 'production',

            category: 'audit-log',
            subcategory: null,
            is_ai_agent: false,
            is_mcp_server: false,

            labels: {},
            metadata: {
              arn: trail.TrailARN,
              trail_name: trail.Name,
              s3_bucket: trail.S3BucketName || null,
              s3_key_prefix: trail.S3KeyPrefix || null,
              is_multi_region: trail.IsMultiRegionTrail === true,
              is_organization_trail: trail.IsOrganizationTrail === true,
              log_file_validation: trail.LogFileValidationEnabled === true,
              cloud_watch_logs_arn: trail.CloudWatchLogsLogGroupArn || null,
              kms_key_id: trail.KmsKeyId || null,
              is_logging: isLogging,
              latest_delivery_time: latestDeliveryTime,
              has_management_events: hasManagementEvents,
              has_data_events: hasDataEvents,
              has_insight_selectors: hasInsightSelectors,
              home_region: trail.HomeRegion || null
            },

            cloud_provider: 'aws',
            region: this.region,
            account_id: this.accountId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `aws://${this.region}`,
            cluster_id: this.region,

            owner: null,
            team: null,
            cost_center: null,

            is_shadow: false,
            shadow_score: 0,

            discovered_by: 'aws-security-scanner'
          };

          workload.security_score = this._calculateCloudTrailSecurityScore(workload);
          workloads.push(workload);
        } catch (trailErr) {
          this.log(`Error processing trail ${trail.Name}: ${trailErr.message}`, 'error');
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering CloudTrail trails: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * CloudTrail-specific security scoring
   */
  _calculateCloudTrailSecurityScore(workload) {
    let score = this.calculateSecurityScore(workload);
    const meta = workload.metadata;

    if (meta.is_multi_region) score += 15;
    if (meta.log_file_validation) score += 10;
    if (meta.cloud_watch_logs_arn) score += 10;
    if (!meta.is_logging) score -= 20;
    if (!meta.kms_key_id) score -= 10;
    if (meta.is_organization_trail) score += 5;

    return Math.max(0, Math.min(100, score));
  }
}

module.exports = AWSSecurityScanner;
