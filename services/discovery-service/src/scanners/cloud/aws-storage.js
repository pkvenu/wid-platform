// =============================================================================
// AWS Storage Scanner - Discovers S3, RDS, and DynamoDB workloads (SDK v3)
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class AWSStorageScanner extends BaseScanner {
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
        S3Client,
        ListBucketsCommand,
        GetBucketPolicyCommand,
        GetBucketAclCommand,
        GetPublicAccessBlockCommand,
        GetBucketEncryptionCommand,
        GetBucketVersioningCommand,
        GetBucketLoggingCommand,
        GetBucketTaggingCommand,
        GetBucketLocationCommand
      } = require('@aws-sdk/client-s3');
      const {
        RDSClient,
        DescribeDBInstancesCommand,
        DescribeDBClustersCommand,
        ListTagsForResourceCommand
      } = require('@aws-sdk/client-rds');
      const {
        DynamoDBClient,
        ListTablesCommand,
        DescribeTableCommand,
        DescribeContinuousBackupsCommand,
        ListTagsOfResourceCommand
      } = require('@aws-sdk/client-dynamodb');

      // Create clients with region
      const clientConfig = { region: this.region };

      this.stsClient = new STSClient(clientConfig);
      this.s3Client = new S3Client(clientConfig);
      this.rdsClient = new RDSClient(clientConfig);
      this.dynamoClient = new DynamoDBClient(clientConfig);

      // Store command classes for later use
      this.STSCommands = { GetCallerIdentityCommand };
      this.S3Commands = {
        ListBucketsCommand,
        GetBucketPolicyCommand,
        GetBucketAclCommand,
        GetPublicAccessBlockCommand,
        GetBucketEncryptionCommand,
        GetBucketVersioningCommand,
        GetBucketLoggingCommand,
        GetBucketTaggingCommand,
        GetBucketLocationCommand
      };
      this.RDSCommands = {
        DescribeDBInstancesCommand,
        DescribeDBClustersCommand,
        ListTagsForResourceCommand
      };
      this.DynamoCommands = {
        ListTablesCommand,
        DescribeTableCommand,
        DescribeContinuousBackupsCommand,
        ListTagsOfResourceCommand
      };

      this.initialized = true;
      this.log(`AWS Storage SDK v3 initialized for region: ${this.region}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize AWS Storage SDK v3: ${error.message}`);
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
      this.log(`AWS Storage validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  /**
   * Get scanner capabilities
   */
  getCapabilities() {
    return ['discover', 's3', 'rds', 'dynamodb'];
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

    this.log(`Starting AWS Storage discovery in region: ${this.region}`, 'info');

    const workloads = [];

    try {
      // Discover S3 buckets
      const s3 = await this.discoverS3Buckets();
      workloads.push(...s3);
      this.log(`Found ${s3.length} S3 buckets`, 'success');

      // Discover RDS instances and clusters
      const rds = await this.discoverRDSInstances();
      workloads.push(...rds);
      this.log(`Found ${rds.length} RDS instances/clusters`, 'success');

      // Discover DynamoDB tables
      const dynamo = await this.discoverDynamoDBTables();
      workloads.push(...dynamo);
      this.log(`Found ${dynamo.length} DynamoDB tables`, 'success');

    } catch (error) {
      this.log(`Storage discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ==========================================================================
  // S3 SCANNING
  // ==========================================================================

  async discoverS3Buckets() {
    try {
      const listCommand = new this.S3Commands.ListBucketsCommand({});
      const result = await this.s3Client.send(listCommand);
      const workloads = [];
      const ownerAccount = result.Owner?.ID || this.accountId || 'unknown';

      for (const bucket of result.Buckets || []) {
        const bucketName = bucket.Name;

        // Gather bucket details — each call individually try/caught
        // since some configurations may not be set
        const bucketRegion = await this._getBucketRegion(bucketName);
        const policy = await this._getBucketPolicy(bucketName);
        const acl = await this._getBucketAcl(bucketName);
        const publicAccessBlock = await this._getPublicAccessBlock(bucketName);
        const encryption = await this._getBucketEncryption(bucketName);
        const versioning = await this._getBucketVersioning(bucketName);
        const logging = await this._getBucketLogging(bucketName);
        const tags = await this._getBucketTagging(bucketName);

        const policyAllowsAnonymous = this._policyAllowsAnonymous(policy);
        const policyAllowsCrossAccount = this._policyAllowsCrossAccount(policy, ownerAccount);
        const aclGrantsPublic = this._aclGrantsPublic(acl);

        const isPublic = policyAllowsAnonymous || aclGrantsPublic ||
          !(publicAccessBlock?.BlockPublicAcls && publicAccessBlock?.IgnorePublicAcls &&
            publicAccessBlock?.BlockPublicPolicy && publicAccessBlock?.RestrictPublicBuckets);

        const versioningEnabled = versioning?.Status === 'Enabled';
        const loggingEnabled = !!(logging?.LoggingEnabled);
        const loggingTargetBucket = logging?.LoggingEnabled?.TargetBucket || null;

        const encryptionInfo = this._parseEncryption(encryption);

        const workload = {
          name: bucketName,
          type: 's3-bucket',
          namespace: 'storage',
          environment: tags.environment || tags.Environment || 'unknown',

          category: 'data-store',
          subcategory: this.determineSubcategory(tags, { name: bucketName }),
          is_ai_agent: this.isAIAgent(tags, { name: bucketName }),
          is_mcp_server: this.isMCPServer(tags, { name: bucketName }),

          labels: tags,
          metadata: {
            arn: `arn:aws:s3:::${bucketName}`,
            creation_date: bucket.CreationDate,
            bucket_region: bucketRegion,
            is_public: isPublic,
            public_access_block: publicAccessBlock ? {
              BlockPublicAcls: publicAccessBlock.BlockPublicAcls || false,
              IgnorePublicAcls: publicAccessBlock.IgnorePublicAcls || false,
              BlockPublicPolicy: publicAccessBlock.BlockPublicPolicy || false,
              RestrictPublicBuckets: publicAccessBlock.RestrictPublicBuckets || false
            } : null,
            encryption: encryptionInfo,
            versioning_enabled: versioningEnabled,
            logging_enabled: loggingEnabled,
            logging_target_bucket: loggingTargetBucket,
            policy_allows_cross_account: policyAllowsCrossAccount,
            policy_allows_anonymous: policyAllowsAnonymous,
            acl_grants_public: aclGrantsPublic,
            credentials: []
          },

          cloud_provider: 'aws',
          region: bucketRegion || this.region,
          account_id: this.accountId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `aws://${bucketRegion || this.region}`,
          cluster_id: bucketRegion || this.region,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name: bucketName }),
          shadow_score: this.calculateShadowScore(tags, { name: bucketName }),

          discovered_by: 'aws-storage-scanner'
        };

        workload.security_score = this.calculateStorageSecurityScore(workload, {
          is_public: isPublic,
          has_encryption: !!encryptionInfo.SSEAlgorithm,
          versioning_enabled: versioningEnabled,
          logging_enabled: loggingEnabled,
          policy_allows_anonymous: policyAllowsAnonymous
        });

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering S3 buckets: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Get the region for a bucket
   */
  async _getBucketRegion(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketLocationCommand({ Bucket: bucketName });
      const result = await this.throttledCall(() => this.s3Client.send(command));
      // LocationConstraint is null/empty for us-east-1
      return result.LocationConstraint || 'us-east-1';
    } catch (error) {
      this.log(`Could not get region for bucket ${bucketName}: ${error.message}`, 'warn');
      return null;
    }
  }

  /**
   * Get bucket policy (parsed JSON)
   */
  async _getBucketPolicy(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketPolicyCommand({ Bucket: bucketName });
      const result = await this.throttledCall(() => this.s3Client.send(command));
      return JSON.parse(result.Policy);
    } catch (error) {
      // NoSuchBucketPolicy is expected — bucket has no policy
      return null;
    }
  }

  /**
   * Get bucket ACL
   */
  async _getBucketAcl(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketAclCommand({ Bucket: bucketName });
      return await this.throttledCall(() => this.s3Client.send(command));
    } catch (error) {
      return null;
    }
  }

  /**
   * Get public access block configuration
   */
  async _getPublicAccessBlock(bucketName) {
    try {
      const command = new this.S3Commands.GetPublicAccessBlockCommand({ Bucket: bucketName });
      const result = await this.throttledCall(() => this.s3Client.send(command));
      return result.PublicAccessBlockConfiguration || null;
    } catch (error) {
      // NoSuchPublicAccessBlockConfiguration means no block is set
      return null;
    }
  }

  /**
   * Get bucket encryption configuration
   */
  async _getBucketEncryption(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketEncryptionCommand({ Bucket: bucketName });
      const result = await this.throttledCall(() => this.s3Client.send(command));
      return result.ServerSideEncryptionConfiguration || null;
    } catch (error) {
      // ServerSideEncryptionConfigurationNotFoundError is expected
      return null;
    }
  }

  /**
   * Get bucket versioning status
   */
  async _getBucketVersioning(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketVersioningCommand({ Bucket: bucketName });
      return await this.throttledCall(() => this.s3Client.send(command));
    } catch (error) {
      return null;
    }
  }

  /**
   * Get bucket logging configuration
   */
  async _getBucketLogging(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketLoggingCommand({ Bucket: bucketName });
      return await this.throttledCall(() => this.s3Client.send(command));
    } catch (error) {
      return null;
    }
  }

  /**
   * Get bucket tags
   */
  async _getBucketTagging(bucketName) {
    try {
      const command = new this.S3Commands.GetBucketTaggingCommand({ Bucket: bucketName });
      const result = await this.throttledCall(() => this.s3Client.send(command));
      return this.parseTags(result.TagSet || []);
    } catch (error) {
      // NoSuchTagSet is expected — bucket has no tags
      return {};
    }
  }

  /**
   * Parse encryption configuration into a normalized object
   */
  _parseEncryption(encryptionConfig) {
    if (!encryptionConfig || !encryptionConfig.Rules || encryptionConfig.Rules.length === 0) {
      return { SSEAlgorithm: null, KMSMasterKeyID: null };
    }

    const rule = encryptionConfig.Rules[0];
    const sse = rule.ApplyServerSideEncryptionByDefault || {};
    return {
      SSEAlgorithm: sse.SSEAlgorithm || null,
      KMSMasterKeyID: sse.KMSMasterKeyID || null
    };
  }

  /**
   * Check if bucket policy allows anonymous (Principal: "*") access
   */
  _policyAllowsAnonymous(policy) {
    if (!policy || !policy.Statement) return false;

    for (const statement of policy.Statement) {
      if (statement.Effect !== 'Allow') continue;

      const principal = statement.Principal;
      if (principal === '*') return true;
      if (principal && principal.AWS === '*') return true;
      if (Array.isArray(principal?.AWS) && principal.AWS.includes('*')) return true;
    }

    return false;
  }

  /**
   * Check if bucket policy allows cross-account access
   */
  _policyAllowsCrossAccount(policy, ownerAccount) {
    if (!policy || !policy.Statement || !ownerAccount) return false;

    for (const statement of policy.Statement) {
      if (statement.Effect !== 'Allow') continue;

      const principal = statement.Principal;
      if (!principal) continue;

      const awsPrincipals = this._extractAWSPrincipals(principal);
      for (const arn of awsPrincipals) {
        // Skip wildcard — handled by anonymous check
        if (arn === '*') continue;
        // Extract account ID from ARN (arn:aws:iam::ACCOUNT_ID:...)
        const match = arn.match(/arn:aws:iam::(\d+):/);
        if (match && match[1] !== ownerAccount) return true;
      }
    }

    return false;
  }

  /**
   * Extract AWS principal ARNs from a policy principal field
   */
  _extractAWSPrincipals(principal) {
    if (typeof principal === 'string') return [principal];
    if (!principal.AWS) return [];
    if (Array.isArray(principal.AWS)) return principal.AWS;
    return [principal.AWS];
  }

  /**
   * Check if ACL grants public access (AllUsers or AuthenticatedUsers)
   */
  _aclGrantsPublic(acl) {
    if (!acl || !acl.Grants) return false;

    const publicURIs = [
      'http://acs.amazonaws.com/groups/global/AllUsers',
      'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
    ];

    for (const grant of acl.Grants) {
      if (grant.Grantee?.URI && publicURIs.includes(grant.Grantee.URI)) {
        return true;
      }
    }

    return false;
  }

  // ==========================================================================
  // RDS SCANNING
  // ==========================================================================

  async discoverRDSInstances() {
    try {
      const workloads = [];

      // Discover DB instances (paginated via Marker)
      const instances = await this._discoverRDSDBInstances();
      workloads.push(...instances);

      // Discover Aurora clusters
      const clusters = await this._discoverRDSClusters();
      workloads.push(...clusters);

      return workloads;
    } catch (error) {
      this.log(`Error discovering RDS: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Discover RDS DB instances with pagination
   */
  async _discoverRDSDBInstances() {
    const allInstances = await this.paginateAll(
      async (marker) => {
        const params = {};
        if (marker) params.Marker = marker;
        const command = new this.RDSCommands.DescribeDBInstancesCommand(params);
        return await this.rdsClient.send(command);
      },
      'DBInstances',
      'Marker',
      'Marker'
    );

    const workloads = [];

    for (const instance of allInstances) {
      const tags = await this._getRDSTags(instance.DBInstanceArn);

      const workload = {
        name: instance.DBInstanceIdentifier,
        type: 'rds-instance',
        namespace: 'database',
        environment: tags.environment || tags.Environment || 'unknown',

        category: 'data-store',
        subcategory: this.determineSubcategory(tags, { name: instance.DBInstanceIdentifier }),
        is_ai_agent: this.isAIAgent(tags, { name: instance.DBInstanceIdentifier }),
        is_mcp_server: this.isMCPServer(tags, { name: instance.DBInstanceIdentifier }),

        labels: tags,
        metadata: {
          arn: instance.DBInstanceArn,
          engine: instance.Engine,
          engine_version: instance.EngineVersion,
          instance_class: instance.DBInstanceClass,
          storage_encrypted: instance.StorageEncrypted || false,
          publicly_accessible: instance.PubliclyAccessible || false,
          iam_auth_enabled: instance.IAMDatabaseAuthenticationEnabled || false,
          multi_az: instance.MultiAZ || false,
          backup_retention_period: instance.BackupRetentionPeriod || 0,
          security_groups: (instance.VpcSecurityGroups || []).map(sg => sg.VpcSecurityGroupId),
          vpc_id: instance.DBSubnetGroup?.VpcId || null,
          endpoint: instance.Endpoint?.Address || null,
          port: instance.Endpoint?.Port || null,
          storage_type: instance.StorageType || null,
          allocated_storage: instance.AllocatedStorage || null,
          auto_minor_version_upgrade: instance.AutoMinorVersionUpgrade || false,
          deletion_protection: instance.DeletionProtection || false,
          performance_insights_enabled: instance.PerformanceInsightsEnabled || false,
          credentials: [
            {
              name: 'RDS_MASTER_USER',
              key: 'RDS_MASTER_USER',
              type: 'database-credential',
              is_static: true,
              provider: 'aws',
              value: instance.MasterUsername || 'unknown'
            }
          ]
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

        is_shadow: this.isShadowService(tags, { name: instance.DBInstanceIdentifier }),
        shadow_score: this.calculateShadowScore(tags, { name: instance.DBInstanceIdentifier }),

        discovered_by: 'aws-storage-scanner'
      };

      workload.security_score = this.calculateStorageSecurityScore(workload, {
        publicly_accessible: instance.PubliclyAccessible || false,
        storage_encrypted: instance.StorageEncrypted || false,
        multi_az: instance.MultiAZ || false,
        backup_retention_period: instance.BackupRetentionPeriod || 0,
        iam_auth_enabled: instance.IAMDatabaseAuthenticationEnabled || false,
        deletion_protection: instance.DeletionProtection || false
      });

      workloads.push(workload);
    }

    return workloads;
  }

  /**
   * Discover Aurora DB clusters with pagination
   */
  async _discoverRDSClusters() {
    const allClusters = await this.paginateAll(
      async (marker) => {
        const params = {};
        if (marker) params.Marker = marker;
        const command = new this.RDSCommands.DescribeDBClustersCommand(params);
        return await this.rdsClient.send(command);
      },
      'DBClusters',
      'Marker',
      'Marker'
    );

    const workloads = [];

    for (const cluster of allClusters) {
      const tags = await this._getRDSTags(cluster.DBClusterArn);

      const workload = {
        name: cluster.DBClusterIdentifier,
        type: 'rds-cluster',
        namespace: 'database',
        environment: tags.environment || tags.Environment || 'unknown',

        category: 'data-store',
        subcategory: this.determineSubcategory(tags, { name: cluster.DBClusterIdentifier }),
        is_ai_agent: this.isAIAgent(tags, { name: cluster.DBClusterIdentifier }),
        is_mcp_server: this.isMCPServer(tags, { name: cluster.DBClusterIdentifier }),

        labels: tags,
        metadata: {
          arn: cluster.DBClusterArn,
          engine: cluster.Engine,
          engine_version: cluster.EngineVersion,
          storage_encrypted: cluster.StorageEncrypted || false,
          iam_auth_enabled: cluster.IAMDatabaseAuthenticationEnabled || false,
          multi_az: cluster.MultiAZ || false,
          backup_retention_period: cluster.BackupRetentionPeriod || 0,
          members: (cluster.DBClusterMembers || []).length,
          endpoint: cluster.Endpoint || null,
          reader_endpoint: cluster.ReaderEndpoint || null,
          deletion_protection: cluster.DeletionProtection || false,
          credentials: [
            {
              name: 'RDS_CLUSTER_MASTER_USER',
              key: 'RDS_CLUSTER_MASTER_USER',
              type: 'database-credential',
              is_static: true,
              provider: 'aws',
              value: cluster.MasterUsername || 'unknown'
            }
          ]
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

        is_shadow: this.isShadowService(tags, { name: cluster.DBClusterIdentifier }),
        shadow_score: this.calculateShadowScore(tags, { name: cluster.DBClusterIdentifier }),

        discovered_by: 'aws-storage-scanner'
      };

      workload.security_score = this.calculateStorageSecurityScore(workload, {
        publicly_accessible: false, // Clusters are not directly publicly accessible
        storage_encrypted: cluster.StorageEncrypted || false,
        multi_az: cluster.MultiAZ || false,
        backup_retention_period: cluster.BackupRetentionPeriod || 0,
        iam_auth_enabled: cluster.IAMDatabaseAuthenticationEnabled || false,
        deletion_protection: cluster.DeletionProtection || false
      });

      workloads.push(workload);
    }

    return workloads;
  }

  /**
   * Get tags for an RDS resource
   */
  async _getRDSTags(resourceArn) {
    try {
      const command = new this.RDSCommands.ListTagsForResourceCommand({
        ResourceName: resourceArn
      });
      const result = await this.throttledCall(() => this.rdsClient.send(command));
      return this.parseTags(result.TagList || []);
    } catch (error) {
      this.log(`Could not get tags for RDS resource ${resourceArn}: ${error.message}`, 'warn');
      return {};
    }
  }

  // ==========================================================================
  // DYNAMODB SCANNING
  // ==========================================================================

  async discoverDynamoDBTables() {
    try {
      // Paginate ListTables using LastEvaluatedTableName/ExclusiveStartTableName
      const allTableNames = await this.paginateAll(
        async (token) => {
          const params = {};
          if (token) params.ExclusiveStartTableName = token;
          const command = new this.DynamoCommands.ListTablesCommand(params);
          return await this.dynamoClient.send(command);
        },
        'TableNames',
        'LastEvaluatedTableName',
        'ExclusiveStartTableName'
      );

      const workloads = [];

      for (const tableName of allTableNames) {
        // Describe table
        const describeCommand = new this.DynamoCommands.DescribeTableCommand({
          TableName: tableName
        });
        const describeResult = await this.throttledCall(
          () => this.dynamoClient.send(describeCommand)
        );
        const table = describeResult.Table;

        // Get continuous backups / PITR status
        const pitrEnabled = await this._getDynamoPITR(tableName);

        // Get tags
        const tags = await this._getDynamoTags(table.TableArn);

        const encryptionType = this._parseDynamoEncryption(table.SSEDescription);
        const billingMode = table.BillingModeSummary?.BillingMode ||
          (table.ProvisionedThroughput?.ReadCapacityUnits ? 'PROVISIONED' : 'PAY_PER_REQUEST');

        const workload = {
          name: tableName,
          type: 'dynamodb-table',
          namespace: 'database',
          environment: tags.environment || tags.Environment || 'unknown',

          category: 'data-store',
          subcategory: this.determineSubcategory(tags, { name: tableName }),
          is_ai_agent: this.isAIAgent(tags, { name: tableName }),
          is_mcp_server: this.isMCPServer(tags, { name: tableName }),

          labels: tags,
          metadata: {
            arn: table.TableArn,
            table_status: table.TableStatus,
            item_count: table.ItemCount || 0,
            table_size_bytes: table.TableSizeBytes || 0,
            billing_mode: billingMode,
            encryption_type: encryptionType,
            point_in_time_recovery: pitrEnabled,
            table_class: table.TableClassSummary?.TableClass || 'STANDARD',
            global_secondary_indexes: (table.GlobalSecondaryIndexes || []).length,
            stream_enabled: table.StreamSpecification?.StreamEnabled || false,
            credentials: []
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

          is_shadow: this.isShadowService(tags, { name: tableName }),
          shadow_score: this.calculateShadowScore(tags, { name: tableName }),

          discovered_by: 'aws-storage-scanner'
        };

        workload.security_score = this.calculateStorageSecurityScore(workload, {
          encryption_type: encryptionType,
          point_in_time_recovery: pitrEnabled,
          billing_mode: billingMode
        });

        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering DynamoDB tables: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Get Point-in-Time Recovery status for a DynamoDB table
   */
  async _getDynamoPITR(tableName) {
    try {
      const command = new this.DynamoCommands.DescribeContinuousBackupsCommand({
        TableName: tableName
      });
      const result = await this.throttledCall(() => this.dynamoClient.send(command));
      return result.ContinuousBackupsDescription
        ?.PointInTimeRecoveryDescription
        ?.PointInTimeRecoveryStatus === 'ENABLED';
    } catch (error) {
      this.log(`Could not get PITR status for table ${tableName}: ${error.message}`, 'warn');
      return false;
    }
  }

  /**
   * Get tags for a DynamoDB table
   */
  async _getDynamoTags(tableArn) {
    try {
      const command = new this.DynamoCommands.ListTagsOfResourceCommand({
        ResourceArn: tableArn
      });
      const result = await this.throttledCall(() => this.dynamoClient.send(command));
      return this.parseTags(result.Tags || []);
    } catch (error) {
      this.log(`Could not get tags for DynamoDB table ${tableArn}: ${error.message}`, 'warn');
      return {};
    }
  }

  /**
   * Parse DynamoDB SSE description into an encryption type string
   */
  _parseDynamoEncryption(sseDescription) {
    if (!sseDescription || sseDescription.Status !== 'ENABLED') return 'AES256';
    return sseDescription.SSEType || 'KMS';
  }

  // ==========================================================================
  // SECURITY SCORING
  // ==========================================================================

  /**
   * Calculate security score for storage resources.
   * Starts with the base score from BaseScanner, then applies resource-specific
   * adjustments based on the workload type.
   *
   * @param {Object} workload - The workload object
   * @param {Object} resourceSpecificFactors - Type-specific security factors
   * @returns {number} Security score 0-100
   */
  calculateStorageSecurityScore(workload, resourceSpecificFactors = {}) {
    // Start with the base security score from BaseScanner
    let score = this.calculateSecurityScore(workload);

    switch (workload.type) {
      case 's3-bucket':
        if (resourceSpecificFactors.is_public) score -= 30;
        if (!resourceSpecificFactors.has_encryption) score -= 20;
        if (!resourceSpecificFactors.versioning_enabled) score -= 10;
        if (!resourceSpecificFactors.logging_enabled) score -= 10;
        if (resourceSpecificFactors.policy_allows_anonymous) score -= 15;
        break;

      case 'rds-instance':
      case 'rds-cluster':
        if (resourceSpecificFactors.publicly_accessible) score -= 25;
        if (!resourceSpecificFactors.storage_encrypted) score -= 20;
        if (!resourceSpecificFactors.multi_az) score -= 10;
        if ((resourceSpecificFactors.backup_retention_period || 0) < 7) score -= 10;
        if (resourceSpecificFactors.iam_auth_enabled) score += 10;
        if (!resourceSpecificFactors.deletion_protection) score -= 10;
        break;

      case 'dynamodb-table': {
        const encType = resourceSpecificFactors.encryption_type;
        if (!encType || encType === 'AES256') score -= 15;
        if (!resourceSpecificFactors.point_in_time_recovery) score -= 10;
        if (resourceSpecificFactors.billing_mode === 'PAY_PER_REQUEST') score += 5;
        break;
      }

      default:
        break;
    }

    // Clamp to 0-100
    return Math.max(0, Math.min(100, score));
  }
}

module.exports = AWSStorageScanner;
