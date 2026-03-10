// =============================================================================
// AWS Scanner - Discovers workloads from AWS (SDK v3)
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class AWSScanner extends BaseScanner {
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
   * Uses credentials from this.config.credentials if provided (from connector wizard).
   * Supports role assumption via roleArn + externalId.
   */
  async initializeAWS() {
    if (this.initialized) return;

    try {
      // AWS SDK v3 - import only what we need
      const { EC2Client, DescribeInstancesCommand, DescribeRegionsCommand } = require('@aws-sdk/client-ec2');
      const { LambdaClient, ListFunctionsCommand, ListTagsCommand } = require('@aws-sdk/client-lambda');
      const { ECSClient, ListClustersCommand, ListTasksCommand, DescribeTasksCommand } = require('@aws-sdk/client-ecs');
      const { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } = require('@aws-sdk/client-sts');

      // Build client config with region + explicit credentials if provided
      const clientConfig = { region: this.region };

      if (this.config.credentials?.accessKeyId && this.config.credentials?.secretAccessKey) {
        clientConfig.credentials = {
          accessKeyId: this.config.credentials.accessKeyId,
          secretAccessKey: this.config.credentials.secretAccessKey,
        };
        this.log('Using explicit credentials from connector config', 'info');
      }

      // If roleArn is provided, assume the role to get temporary credentials
      if (this.config.roleArn || this.config.credentials?.roleArn) {
        const roleArn = this.config.roleArn || this.config.credentials.roleArn;
        const externalId = this.config.externalId || this.config.credentials?.externalId;
        this.log(`Assuming role: ${roleArn}`, 'info');

        const stsClient = new STSClient(clientConfig);
        const assumeParams = {
          RoleArn: roleArn,
          RoleSessionName: `wid-discovery-${Date.now()}`,
          DurationSeconds: 3600,
        };
        if (externalId) assumeParams.ExternalId = externalId;

        const assumeResult = await stsClient.send(new AssumeRoleCommand(assumeParams));
        const assumed = assumeResult.Credentials;

        clientConfig.credentials = {
          accessKeyId: assumed.AccessKeyId,
          secretAccessKey: assumed.SecretAccessKey,
          sessionToken: assumed.SessionToken,
        };
        this.log(`Assumed role successfully, expires: ${assumed.Expiration}`, 'success');
      }

      // Store the resolved client config for multi-region client creation
      this._clientConfig = clientConfig;

      this.ec2Client = new EC2Client(clientConfig);
      this.lambdaClient = new LambdaClient(clientConfig);
      this.ecsClient = new ECSClient(clientConfig);
      this.stsClient = new STSClient(clientConfig);

      // Store command classes for later use
      this.EC2Commands = { DescribeInstancesCommand, DescribeRegionsCommand };
      this.LambdaCommands = { ListFunctionsCommand, ListTagsCommand };
      this.ECSCommands = { ListClustersCommand, ListTasksCommand, DescribeTasksCommand };
      this.STSCommands = { GetCallerIdentityCommand };

      // Store SDK module references for multi-region client creation
      this._EC2Client = EC2Client;
      this._LambdaClient = LambdaClient;
      this._ECSClient = ECSClient;

      this.initialized = true;
      this.log(`AWS SDK v3 initialized for region: ${this.region}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize AWS SDK v3: ${error.message}`);
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
      
      this.log(`Connected to AWS account: ${response.Account}`, 'success');
      return true;
    } catch (error) {
      this.log(`AWS validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  /**
   * Get scanner capabilities
   */
  getCapabilities() {
    return ['discover', 'ec2', 'lambda', 'ecs', 'attestation'];
  }

  getRequiredCredentials() {
    return [
      { name: 'AWS_ACCESS_KEY_ID', description: 'AWS access key' },
      { name: 'AWS_SECRET_ACCESS_KEY', description: 'AWS secret key' },
      { name: 'AWS_DEFAULT_REGION', description: 'AWS region (e.g. us-east-1)' },
    ];
  }

  /**
   * Enumerate opted-in AWS regions
   */
  async getActiveRegions() {
    try {
      const result = await this.ec2Client.send(new this.EC2Commands.DescribeRegionsCommand({
        Filters: [{ Name: 'opt-in-status', Values: ['opt-in-not-required', 'opted-in'] }]
      }));
      return (result.Regions || []).map(r => r.RegionName);
    } catch (e) {
      this.log(`Failed to enumerate regions, using default: ${this.region}`, 'warn');
      return [this.region];
    }
  }

  /**
   * Main discovery method — scans all opted-in regions in parallel
   */
  async discover() {
    await this.initializeAWS();

    const multiRegion = this.config.multiRegion !== false;
    let regions = [this.region];

    if (multiRegion) {
      regions = await this.getActiveRegions();
      this.log(`Multi-region scan: ${regions.length} regions`, 'info');
    } else {
      this.log(`Starting AWS discovery in region: ${this.region}`, 'info');
    }

    // Scan all regions in parallel
    const regionResults = await Promise.allSettled(
      regions.map(region => this.discoverRegion(region))
    );

    const workloads = [];
    for (let i = 0; i < regionResults.length; i++) {
      const result = regionResults[i];
      if (result.status === 'fulfilled') {
        workloads.push(...result.value);
      } else {
        this.log(`Region ${regions[i]} scan failed: ${result.reason?.message}`, 'error');
      }
    }

    this.log(`Total across ${regions.length} regions: ${workloads.length} workloads`, 'success');
    return workloads;
  }

  /**
   * Discover all workloads in a single region
   */
  async discoverRegion(region) {
    const isDefaultRegion = region === this.region;
    const regionConfig = isDefaultRegion ? null : { ...this._clientConfig, region };
    const ec2Client = isDefaultRegion ? this.ec2Client : new this._EC2Client(regionConfig);
    const lambdaClient = isDefaultRegion ? this.lambdaClient : new this._LambdaClient(regionConfig);
    const ecsClient = isDefaultRegion ? this.ecsClient : new this._ECSClient(regionConfig);

    const workloads = [];

    try {
      const ec2 = await this.discoverEC2(ec2Client, region);
      workloads.push(...ec2);
      if (ec2.length > 0) this.log(`[${region}] Found ${ec2.length} EC2 instances`, 'success');

      const lambda = await this.discoverLambda(lambdaClient, region);
      workloads.push(...lambda);
      if (lambda.length > 0) this.log(`[${region}] Found ${lambda.length} Lambda functions`, 'success');

      const ecs = await this.discoverECS(ecsClient, region);
      workloads.push(...ecs);
      if (ecs.length > 0) this.log(`[${region}] Found ${ecs.length} ECS tasks`, 'success');
    } catch (error) {
      this.log(`[${region}] Discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  async discoverEC2(ec2Client, region) {
    const client = ec2Client || this.ec2Client;
    const scanRegion = region || this.region;
    try {
      const command = new this.EC2Commands.DescribeInstancesCommand({
        Filters: [
          { Name: 'instance-state-name', Values: ['running'] }
        ]
      });

      const result = await client.send(command);
      const workloads = [];
      
      for (const reservation of result.Reservations || []) {
        for (const instance of reservation.Instances || []) {
          const tags = this.parseTags(instance.Tags);
          const name = tags.Name || instance.InstanceId;
          
          const workload = {
            name,
            type: 'ec2',
            namespace: tags.namespace || tags.Namespace || 'default',
            environment: tags.environment || tags.Environment || 'unknown',
            
            instance_id: instance.InstanceId,
            arn: `arn:aws:ec2:${scanRegion}:${reservation.OwnerId}:instance/${instance.InstanceId}`,

            category: this.categorizeWorkload(tags, instance),
            subcategory: this.determineSubcategory(tags, instance),
            is_ai_agent: this.isAIAgent(tags, instance),
            is_mcp_server: this.isMCPServer(tags, instance),

            labels: tags,
            metadata: {
              instance_type: instance.InstanceType,
              ami_id: instance.ImageId,
              vpc_id: instance.VpcId,
              subnet_id: instance.SubnetId,
              private_ip: instance.PrivateIpAddress,
              public_ip: instance.PublicIpAddress,
              launch_time: instance.LaunchTime,
              iam_instance_profile: instance.IamInstanceProfile?.Arn || null,
              security_groups: (instance.SecurityGroups || []).map(sg => sg.GroupId),
              credentials: [
                ...(instance.IamInstanceProfile ? [{
                  name: 'IAM_INSTANCE_PROFILE',
                  key: 'IAM_INSTANCE_PROFILE',
                  type: 'iam-role',
                  is_static: false,
                  provider: 'aws',
                  value: instance.IamInstanceProfile.Arn.split('/').pop(),
                }] : []),
              ],
            },

            cloud_provider: 'aws',
            region: scanRegion,
            account_id: reservation.OwnerId,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `aws://${scanRegion}`,
            cluster_id: scanRegion,

            owner: tags.owner || tags.Owner || null,
            team: tags.team || tags.Team || null,
            cost_center: tags.CostCenter || tags['cost-center'] || null,

            is_shadow: this.isShadowService(tags, instance),
            shadow_score: this.calculateShadowScore(tags, instance),

            discovered_by: 'aws-scanner'
          };

          workload.security_score = this.calculateSecurityScore(workload);
          workloads.push(workload);
        }
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering EC2: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverLambda(lambdaClient, region) {
    const client = lambdaClient || this.lambdaClient;
    const scanRegion = region || this.region;
    try {
      const listCommand = new this.LambdaCommands.ListFunctionsCommand({});
      const result = await client.send(listCommand);
      const workloads = [];
      
      for (const func of result.Functions || []) {
        // Get tags for this function
        const tagsCommand = new this.LambdaCommands.ListTagsCommand({
          Resource: func.FunctionArn
        });
        
        const tagsResult = await client.send(tagsCommand);
        const tags = tagsResult.Tags || {};
        
        const workload = {
          name: func.FunctionName,
          type: 'lambda',
          namespace: tags.namespace || tags.Namespace || 'lambda',
          environment: tags.environment || tags.Environment || 'unknown',
          
          arn: func.FunctionArn,
          
          category: this.categorizeWorkload(tags, func),
          subcategory: this.determineSubcategory(tags, func),
          is_ai_agent: this.isAIAgent(tags, func),
          is_mcp_server: this.isMCPServer(tags, func),
          
          labels: tags,
          metadata: {
            runtime: func.Runtime,
            memory_size: func.MemorySize,
            timeout: func.Timeout,
            handler: func.Handler,
            code_size: func.CodeSize,
            last_modified: func.LastModified,
            role: func.Role,
            credentials: [
              ...(func.Role ? [{
                name: 'IAM_EXECUTION_ROLE',
                key: 'IAM_EXECUTION_ROLE',
                type: 'iam-role',
                is_static: false,
                provider: 'aws',
                value: func.Role.split('/').pop(),
              }] : []),
            ],
            env: Object.fromEntries(
              Object.entries(func.Environment?.Variables || {}).map(([k]) => [k, '[set]'])
            ),
          },
          
          cloud_provider: 'aws',
          region: scanRegion,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `aws://${scanRegion}`,
          cluster_id: scanRegion,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, func),
          shadow_score: this.calculateShadowScore(tags, func),

          discovered_by: 'aws-scanner'
        };

        workload.security_score = this.calculateSecurityScore(workload);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Lambda: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverECS(ecsClient, region) {
    const client = ecsClient || this.ecsClient;
    const scanRegion = region || this.region;
    try {
      // List all clusters
      const listClustersCommand = new this.ECSCommands.ListClustersCommand({});
      const clustersResult = await client.send(listClustersCommand);
      const workloads = [];
      
      for (const clusterArn of clustersResult.clusterArns || []) {
        // List tasks in cluster
        const listTasksCommand = new this.ECSCommands.ListTasksCommand({
          cluster: clusterArn
        });
        const tasksResult = await client.send(listTasksCommand);
        
        if (!tasksResult.taskArns || tasksResult.taskArns.length === 0) continue;
        
        // Describe tasks
        const describeCommand = new this.ECSCommands.DescribeTasksCommand({
          cluster: clusterArn,
          tasks: tasksResult.taskArns
        });
        const describeResult = await client.send(describeCommand);
        
        for (const task of describeResult.tasks || []) {
          const tags = this.parseTags(task.tags);
          
          const workload = {
            name: tags.Name || task.taskArn.split('/').pop(),
            type: 'ecs-task',
            namespace: tags.namespace || tags.Namespace || 'ecs',
            environment: tags.environment || tags.Environment || 'unknown',
            
            arn: task.taskArn,
            
            category: this.categorizeWorkload(tags, task),
            subcategory: this.determineSubcategory(tags, task),
            is_ai_agent: this.isAIAgent(tags, task),
            is_mcp_server: this.isMCPServer(tags, task),
            
            labels: tags,
            metadata: {
              cluster_arn: clusterArn,
              task_definition: task.taskDefinitionArn,
              launch_type: task.launchType,
              platform_version: task.platformVersion,
              started_at: task.startedAt,
              credentials: [
                ...(task.overrides?.taskRoleArn ? [{
                  name: 'TASK_ROLE',
                  key: 'TASK_ROLE',
                  type: 'iam-role',
                  is_static: false,
                  provider: 'aws',
                  value: task.overrides.taskRoleArn.split('/').pop(),
                }] : []),
                ...(task.overrides?.executionRoleArn ? [{
                  name: 'EXECUTION_ROLE',
                  key: 'EXECUTION_ROLE',
                  type: 'iam-role',
                  is_static: false,
                  provider: 'aws',
                  value: task.overrides.executionRoleArn.split('/').pop(),
                }] : []),
              ],
            },
            
            cloud_provider: 'aws',
            region: scanRegion,
            trust_domain: this.config.trustDomain || 'company.com',
            issuer: `aws://${scanRegion}`,
            cluster_id: scanRegion,

            owner: tags.owner || tags.Owner || null,
            team: tags.team || tags.Team || null,
            cost_center: tags.CostCenter || tags['cost-center'] || null,

            is_shadow: this.isShadowService(tags, task),
            shadow_score: this.calculateShadowScore(tags, task),

            discovered_by: 'aws-scanner'
          };
          
          workload.security_score = this.calculateSecurityScore(workload);
          workloads.push(workload);
        }
      }
      
      return workloads;
    } catch (error) {
      this.log(`Error discovering ECS: ${error.message}`, 'error');
      return [];
    }
  }
}

module.exports = AWSScanner;
