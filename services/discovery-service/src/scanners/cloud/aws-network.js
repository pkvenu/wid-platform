// =============================================================================
// AWS Network Scanner - Discovers VPCs, Security Groups, and Load Balancers
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class AWSNetworkScanner extends BaseScanner {
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
      const {
        EC2Client,
        DescribeVpcsCommand,
        DescribeSubnetsCommand,
        DescribeRouteTablesCommand,
        DescribeInternetGatewaysCommand,
        DescribeNatGatewaysCommand,
        DescribeFlowLogsCommand,
        DescribeSecurityGroupsCommand
      } = require('@aws-sdk/client-ec2');

      const {
        ElasticLoadBalancingV2Client,
        DescribeLoadBalancersCommand,
        DescribeTargetGroupsCommand,
        DescribeListenersCommand,
        DescribeTagsCommand
      } = require('@aws-sdk/client-elastic-load-balancing-v2');

      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

      // Create clients with region
      const clientConfig = { region: this.region };

      this.ec2Client = new EC2Client(clientConfig);
      this.elbv2Client = new ElasticLoadBalancingV2Client(clientConfig);
      this.stsClient = new STSClient(clientConfig);

      // Store command classes for later use
      this.EC2Commands = {
        DescribeVpcsCommand,
        DescribeSubnetsCommand,
        DescribeRouteTablesCommand,
        DescribeInternetGatewaysCommand,
        DescribeNatGatewaysCommand,
        DescribeFlowLogsCommand,
        DescribeSecurityGroupsCommand
      };
      this.ELBv2Commands = {
        DescribeLoadBalancersCommand,
        DescribeTargetGroupsCommand,
        DescribeListenersCommand,
        DescribeTagsCommand
      };
      this.STSCommands = { GetCallerIdentityCommand };

      this.initialized = true;
      this.log(`AWS Network SDK v3 initialized for region: ${this.region}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize AWS Network SDK v3: ${error.message}`);
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
      this.log(`AWS Network validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  /**
   * Get scanner capabilities
   */
  getCapabilities() {
    return ['discover', 'vpc', 'security-groups', 'load-balancers'];
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

    this.log(`Starting AWS Network discovery in region: ${this.region}`, 'info');

    const workloads = [];

    try {
      // Discover VPCs
      const vpcs = await this.discoverVPCs();
      workloads.push(...vpcs);
      this.log(`Found ${vpcs.length} VPCs`, 'success');

      // Discover Security Groups
      const securityGroups = await this.discoverSecurityGroups();
      workloads.push(...securityGroups);
      this.log(`Found ${securityGroups.length} Security Groups`, 'success');

      // Discover Load Balancers
      const loadBalancers = await this.discoverLoadBalancers();
      workloads.push(...loadBalancers);
      this.log(`Found ${loadBalancers.length} Load Balancers`, 'success');

    } catch (error) {
      this.log(`Network discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ===========================================================================
  // VPC Discovery
  // ===========================================================================

  async discoverVPCs() {
    try {
      // Fetch all VPCs
      const vpcsResult = await this.ec2Client.send(
        new this.EC2Commands.DescribeVpcsCommand({})
      );
      const vpcs = vpcsResult.Vpcs || [];

      if (vpcs.length === 0) return [];

      // Fetch supporting resources in parallel for the region
      const [subnetsResult, routeTablesResult, igwsResult, natGwsResult] = await Promise.all([
        this.ec2Client.send(new this.EC2Commands.DescribeSubnetsCommand({})),
        this.ec2Client.send(new this.EC2Commands.DescribeRouteTablesCommand({})),
        this.ec2Client.send(new this.EC2Commands.DescribeInternetGatewaysCommand({})),
        this.ec2Client.send(new this.EC2Commands.DescribeNatGatewaysCommand({}))
      ]);

      const allSubnets = subnetsResult.Subnets || [];
      const allRouteTables = routeTablesResult.RouteTables || [];
      const allIGWs = igwsResult.InternetGateways || [];
      const allNATGWs = natGwsResult.NatGateways || [];

      const workloads = [];

      for (const vpc of vpcs) {
        const tags = this.parseTags(vpc.Tags);
        const vpcId = vpc.VpcId;
        const name = tags.Name || vpcId;

        // Filter resources belonging to this VPC
        const vpcSubnets = allSubnets.filter(s => s.VpcId === vpcId);
        const vpcRouteTables = allRouteTables.filter(rt => rt.VpcId === vpcId);
        const vpcNATGWs = allNATGWs.filter(
          ng => ng.VpcId === vpcId && ng.State !== 'deleted'
        );

        // IGWs attached to this VPC
        const vpcIGWs = allIGWs.filter(igw =>
          (igw.Attachments || []).some(att => att.VpcId === vpcId)
        );
        const hasInternetGateway = vpcIGWs.length > 0;
        const internetGatewayIds = vpcIGWs.map(igw => igw.InternetGatewayId);

        // Determine which subnets are public (have a route to an IGW)
        const igwIds = new Set(internetGatewayIds);
        const publicSubnetIds = new Set();
        for (const rt of vpcRouteTables) {
          const routesToIGW = (rt.Routes || []).some(route =>
            route.GatewayId && igwIds.has(route.GatewayId)
          );
          if (routesToIGW) {
            // Find subnets explicitly associated with this route table
            const associatedSubnetIds = (rt.Associations || [])
              .filter(a => a.SubnetId)
              .map(a => a.SubnetId);

            // If no explicit subnet associations, this is the main route table
            // and applies to all subnets without explicit associations
            if (associatedSubnetIds.length > 0) {
              associatedSubnetIds.forEach(id => publicSubnetIds.add(id));
            } else {
              const isMain = (rt.Associations || []).some(a => a.Main);
              if (isMain) {
                // All subnets without explicit route table associations are public
                const explicitlyAssociated = new Set();
                for (const otherRt of vpcRouteTables) {
                  if (otherRt.RouteTableId === rt.RouteTableId) continue;
                  for (const assoc of otherRt.Associations || []) {
                    if (assoc.SubnetId) explicitlyAssociated.add(assoc.SubnetId);
                  }
                }
                for (const subnet of vpcSubnets) {
                  if (!explicitlyAssociated.has(subnet.SubnetId)) {
                    publicSubnetIds.add(subnet.SubnetId);
                  }
                }
              }
            }
          }
        }

        const publicSubnetCount = publicSubnetIds.size;
        const privateSubnetCount = vpcSubnets.length - publicSubnetCount;

        // Check flow logs for this VPC
        let flowLogsEnabled = false;
        try {
          const flowLogsResult = await this.ec2Client.send(
            new this.EC2Commands.DescribeFlowLogsCommand({
              Filter: [{ Name: 'resource-id', Values: [vpcId] }]
            })
          );
          flowLogsEnabled = (flowLogsResult.FlowLogs || []).length > 0;
        } catch (err) {
          this.log(`Error checking flow logs for ${vpcId}: ${err.message}`, 'warn');
        }

        // Calculate security score adjustments
        let scoreAdjustment = 0;
        if (!flowLogsEnabled) scoreAdjustment -= 15;
        if (vpc.IsDefault) scoreAdjustment -= 10;
        if (vpcNATGWs.length > 0) scoreAdjustment += 10;

        const workload = {
          name,
          type: 'vpc',
          namespace: 'network',
          environment: tags.environment || tags.Environment || 'unknown',

          category: 'network',
          subcategory: tags.subcategory || null,
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            vpc_id: vpcId,
            cidr_block: vpc.CidrBlock,
            is_default: vpc.IsDefault || false,
            state: vpc.State,
            has_internet_gateway: hasInternetGateway,
            internet_gateway_ids: internetGatewayIds,
            nat_gateway_count: vpcNATGWs.length,
            public_subnet_count: publicSubnetCount,
            private_subnet_count: privateSubnetCount,
            total_subnet_count: vpcSubnets.length,
            flow_logs_enabled: flowLogsEnabled,
            dhcp_options_id: vpc.DhcpOptionsId || null
          },

          cloud_provider: 'aws',
          region: this.region,
          account_id: this.accountId || null,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `aws://${this.region}`,
          cluster_id: this.region,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, vpc),
          shadow_score: this.calculateShadowScore(tags, vpc),

          discovered_by: 'aws-network-scanner'
        };

        workload.security_score = Math.max(0, Math.min(100,
          this.calculateSecurityScore(workload) + scoreAdjustment
        ));
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering VPCs: ${error.message}`, 'error');
      return [];
    }
  }

  // ===========================================================================
  // Security Group Discovery
  // ===========================================================================

  async discoverSecurityGroups() {
    try {
      // Paginate through all security groups
      const securityGroups = await this.paginateAll(
        async (token) => {
          const params = {};
          if (token) params.NextToken = token;
          return this.ec2Client.send(
            new this.EC2Commands.DescribeSecurityGroupsCommand(params)
          );
        },
        'SecurityGroups',
        'NextToken',
        'NextToken'
      );

      const workloads = [];

      for (const sg of securityGroups) {
        const tags = this.parseTags(sg.Tags);
        const name = tags.Name || sg.GroupName || sg.GroupId;

        // Parse ingress rules
        const ingressRules = (sg.IpPermissions || []).map(perm =>
          this._parseIpPermission(perm)
        );

        // Parse egress rules
        const egressRules = (sg.IpPermissionsEgress || []).map(perm =>
          this._parseIpPermission(perm)
        );

        // Determine public exposure
        const publicCidrs = ['0.0.0.0/0', '::/0'];
        const allowsPublicIngress = ingressRules.some(rule =>
          rule.cidr_ranges.some(cidr => publicCidrs.includes(cidr))
        );

        const publicPorts = [];
        for (const rule of ingressRules) {
          const isPublic = rule.cidr_ranges.some(cidr => publicCidrs.includes(cidr));
          if (isPublic) {
            if (rule.protocol === '-1') {
              publicPorts.push('all');
            } else if (rule.from_port !== null) {
              for (let port = rule.from_port; port <= rule.to_port; port++) {
                publicPorts.push(port);
              }
            }
          }
        }

        const allowsAllTraffic = ingressRules.some(rule =>
          rule.protocol === '-1' &&
          rule.cidr_ranges.some(cidr => publicCidrs.includes(cidr))
        );

        // Calculate security score adjustments
        let scoreAdjustment = 0;
        if (allowsAllTraffic) {
          scoreAdjustment -= 30;
        } else if (allowsPublicIngress) {
          const hasSshRdp = publicPorts.includes(22) || publicPorts.includes(3389);
          if (hasSshRdp) {
            scoreAdjustment -= 20;
          } else {
            scoreAdjustment -= 15;
          }
        } else {
          scoreAdjustment += 10;
        }

        const workload = {
          name,
          type: 'security-group',
          namespace: 'network',
          environment: tags.environment || tags.Environment || 'unknown',

          category: 'network-policy',
          subcategory: tags.subcategory || null,
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            group_id: sg.GroupId,
            group_name: sg.GroupName,
            vpc_id: sg.VpcId,
            description: sg.Description || null,
            ingress_rules: ingressRules,
            egress_rules: egressRules,
            allows_public_ingress: allowsPublicIngress,
            public_ports: publicPorts,
            allows_all_traffic: allowsAllTraffic,
            ingress_rule_count: ingressRules.length,
            egress_rule_count: egressRules.length
          },

          cloud_provider: 'aws',
          region: this.region,
          account_id: this.accountId || null,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `aws://${this.region}`,
          cluster_id: this.region,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, sg),
          shadow_score: this.calculateShadowScore(tags, sg),

          discovered_by: 'aws-network-scanner'
        };

        workload.security_score = Math.max(0, Math.min(100,
          this.calculateSecurityScore(workload) + scoreAdjustment
        ));
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Security Groups: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Parse an AWS IpPermission into a normalized rule object
   */
  _parseIpPermission(perm) {
    const cidrRanges = [
      ...(perm.IpRanges || []).map(r => r.CidrIp),
      ...(perm.Ipv6Ranges || []).map(r => r.CidrIpv6)
    ];

    const sourceSecurityGroups = (perm.UserIdGroupPairs || []).map(pair => ({
      group_id: pair.GroupId,
      user_id: pair.UserId || null,
      description: pair.Description || null
    }));

    // Build description from individual range descriptions
    const descriptions = [
      ...(perm.IpRanges || []).filter(r => r.Description).map(r => r.Description),
      ...(perm.Ipv6Ranges || []).filter(r => r.Description).map(r => r.Description),
      ...(perm.UserIdGroupPairs || []).filter(p => p.Description).map(p => p.Description)
    ];

    return {
      protocol: perm.IpProtocol,
      from_port: perm.FromPort != null ? perm.FromPort : null,
      to_port: perm.ToPort != null ? perm.ToPort : null,
      cidr_ranges: cidrRanges,
      source_security_groups: sourceSecurityGroups,
      description: descriptions.length > 0 ? descriptions.join('; ') : null
    };
  }

  // ===========================================================================
  // Load Balancer Discovery
  // ===========================================================================

  async discoverLoadBalancers() {
    try {
      // Paginate through all load balancers
      const loadBalancers = await this.paginateAll(
        async (token) => {
          const params = {};
          if (token) params.Marker = token;
          return this.elbv2Client.send(
            new this.ELBv2Commands.DescribeLoadBalancersCommand(params)
          );
        },
        'LoadBalancers',
        'NextMarker',
        'Marker'
      );

      const workloads = [];

      for (const lb of loadBalancers) {
        const lbArn = lb.LoadBalancerArn;
        const name = lb.LoadBalancerName;

        // Fetch listeners, target groups, and tags in parallel
        const [listenersResult, targetGroupsResult, tagsResult] = await Promise.all([
          this._describeListenersSafe(lbArn),
          this._describeTargetGroupsSafe(lbArn),
          this._describeTagsSafe([lbArn])
        ]);

        const listeners = (listenersResult || []).map(l => ({
          port: l.Port,
          protocol: l.Protocol,
          ssl_policy: l.SslPolicy || null,
          default_actions: (l.DefaultActions || []).map(a => ({
            type: a.Type,
            target_group_arn: a.TargetGroupArn || null
          }))
        }));

        const targetGroups = (targetGroupsResult || []).map(tg => ({
          arn: tg.TargetGroupArn,
          name: tg.TargetGroupName,
          protocol: tg.Protocol,
          port: tg.Port,
          target_type: tg.TargetType,
          health_check_path: tg.HealthCheckPath || null
        }));

        // Parse tags from the Tags response
        const tagDescriptions = tagsResult || [];
        const lbTagDesc = tagDescriptions.find(td => td.ResourceArn === lbArn);
        const tags = this.parseTags(lbTagDesc ? lbTagDesc.Tags : []);

        const isInternetFacing = lb.Scheme === 'internet-facing';
        const httpsProtocols = ['HTTPS', 'TLS'];
        const hasHttpsListener = listeners.some(l =>
          httpsProtocols.includes(l.protocol)
        );
        const allListenersHttps = listeners.length > 0 && listeners.every(l =>
          httpsProtocols.includes(l.protocol)
        );

        // Calculate security score adjustments
        let scoreAdjustment = 0;
        if (isInternetFacing && !hasHttpsListener && listeners.length > 0) {
          scoreAdjustment -= 10;
        }
        if (allListenersHttps) {
          scoreAdjustment += 10;
        }
        if (isInternetFacing) {
          scoreAdjustment -= 5;
        }

        const workload = {
          name,
          type: 'load-balancer',
          namespace: 'network',
          environment: tags.environment || tags.Environment || 'unknown',

          category: 'network',
          subcategory: tags.subcategory || null,
          is_ai_agent: false,
          is_mcp_server: false,

          labels: tags,
          metadata: {
            arn: lbArn,
            dns_name: lb.DNSName,
            scheme: lb.Scheme,
            type: lb.Type,
            vpc_id: lb.VpcId,
            availability_zones: (lb.AvailabilityZones || []).map(az => az.ZoneName),
            security_groups: lb.SecurityGroups || [],
            state: lb.State ? lb.State.Code : null,
            listeners,
            target_groups: targetGroups,
            is_internet_facing: isInternetFacing,
            has_https_listener: hasHttpsListener,
            has_waf: false // Would need separate WAF API check (wafv2:GetWebACLForResource)
          },

          cloud_provider: 'aws',
          region: this.region,
          account_id: this.accountId || null,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `aws://${this.region}`,
          cluster_id: this.region,

          owner: tags.owner || tags.Owner || null,
          team: tags.team || tags.Team || null,
          cost_center: tags.CostCenter || tags['cost-center'] || null,

          is_shadow: this.isShadowService(tags, { name, ...lb }),
          shadow_score: this.calculateShadowScore(tags, { name, ...lb }),

          discovered_by: 'aws-network-scanner'
        };

        workload.security_score = Math.max(0, Math.min(100,
          this.calculateSecurityScore(workload) + scoreAdjustment
        ));
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Load Balancers: ${error.message}`, 'error');
      return [];
    }
  }

  /**
   * Safely describe listeners for a load balancer
   */
  async _describeListenersSafe(loadBalancerArn) {
    try {
      const result = await this.elbv2Client.send(
        new this.ELBv2Commands.DescribeListenersCommand({
          LoadBalancerArn: loadBalancerArn
        })
      );
      return result.Listeners || [];
    } catch (error) {
      this.log(`Error fetching listeners for ${loadBalancerArn}: ${error.message}`, 'warn');
      return [];
    }
  }

  /**
   * Safely describe target groups for a load balancer
   */
  async _describeTargetGroupsSafe(loadBalancerArn) {
    try {
      const result = await this.elbv2Client.send(
        new this.ELBv2Commands.DescribeTargetGroupsCommand({
          LoadBalancerArn: loadBalancerArn
        })
      );
      return result.TargetGroups || [];
    } catch (error) {
      this.log(`Error fetching target groups for ${loadBalancerArn}: ${error.message}`, 'warn');
      return [];
    }
  }

  /**
   * Safely describe tags for resource ARNs
   */
  async _describeTagsSafe(resourceArns) {
    try {
      const result = await this.elbv2Client.send(
        new this.ELBv2Commands.DescribeTagsCommand({
          ResourceArns: resourceArns
        })
      );
      return result.TagDescriptions || [];
    } catch (error) {
      this.log(`Error fetching tags for resources: ${error.message}`, 'warn');
      return [];
    }
  }
}

module.exports = AWSNetworkScanner;
