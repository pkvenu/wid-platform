// =============================================================================
// IAM Scanner - Discovers IAM Roles, Users, Access Keys & Service Accounts
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

class IAMScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'aws';
    this.version = '1.0.0';
    this.region = config.region || process.env.AWS_DEFAULT_REGION || 'us-east-1';
    this.initialized = false;
  }

  async initializeAWS() {
    if (this.initialized) return;
    try {
      const { IAMClient, ListRolesCommand, ListUsersCommand, ListAccessKeysCommand,
              GetRoleCommand, ListAttachedRolePoliciesCommand, ListMFADevicesCommand,
              GetAccessKeyLastUsedCommand, ListServiceSpecificCredentialsCommand,
              ListGroupsCommand, GetGroupCommand, ListAttachedGroupPoliciesCommand,
              ListGroupPoliciesCommand, GetGroupPolicyCommand,
              ListRolePoliciesCommand, GetRolePolicyCommand,
              GetPolicyCommand, GetPolicyVersionCommand,
              ListGroupsForUserCommand } = require('@aws-sdk/client-iam');
      const { STSClient, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');

      this.iamClient = new IAMClient({ region: this.region });
      this.stsClient = new STSClient({ region: this.region });
      this.IAMCommands = {
        ListRolesCommand, ListUsersCommand, ListAccessKeysCommand,
        GetRoleCommand, ListAttachedRolePoliciesCommand, ListMFADevicesCommand,
        GetAccessKeyLastUsedCommand, ListServiceSpecificCredentialsCommand,
        ListGroupsCommand, GetGroupCommand, ListAttachedGroupPoliciesCommand,
        ListGroupPoliciesCommand, GetGroupPolicyCommand,
        ListRolePoliciesCommand, GetRolePolicyCommand,
        GetPolicyCommand, GetPolicyVersionCommand,
        ListGroupsForUserCommand
      };
      this.STSCommands = { GetCallerIdentityCommand };
      this.initialized = true;
      this.log('AWS IAM SDK initialized', 'info');
    } catch (error) {
      throw new Error(`Failed to initialize IAM SDK: ${error.message}`);
    }
  }

  async validate() {
    try {
      await this.initializeAWS();
      const cmd = new this.STSCommands.GetCallerIdentityCommand({});
      const res = await this.stsClient.send(cmd);
      this.accountId = res.Account;
      this.log(`Connected to AWS account: ${res.Account}`, 'success');
      return true;
    } catch (error) {
      this.log(`IAM validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'iam-roles', 'iam-users', 'iam-groups', 'access-keys', 'service-accounts', 'inline-policies', 'permission-boundaries'];
  }

  getRequiredCredentials() {
    return [
      { name: 'AWS_ACCESS_KEY_ID', description: 'AWS access key' },
      { name: 'AWS_SECRET_ACCESS_KEY', description: 'AWS secret key' },
    ];
  }

  async discover() {
    await this.initializeAWS();
    this.log('Starting IAM identity discovery', 'info');
    const workloads = [];

    // Discover IAM Roles (service accounts)
    const roles = await this.discoverRoles();
    workloads.push(...roles);
    this.log(`Found ${roles.length} IAM roles`, 'success');

    // Discover IAM Users + their access keys
    const users = await this.discoverUsers();
    workloads.push(...users);
    this.log(`Found ${users.length} IAM users/access keys`, 'success');

    // Discover IAM Groups
    const groups = await this.discoverGroups();
    workloads.push(...groups);
    this.log(`Found ${groups.length} IAM groups`, 'success');

    return workloads;
  }

  async discoverRoles() {
    try {
      const result = await this.iamClient.send(new this.IAMCommands.ListRolesCommand({ MaxItems: 200 }));
      const workloads = [];

      for (const role of result.Roles || []) {
        // Skip AWS service-linked roles (aws-service-role/) unless they're interesting
        const isServiceLinked = role.Path?.startsWith('/aws-service-role/');

        // Parse the trust policy to understand who can assume this role
        let assumableBy = [];
        let isLambdaRole = false;
        let isEC2Role = false;
        let isECSRole = false;
        try {
          const trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
          for (const stmt of trustPolicy.Statement || []) {
            const principal = stmt.Principal;
            if (principal?.Service) {
              const services = Array.isArray(principal.Service) ? principal.Service : [principal.Service];
              assumableBy.push(...services);
              if (services.includes('lambda.amazonaws.com')) isLambdaRole = true;
              if (services.includes('ec2.amazonaws.com')) isEC2Role = true;
              if (services.includes('ecs-tasks.amazonaws.com')) isECSRole = true;
            }
            if (principal?.AWS) {
              const awsPrincipals = Array.isArray(principal.AWS) ? principal.AWS : [principal.AWS];
              assumableBy.push(...awsPrincipals);
            }
          }
        } catch (e) { /* trust policy parse error - not critical */ }

        // Get attached policies
        let policies = [];
        try {
          const polRes = await this.iamClient.send(new this.IAMCommands.ListAttachedRolePoliciesCommand({ RoleName: role.RoleName }));
          policies = (polRes.AttachedPolicies || []).map(p => p.PolicyName);
        } catch (e) { /* permission error */ }

        // Get inline policies
        let inlinePolicies = [];
        try {
          const inlineRes = await this.iamClient.send(new this.IAMCommands.ListRolePoliciesCommand({ RoleName: role.RoleName }));
          for (const policyName of inlineRes.PolicyNames || []) {
            try {
              const policyDoc = await this.iamClient.send(new this.IAMCommands.GetRolePolicyCommand({ RoleName: role.RoleName, PolicyName: policyName }));
              const doc = JSON.parse(decodeURIComponent(policyDoc.PolicyDocument));
              const actions = [];
              for (const stmt of doc.Statement || []) {
                if (stmt.Effect === 'Allow') {
                  const a = Array.isArray(stmt.Action) ? stmt.Action : (stmt.Action ? [stmt.Action] : []);
                  actions.push(...a);
                }
              }
              inlinePolicies.push({ name: policyName, actions_summary: actions.slice(0, 20) });
            } catch (e) { inlinePolicies.push({ name: policyName, actions_summary: [] }); }
          }
        } catch (e) { /* permission error */ }

        // Permission boundary
        const permissionBoundaryArn = role.PermissionsBoundary?.PermissionsBoundaryArn || null;

        // Cross-account trust analysis
        let crossAccountTrusts = [];
        try {
          const trustPolicy = JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument));
          for (const stmt of trustPolicy.Statement || []) {
            const awsPrincipals = Array.isArray(stmt.Principal?.AWS) ? stmt.Principal.AWS : (stmt.Principal?.AWS ? [stmt.Principal.AWS] : []);
            for (const p of awsPrincipals) {
              const accountMatch = p.match(/arn:aws:iam::(\d{12}):/);
              if (accountMatch && accountMatch[1] !== this.accountId) {
                crossAccountTrusts.push({
                  account_id: accountMatch[1],
                  principal: p,
                  has_external_id: !!(stmt.Condition?.StringEquals?.['sts:ExternalId']),
                });
              }
              if (p === '*') {
                crossAccountTrusts.push({ account_id: '*', principal: '*', has_external_id: false });
              }
            }
          }
        } catch (e) { /* trust policy parse error */ }

        // Effective permissions summary
        const allActions = inlinePolicies.flatMap(p => p.actions_summary);
        const hasWildcardActions = allActions.some(a => a === '*') || policies.some(p => /AdministratorAccess/i.test(p));
        const sensitiveServices = [...new Set(allActions.filter(a => /^(iam|sts|kms|secretsmanager|organizations):/i.test(a)).map(a => a.split(':')[0].toLowerCase()))];
        const canEscalate = allActions.some(a => /iam:PassRole|iam:CreateRole|iam:AttachRolePolicy|iam:PutRolePolicy|iam:CreateUser|iam:CreateAccessKey|sts:AssumeRole/i.test(a));
        const escalationPaths = [];
        if (allActions.some(a => /iam:PassRole/i.test(a))) escalationPaths.push('iam:PassRole → assume admin role via Lambda/EC2');
        if (allActions.some(a => /iam:CreateAccessKey/i.test(a))) escalationPaths.push('iam:CreateAccessKey → create key for any user');
        if (allActions.some(a => /iam:AttachRolePolicy|iam:PutRolePolicy/i.test(a))) escalationPaths.push('iam:AttachRolePolicy → grant self admin');

        const hasAdminAccess = policies.some(p => /admin|fullaccess|poweruser/i.test(p)) || hasWildcardActions;

        // Fetch RoleLastUsed for zombie/unused-IAM detection
        let roleLastUsed = null;
        try {
          const roleDetail = await this.throttledCall(() =>
            this.iamClient.send(new this.IAMCommands.GetRoleCommand({ RoleName: role.RoleName })), 100
          );
          roleLastUsed = roleDetail.Role?.RoleLastUsed?.LastUsedDate || null;
        } catch (e) { /* permission error — non-critical */ }

        const workload = {
          name: role.RoleName,
          type: 'iam-role',
          namespace: 'iam',
          environment: this.inferEnvironment(role.RoleName, role.Tags),

          category: this.categorizeIAMRole(role, assumableBy, policies),
          subcategory: isLambdaRole ? 'lambda-execution' : isEC2Role ? 'ec2-instance-profile' : isECSRole ? 'ecs-task-role' : (isServiceLinked ? 'service-linked' : 'custom'),
          is_ai_agent: false,
          is_mcp_server: false,

          labels: this.parseTags(role.Tags),
          metadata: {
            arn: role.Arn,
            path: role.Path,
            create_date: role.CreateDate,
            max_session_duration: role.MaxSessionDuration,
            assumable_by: assumableBy,
            attached_policies: policies,
            inline_policies: inlinePolicies,
            permission_boundary_arn: permissionBoundaryArn,
            cross_account_trusts: crossAccountTrusts,
            has_admin_access: hasAdminAccess,
            is_service_linked: isServiceLinked,
            description: role.Description || null,
            role_last_used: roleLastUsed,
            effective_permissions_summary: {
              has_admin: hasAdminAccess,
              has_wildcard_actions: hasWildcardActions,
              sensitive_services: sensitiveServices,
              can_escalate: canEscalate,
              escalation_paths: escalationPaths,
            },
          },

          cloud_provider: 'aws',
          region: 'global',
          account_id: this.accountId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'aws://iam',
          cluster_id: this.accountId,

          owner: this.parseTags(role.Tags)?.owner || this.parseTags(role.Tags)?.Owner || null,
          team: this.parseTags(role.Tags)?.team || this.parseTags(role.Tags)?.Team || null,

          // Shadow/classification computed centrally by classifyWorkload() in saveWorkload()
          is_shadow: false,
          shadow_score: 0,

          discovered_by: 'iam-scanner'
        };

        workload.security_score = this.calculateIAMSecurityScore(workload, hasAdminAccess, isServiceLinked);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering IAM roles: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverUsers() {
    try {
      const result = await this.iamClient.send(new this.IAMCommands.ListUsersCommand({ MaxItems: 200 }));
      const workloads = [];

      for (const user of result.Users || []) {
        // Check for MFA
        let hasMFA = false;
        try {
          const mfaRes = await this.iamClient.send(new this.IAMCommands.ListMFADevicesCommand({ UserName: user.UserName }));
          hasMFA = (mfaRes.MFADevices || []).length > 0;
        } catch (e) { /* permission error */ }

        // Discover access keys for this user
        let accessKeys = [];
        try {
          const keysRes = await this.iamClient.send(new this.IAMCommands.ListAccessKeysCommand({ UserName: user.UserName }));
          for (const key of keysRes.AccessKeyMetadata || []) {
            let lastUsed = null;
            try {
              const usedRes = await this.iamClient.send(new this.IAMCommands.GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId }));
              lastUsed = usedRes.AccessKeyLastUsed;
            } catch (e) { /* */ }

            accessKeys.push({
              access_key_id: key.AccessKeyId,
              status: key.Status,
              create_date: key.CreateDate,
              last_used_date: lastUsed?.LastUsedDate || null,
              last_used_service: lastUsed?.ServiceName || null,
              last_used_region: lastUsed?.Region || null
            });
          }
        } catch (e) { /* permission error */ }

        // Get group memberships
        let groups = [];
        try {
          const groupRes = await this.iamClient.send(new this.IAMCommands.ListGroupsForUserCommand({ UserName: user.UserName }));
          groups = (groupRes.Groups || []).map(g => ({ name: g.GroupName, arn: g.Arn }));
        } catch (e) { /* permission error */ }

        // Determine if this is a service/machine user (no console login, has access keys)
        const isServiceUser = accessKeys.length > 0 && !user.PasswordLastUsed;

        // Calculate key age
        const oldestKeyAge = accessKeys.reduce((max, k) => {
          const age = (Date.now() - new Date(k.create_date).getTime()) / 86400000;
          return Math.max(max, age);
        }, 0);

        // Find stale keys (not used in 90+ days or never used)
        const staleKeys = accessKeys.filter(k => {
          if (!k.last_used_date) return true;
          const daysSinceUse = (Date.now() - new Date(k.last_used_date).getTime()) / 86400000;
          return daysSinceUse > 90;
        });

        const workload = {
          name: user.UserName,
          type: isServiceUser ? 'service-account' : 'iam-user',
          namespace: 'iam',
          environment: this.inferEnvironment(user.UserName, user.Tags),

          category: isServiceUser ? 'service-account' : 'iam-user',
          subcategory: isServiceUser ? 'machine-user' : 'human-user',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {
            ...this.parseTags(user.Tags),
            has_mfa: String(hasMFA),
            access_key_count: String(accessKeys.length),
            is_service_user: String(isServiceUser)
          },
          metadata: {
            arn: user.Arn,
            path: user.Path,
            create_date: user.CreateDate,
            password_last_used: user.PasswordLastUsed || null,
            has_mfa: hasMFA,
            access_keys: accessKeys,
            stale_keys_count: staleKeys.length,
            oldest_key_age_days: Math.round(oldestKeyAge),
            has_console_access: !!user.PasswordLastUsed,
            groups: groups,
            group_count: groups.length,
          },

          cloud_provider: 'aws',
          region: 'global',
          account_id: this.accountId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'aws://iam',
          cluster_id: this.accountId,

          owner: this.parseTags(user.Tags)?.owner || null,
          team: this.parseTags(user.Tags)?.team || null,

          // Shadow/classification computed centrally by classifyWorkload() in saveWorkload()
          is_shadow: false,
          shadow_score: 0,

          discovered_by: 'iam-scanner'
        };

        workload.security_score = this.calculateUserSecurityScore(workload, hasMFA, staleKeys, oldestKeyAge);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering IAM users: ${error.message}`, 'error');
      return [];
    }
  }

  async discoverGroups() {
    try {
      const result = await this.iamClient.send(new this.IAMCommands.ListGroupsCommand({ MaxItems: 200 }));
      const workloads = [];

      for (const group of result.Groups || []) {
        // Get group members
        let memberArns = [];
        try {
          const groupDetail = await this.iamClient.send(new this.IAMCommands.GetGroupCommand({ GroupName: group.GroupName }));
          memberArns = (groupDetail.Users || []).map(u => u.Arn);
        } catch (e) { /* permission error */ }

        // Get attached (managed) policies
        let attachedPolicies = [];
        try {
          const polRes = await this.iamClient.send(new this.IAMCommands.ListAttachedGroupPoliciesCommand({ GroupName: group.GroupName }));
          attachedPolicies = (polRes.AttachedPolicies || []).map(p => p.PolicyName);
        } catch (e) { /* permission error */ }

        // Get inline policies
        let inlinePolicies = [];
        try {
          const inlineRes = await this.iamClient.send(new this.IAMCommands.ListGroupPoliciesCommand({ GroupName: group.GroupName }));
          for (const policyName of inlineRes.PolicyNames || []) {
            try {
              const policyDoc = await this.iamClient.send(new this.IAMCommands.GetGroupPolicyCommand({ GroupName: group.GroupName, PolicyName: policyName }));
              const doc = JSON.parse(decodeURIComponent(policyDoc.PolicyDocument));
              const actions = [];
              for (const stmt of doc.Statement || []) {
                if (stmt.Effect === 'Allow') {
                  const a = Array.isArray(stmt.Action) ? stmt.Action : (stmt.Action ? [stmt.Action] : []);
                  actions.push(...a);
                }
              }
              inlinePolicies.push({ name: policyName, actions_summary: actions.slice(0, 20) });
            } catch (e) { inlinePolicies.push({ name: policyName, actions_summary: [] }); }
          }
        } catch (e) { /* permission error */ }

        const allPolicies = [...attachedPolicies, ...inlinePolicies.map(p => p.name)];
        const hasAdminAccess = allPolicies.some(p => /admin|fullaccess|poweruser/i.test(p));

        const workload = {
          name: group.GroupName,
          type: 'iam-group',
          namespace: 'iam',
          environment: this.inferEnvironment(group.GroupName, []),

          category: 'identity-group',
          subcategory: hasAdminAccess ? 'admin-group' : 'standard-group',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            arn: group.Arn,
            path: group.Path,
            group_id: group.GroupId,
            create_date: group.CreateDate,
            member_arns: memberArns,
            member_count: memberArns.length,
            attached_policies: attachedPolicies,
            inline_policies: inlinePolicies,
            has_admin_access: hasAdminAccess,
          },

          cloud_provider: 'aws',
          region: 'global',
          account_id: this.accountId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: 'aws://iam',
          cluster_id: this.accountId,

          owner: null,
          team: null,

          // Shadow/classification computed centrally by classifyWorkload() in saveWorkload()
          is_shadow: false,
          shadow_score: 0,

          discovered_by: 'iam-scanner'
        };

        workload.security_score = this.calculateGroupSecurityScore(workload, hasAdminAccess, memberArns.length);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering IAM groups: ${error.message}`, 'error');
      return [];
    }
  }

  // ── Helpers ──

  inferEnvironment(name, tags) {
    const parsedTags = this.parseTags(tags);
    if (parsedTags.environment) return parsedTags.environment;
    if (parsedTags.Environment) return parsedTags.Environment;
    const n = (name || '').toLowerCase();
    if (/prod/.test(n)) return 'production';
    if (/stag/.test(n)) return 'staging';
    if (/dev/.test(n)) return 'development';
    if (/test/.test(n)) return 'testing';
    return 'unknown';
  }

  categorizeIAMRole(role, assumableBy, policies) {
    if (assumableBy.some(s => s.includes('lambda'))) return 'lambda-execution-role';
    if (assumableBy.some(s => s.includes('ec2'))) return 'ec2-instance-role';
    if (assumableBy.some(s => s.includes('ecs'))) return 'ecs-task-role';
    if (assumableBy.some(s => s.includes('sagemaker'))) return 'ml-execution-role';
    if (role.Path?.startsWith('/aws-service-role/')) return 'service-linked-role';
    if (policies.some(p => /admin/i.test(p))) return 'admin-role';
    return 'iam-role';
  }

  isRoleShadow(role, policies, assumableBy) {
    const tags = this.parseTags(role.Tags);
    if (!tags.owner && !tags.Owner && !tags.team && !tags.Team) return true;
    if (!role.Description && (role.Path === '/' || !role.Path)) return true;
    return false;
  }

  calculateRoleShadowScore(role, policies, assumableBy) {
    let score = 0;
    const tags = this.parseTags(role.Tags);
    if (!tags.owner && !tags.Owner) score += 30;
    if (!tags.team && !tags.Team) score += 20;
    if (!role.Description) score += 15;
    if (role.Path === '/' || !role.Path) score += 10;
    const name = (role.RoleName || '').toLowerCase();
    if (/^(test|tmp|dev)/.test(name)) score += 25;
    return Math.min(100, score);
  }

  isUserShadow(user, accessKeys) {
    const tags = this.parseTags(user.Tags);
    if (!tags.owner && !tags.Owner) return true;
    // Stale: no password use and no key use in 90 days
    if (!user.PasswordLastUsed && accessKeys.every(k => !k.last_used_date)) return true;
    return false;
  }

  calculateUserShadowScore(user, accessKeys, hasMFA) {
    let score = 0;
    const tags = this.parseTags(user.Tags);
    if (!tags.owner && !tags.Owner) score += 25;
    if (!hasMFA) score += 20;
    if (accessKeys.length === 0 && !user.PasswordLastUsed) score += 30;
    const name = (user.UserName || '').toLowerCase();
    if (/^(test|tmp|svc-)/.test(name)) score += 15;
    return Math.min(100, score);
  }

  calculateIAMSecurityScore(workload, hasAdminAccess, isServiceLinked) {
    let score = this.calculateSecurityScore(workload);
    if (hasAdminAccess) score -= 20;
    if (isServiceLinked) score += 10; // AWS-managed = safer
    // Cross-account trust penalties
    const crossAccount = workload.metadata?.cross_account_trusts || [];
    if (crossAccount.some(t => t.principal === '*')) score -= 30; // Trust ANY account = critical
    else if (crossAccount.length > 0 && crossAccount.some(t => !t.has_external_id)) score -= 15; // No ExternalId
    // Permission boundary bonus
    if (workload.metadata?.permission_boundary_arn) score += 10;
    // Escalation penalty
    if (workload.metadata?.effective_permissions_summary?.can_escalate) score -= 15;
    return Math.max(0, Math.min(100, score));
  }

  calculateGroupSecurityScore(workload, hasAdminAccess, memberCount) {
    let score = this.calculateSecurityScore(workload);
    if (hasAdminAccess) score -= 25;
    if (memberCount > 10) score -= 10; // Large groups = broad blast radius
    if (memberCount === 0) score -= 5; // Empty group = possibly stale
    return Math.max(0, Math.min(100, score));
  }

  calculateUserSecurityScore(workload, hasMFA, staleKeys, oldestKeyAge) {
    let score = this.calculateSecurityScore(workload);
    if (!hasMFA) score -= 20;
    if (staleKeys.length > 0) score -= 15;
    if (oldestKeyAge > 365) score -= 15; // Keys older than 1 year
    if (oldestKeyAge > 90) score -= 5;
    return Math.max(0, Math.min(100, score));
  }
}

module.exports = IAMScanner;