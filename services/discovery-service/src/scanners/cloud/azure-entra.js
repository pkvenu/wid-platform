// =============================================================================
// Azure Entra ID (Azure AD) Scanner - Discovers identity workloads from Entra ID
// =============================================================================
// Scans for:
// 1. App Registrations (client secrets, certificates, permissions)
// 2. Service Principals (role assignments, sign-in activity)
// 3. Directory Role Assignments (privileged roles, membership)
// 4. Conditional Access Policies (MFA, compliance posture)
// =============================================================================
// Auto-discovered by ScannerRegistry. Requires:
//   - @azure/identity (DefaultAzureCredential)
//   - @microsoft/microsoft-graph-client
// =============================================================================

const BaseScanner = require('../base/BaseScanner');

// Privileged directory roles that warrant elevated scrutiny
const PRIVILEGED_ROLES = new Set([
  'Global Administrator',
  'Privileged Role Administrator',
  'Application Administrator',
  'Cloud Application Administrator',
  'Exchange Administrator',
  'SharePoint Administrator',
  'Security Administrator',
  'User Administrator',
  'Helpdesk Administrator',
  'Authentication Administrator',
  'Privileged Authentication Administrator',
  'Conditional Access Administrator',
  'Global Reader',
]);

class AzureEntraScanner extends BaseScanner {
  constructor(config = {}) {
    super(config);
    this.provider = 'azure';
    this.version = '1.0.0';
    this.tenantId = config.tenantId || process.env.AZURE_TENANT_ID;
    this.initialized = false;

    if (!this.tenantId) {
      this.enabled = false;
      this.disabledReason = 'Requires AZURE_TENANT_ID + Azure credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)';
    }
  }

  getRequiredCredentials() {
    return [
      { name: 'AZURE_TENANT_ID', description: 'Azure AD tenant ID' },
      { name: 'AZURE_CLIENT_ID', description: 'Azure AD app client ID' },
      { name: 'AZURE_CLIENT_SECRET', description: 'Azure AD app client secret' },
    ];
  }

  async initializeAzure() {
    if (this.initialized) return;

    try {
      const { DefaultAzureCredential } = require('@azure/identity');
      const { Client } = require('@microsoft/microsoft-graph-client');
      const { TokenCredentialAuthenticationProvider } = require('@azure/identity');

      const credential = new DefaultAzureCredential();
      const authProvider = new TokenCredentialAuthenticationProvider(credential, {
        scopes: ['https://graph.microsoft.com/.default'],
      });

      this.graphClient = Client.initWithMiddleware({
        authProvider,
      });

      this.initialized = true;
      this.log(`Azure Entra ID SDK initialized for tenant: ${this.tenantId}`, 'info');
    } catch (error) {
      throw new Error(`Failed to initialize Azure Entra ID SDK: ${error.message}`);
    }
  }

  async validate() {
    if (!this.tenantId) {
      this.log('AZURE_TENANT_ID not set', 'error');
      return false;
    }
    try {
      await this.initializeAzure();
      this.log(`Connected to Azure Entra ID tenant: ${this.tenantId}`, 'success');
      return true;
    } catch (error) {
      this.log(`Azure Entra ID validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  getCapabilities() {
    return ['discover', 'app-registrations', 'service-principals', 'directory-roles', 'conditional-access'];
  }

  async discover() {
    await this.initializeAzure();

    this.log(`Starting Azure Entra ID discovery for tenant: ${this.tenantId}`, 'info');
    const workloads = [];

    try {
      const appRegs = await this.discoverAppRegistrations();
      workloads.push(...appRegs);
      this.log(`Found ${appRegs.length} App Registrations`, 'success');

      const servicePrincipals = await this.discoverServicePrincipals();
      workloads.push(...servicePrincipals);
      this.log(`Found ${servicePrincipals.length} Service Principals`, 'success');

      const directoryRoles = await this.discoverDirectoryRoles();
      workloads.push(...directoryRoles);
      this.log(`Found ${directoryRoles.length} Directory Roles`, 'success');

      const caPolicies = await this.discoverConditionalAccessPolicies();
      workloads.push(...caPolicies);
      this.log(`Found ${caPolicies.length} Conditional Access Policies`, 'success');

    } catch (error) {
      this.log(`Discovery error: ${error.message}`, 'error');
    }

    return workloads;
  }

  // ═══════════════════════════════════════════════════════════════
  // App Registrations
  // ═══════════════════════════════════════════════════════════════

  async discoverAppRegistrations() {
    try {
      const workloads = [];
      const response = await this.graphClient.api('/applications').top(999).get();
      const apps = response.value || [];

      for (const app of apps) {
        const now = new Date();

        // --- Client secrets analysis (never expose actual values) ---
        const clientSecrets = (app.passwordCredentials || []).map(secret => {
          const endDate = secret.endDateTime ? new Date(secret.endDateTime) : null;
          const isExpired = endDate ? endDate < now : false;
          const daysUntilExpiry = endDate
            ? Math.ceil((endDate - now) / (1000 * 60 * 60 * 24))
            : null;
          return {
            id: secret.keyId,
            display_name: secret.displayName || null,
            end_date: secret.endDateTime || null,
            is_expired: isExpired,
            days_until_expiry: daysUntilExpiry,
          };
        });

        // --- Certificate analysis ---
        const certificates = (app.keyCredentials || []).map(cert => {
          const endDate = cert.endDateTime ? new Date(cert.endDateTime) : null;
          const isExpired = endDate ? endDate < now : false;
          return {
            id: cert.keyId,
            display_name: cert.displayName || null,
            end_date: cert.endDateTime || null,
            is_expired: isExpired,
            thumbprint: cert.customKeyIdentifier || null,
            type: cert.type || null,
          };
        });

        const hasExpiredSecrets = clientSecrets.some(s => s.is_expired);
        const hasExpiredCerts = certificates.some(c => c.is_expired);
        const totalSecrets = clientSecrets.length;
        const totalCerts = certificates.length;

        // --- API permissions ---
        const apiPermissions = (app.requiredResourceAccess || []).flatMap(resource =>
          (resource.resourceAccess || []).map(perm => perm.id)
        );

        const isMultiTenant = app.signInAudience !== 'AzureADMyOrg';
        const name = app.displayName || app.appId;

        const workload = {
          name,
          type: 'app-registration',
          namespace: 'entra-id',
          environment: this.inferEnvironmentFromName(name),

          category: 'identity',
          subcategory: 'app-registration',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            app_id: app.appId,
            object_id: app.id,
            display_name: app.displayName,
            sign_in_audience: app.signInAudience,
            created_datetime: app.createdDateTime || null,
            client_secrets: clientSecrets,
            certificates,
            has_expired_secrets: hasExpiredSecrets,
            has_expired_certs: hasExpiredCerts,
            total_secrets: totalSecrets,
            total_certs: totalCerts,
            api_permissions: apiPermissions,
            is_multi_tenant: isMultiTenant,
            identifier_uris: app.identifierUris || [],
            web_redirect_uris: (app.web && app.web.redirectUris) || [],
            spa_redirect_uris: (app.spa && app.spa.redirectUris) || [],
          },

          cloud_provider: 'azure',
          region: 'global',
          account_id: this.tenantId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure-entra://${this.tenantId}`,
          cluster_id: this.tenantId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: this.isShadowService({}, { name }),
          shadow_score: this.calculateShadowScore({}, { name }),

          status: 'active',
          discovered_by: 'azure-entra-scanner',
        };

        workload.security_score = this.calculateAppRegistrationScore(workload, clientSecrets, certificates);
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering App Registrations: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Service Principals
  // ═══════════════════════════════════════════════════════════════

  async discoverServicePrincipals() {
    try {
      const workloads = [];
      const response = await this.graphClient.api('/servicePrincipals').top(999).get();
      const principals = (response.value || []).filter(
        sp => sp.servicePrincipalType === 'Application'
      );

      for (const sp of principals) {
        // Fetch app role assignments for this service principal
        let appRoleAssignments = [];
        try {
          const roleResponse = await this.graphClient
            .api(`/servicePrincipals/${sp.id}/appRoleAssignments`)
            .get();
          appRoleAssignments = (roleResponse.value || []).map(ra => ({
            resource_display_name: ra.resourceDisplayName || null,
            app_role_id: ra.appRoleId || null,
            principal_type: ra.principalType || null,
            created_datetime: ra.createdDateTime || null,
          }));
        } catch (roleError) {
          this.log(`Could not fetch role assignments for SP ${sp.displayName}: ${roleError.message}`, 'warn');
        }

        const name = sp.displayName || sp.appId;
        const accountEnabled = sp.accountEnabled !== false;

        // Check for recent sign-in activity
        const signInActivity = sp.signInActivity || null;
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        const hasRecentSignIn = signInActivity && signInActivity.lastSignInDateTime
          ? new Date(signInActivity.lastSignInDateTime) > thirtyDaysAgo
          : false;

        const workload = {
          name,
          type: 'service-principal',
          namespace: 'entra-id',
          environment: this.inferEnvironmentFromName(name),

          category: 'identity',
          subcategory: 'service-principal',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            app_id: sp.appId,
            object_id: sp.id,
            display_name: sp.displayName,
            service_principal_type: sp.servicePrincipalType,
            account_enabled: accountEnabled,
            app_role_assignments: appRoleAssignments,
            app_role_assignment_count: appRoleAssignments.length,
            sign_in_activity: signInActivity,
            notification_email_addresses: sp.notificationEmailAddresses || [],
            preferred_single_sign_on_mode: sp.preferredSingleSignOnMode || null,
            tags: sp.tags || [],
          },

          cloud_provider: 'azure',
          region: 'global',
          account_id: this.tenantId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure-entra://${this.tenantId}`,
          cluster_id: this.tenantId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: this.isShadowService({}, { name }),
          shadow_score: this.calculateShadowScore({}, { name }),

          status: accountEnabled ? 'active' : 'inactive',
          discovered_by: 'azure-entra-scanner',
        };

        workload.security_score = this.calculateServicePrincipalScore(
          workload, accountEnabled, appRoleAssignments, hasRecentSignIn
        );
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Service Principals: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Directory Role Assignments
  // ═══════════════════════════════════════════════════════════════

  async discoverDirectoryRoles() {
    try {
      const workloads = [];
      const response = await this.graphClient.api('/directoryRoles').get();
      const roles = response.value || [];

      for (const role of roles) {
        // Fetch members for this role
        let members = [];
        try {
          const membersResponse = await this.graphClient
            .api(`/directoryRoles/${role.id}/members`)
            .get();
          members = (membersResponse.value || []).map(member => ({
            id: member.id,
            display_name: member.displayName || null,
            type: this.inferMemberType(member),
          }));
        } catch (memberError) {
          this.log(`Could not fetch members for role ${role.displayName}: ${memberError.message}`, 'warn');
        }

        const hasServicePrincipalMembers = members.some(m => m.type === 'servicePrincipal');
        const isPrivileged = PRIVILEGED_ROLES.has(role.displayName);
        const name = role.displayName || role.id;

        const workload = {
          name,
          type: 'directory-role',
          namespace: 'entra-id',
          environment: 'production',

          category: 'permission',
          subcategory: 'directory-role',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            role_id: role.id,
            display_name: role.displayName,
            description: role.description || null,
            role_template_id: role.roleTemplateId || null,
            is_builtin: role.isBuiltIn !== false,
            members,
            member_count: members.length,
            has_service_principal_members: hasServicePrincipalMembers,
            is_privileged: isPrivileged,
          },

          cloud_provider: 'azure',
          region: 'global',
          account_id: this.tenantId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure-entra://${this.tenantId}`,
          cluster_id: this.tenantId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: false,
          shadow_score: 0,

          status: 'active',
          discovered_by: 'azure-entra-scanner',
        };

        workload.security_score = this.calculateDirectoryRoleScore(
          workload, isPrivileged, members, hasServicePrincipalMembers
        );
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Directory Roles: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Conditional Access Policies
  // ═══════════════════════════════════════════════════════════════

  async discoverConditionalAccessPolicies() {
    try {
      const workloads = [];
      const response = await this.graphClient.api('/identity/conditionalAccess/policies').get();
      const policies = response.value || [];

      for (const policy of policies) {
        const conditions = this.summarizeConditions(policy.conditions);
        const grantControls = this.summarizeGrantControls(policy.grantControls);
        const sessionControls = this.summarizeSessionControls(policy.sessionControls);

        const targetsAllUsers = this.conditionTargetsAll(policy.conditions, 'users');
        const targetsAllApps = this.conditionTargetsAll(policy.conditions, 'applications');
        const requiresMfa = grantControls.built_in_controls
          ? grantControls.built_in_controls.includes('mfa')
          : false;
        const isReportOnly = policy.state === 'enabledForReportingButNotEnforced';
        const name = policy.displayName || policy.id;

        const workload = {
          name,
          type: 'conditional-access-policy',
          namespace: 'entra-id',
          environment: 'production',

          category: 'access-policy',
          subcategory: 'conditional-access',
          is_ai_agent: false,
          is_mcp_server: false,

          labels: {},
          metadata: {
            policy_id: policy.id,
            display_name: policy.displayName,
            state: policy.state,
            created_datetime: policy.createdDateTime || null,
            modified_datetime: policy.modifiedDateTime || null,
            conditions,
            grant_controls: grantControls,
            session_controls: sessionControls,
            targets_all_users: targetsAllUsers,
            targets_all_apps: targetsAllApps,
            requires_mfa: requiresMfa,
            is_report_only: isReportOnly,
          },

          cloud_provider: 'azure',
          region: 'global',
          account_id: this.tenantId,
          trust_domain: this.config.trustDomain || 'company.com',
          issuer: `azure-entra://${this.tenantId}`,
          cluster_id: this.tenantId,

          owner: null,
          team: null,
          cost_center: null,

          is_shadow: false,
          shadow_score: 0,

          status: policy.state === 'enabled' ? 'active' : 'inactive',
          discovered_by: 'azure-entra-scanner',
        };

        workload.security_score = this.calculateConditionalAccessScore(
          workload, requiresMfa, targetsAllUsers, policy.state
        );
        workloads.push(workload);
      }

      return workloads;
    } catch (error) {
      this.log(`Error discovering Conditional Access Policies: ${error.message}`, 'error');
      return [];
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Security Score Helpers
  // ═══════════════════════════════════════════════════════════════

  calculateAppRegistrationScore(workload, clientSecrets, certificates) {
    let score = this.calculateSecurityScore(workload);

    const hasExpiredSecrets = clientSecrets.some(s => s.is_expired);
    if (hasExpiredSecrets) score -= 20;

    const totalSecrets = clientSecrets.length;
    if (totalSecrets > 2) score -= 15;

    if (workload.metadata.is_multi_tenant) score -= 10;

    // Secrets older than 180 days
    const now = new Date();
    const cutoff = new Date(now.getTime() - 180 * 24 * 60 * 60 * 1000);
    const hasOldSecrets = clientSecrets.some(s => {
      if (!s.end_date) return false;
      // If a secret has a very long expiry (end_date far in future) but was
      // created long ago, the start date is not available in the credential
      // object. Approximate by checking if days_until_expiry + 180 < total
      // lifespan. Simpler heuristic: if there IS an end_date, check whether
      // end_date minus a generous 1-year window puts creation before cutoff.
      const endDate = new Date(s.end_date);
      const estimatedCreation = new Date(endDate.getTime() - 365 * 24 * 60 * 60 * 1000);
      return estimatedCreation < cutoff;
    });
    if (hasOldSecrets) score -= 10;

    // Bonus for certificate-based auth instead of secrets
    if (certificates.length > 0 && totalSecrets === 0) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateServicePrincipalScore(workload, accountEnabled, appRoleAssignments, hasRecentSignIn) {
    let score = this.calculateSecurityScore(workload);

    // Orphaned: disabled but still has active role assignments
    if (!accountEnabled && appRoleAssignments.length > 0) score -= 15;

    // Overprivileged: too many role assignments
    if (appRoleAssignments.length > 5) score -= 10;

    // Active usage is a positive signal
    if (hasRecentSignIn) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateDirectoryRoleScore(workload, isPrivileged, members, hasServicePrincipalMembers) {
    let score = this.calculateSecurityScore(workload);

    // Privileged role with too many members
    if (isPrivileged && members.length > 3) score -= 25;

    // Service principals in privileged roles
    if (isPrivileged && hasServicePrincipalMembers) score -= 15;

    // Tight membership on privileged roles is a good signal
    if (isPrivileged && members.length <= 2) score += 10;

    return Math.max(0, Math.min(100, score));
  }

  calculateConditionalAccessScore(workload, requiresMfa, targetsAllUsers, state) {
    let score = this.calculateSecurityScore(workload);

    // MFA targeting all users is the gold standard
    if (requiresMfa && targetsAllUsers) score += 15;

    // Enabled policy is better than report-only
    if (state === 'enabled') score += 10;

    // Disabled policies are a negative signal
    if (state === 'disabled') score -= 10;

    // Report-only: partial credit
    if (state === 'enabledForReportingButNotEnforced') score -= 5;

    return Math.max(0, Math.min(100, score));
  }

  // ═══════════════════════════════════════════════════════════════
  // General Helpers
  // ═══════════════════════════════════════════════════════════════

  /**
   * Infer environment from resource name when tags are unavailable (Entra ID
   * objects do not have Azure resource tags).
   */
  inferEnvironmentFromName(name) {
    const n = (name || '').toLowerCase();
    if (/prod/.test(n)) return 'production';
    if (/stag/.test(n)) return 'staging';
    if (/dev/.test(n)) return 'development';
    if (/test/.test(n)) return 'testing';
    return 'unknown';
  }

  /**
   * Determine the member type from the Graph object's @odata.type property.
   */
  inferMemberType(member) {
    const odataType = member['@odata.type'] || '';
    if (odataType.includes('servicePrincipal')) return 'servicePrincipal';
    if (odataType.includes('group')) return 'group';
    if (odataType.includes('user')) return 'user';
    // Fallback based on presence of servicePrincipalType
    if (member.servicePrincipalType) return 'servicePrincipal';
    return 'user';
  }

  /**
   * Summarize CA policy conditions into a compact metadata object.
   */
  summarizeConditions(conditions) {
    if (!conditions) return {};

    return {
      users_included: (conditions.users && conditions.users.includeUsers) || [],
      users_excluded: (conditions.users && conditions.users.excludeUsers) || [],
      groups_included: (conditions.users && conditions.users.includeGroups) || [],
      groups_excluded: (conditions.users && conditions.users.excludeGroups) || [],
      applications_included: (conditions.applications && conditions.applications.includeApplications) || [],
      applications_excluded: (conditions.applications && conditions.applications.excludeApplications) || [],
      platforms: (conditions.platforms && conditions.platforms.includePlatforms) || [],
      locations_included: (conditions.locations && conditions.locations.includeLocations) || [],
      locations_excluded: (conditions.locations && conditions.locations.excludeLocations) || [],
    };
  }

  /**
   * Summarize CA policy grant controls.
   */
  summarizeGrantControls(grantControls) {
    if (!grantControls) return {};

    return {
      built_in_controls: grantControls.builtInControls || [],
      operator: grantControls.operator || null,
      custom_authentication_factors: grantControls.customAuthenticationFactors || [],
      terms_of_use: grantControls.termsOfUse || [],
    };
  }

  /**
   * Summarize CA policy session controls.
   */
  summarizeSessionControls(sessionControls) {
    if (!sessionControls) return {};

    return {
      application_enforced_restrictions: sessionControls.applicationEnforcedRestrictions
        ? { is_enabled: sessionControls.applicationEnforcedRestrictions.isEnabled }
        : null,
      cloud_app_security: sessionControls.cloudAppSecurity
        ? {
            is_enabled: sessionControls.cloudAppSecurity.isEnabled,
            cloud_app_security_type: sessionControls.cloudAppSecurity.cloudAppSecurityType,
          }
        : null,
      persistent_browser: sessionControls.persistentBrowser
        ? {
            is_enabled: sessionControls.persistentBrowser.isEnabled,
            mode: sessionControls.persistentBrowser.mode,
          }
        : null,
      sign_in_frequency: sessionControls.signInFrequency
        ? {
            is_enabled: sessionControls.signInFrequency.isEnabled,
            value: sessionControls.signInFrequency.value,
            type: sessionControls.signInFrequency.type,
          }
        : null,
    };
  }

  /**
   * Check whether a CA policy condition targets "All" for a given scope.
   * @param {Object} conditions - The policy conditions object
   * @param {'users'|'applications'} scope - Which condition scope to check
   */
  conditionTargetsAll(conditions, scope) {
    if (!conditions || !conditions[scope]) return false;

    if (scope === 'users') {
      return (conditions.users.includeUsers || []).includes('All');
    }
    if (scope === 'applications') {
      return (conditions.applications.includeApplications || []).includes('All');
    }
    return false;
  }
}

module.exports = AzureEntraScanner;
