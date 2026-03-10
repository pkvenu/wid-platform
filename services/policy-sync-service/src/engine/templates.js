// =============================================================================
// Policy Templates — All 6 Policy Types
// =============================================================================
// Each template is a ready-to-deploy policy. Templates are grouped by type.
// =============================================================================

const POLICY_TEMPLATES = {

  // ══════════════════════════════════════════════════════════════════════════
  // 1. COMPLIANCE / POSTURE
  // ══════════════════════════════════════════════════════════════════════════

  'prod-attestation-required': {
    name: 'Production Attestation Required',
    description: 'All production workloads must be attested before deployment.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'attestation', 'scope'],
    conditions: [
      { field: 'environment', operator: 'equals', value: 'production' },
      { field: 'verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Production workload is not attested' },
      { type: 'block_deploy', message: 'Deployment blocked — attestation required' },
    ],
    scope_environment: 'production',
  },

  'no-owner-violation': {
    name: 'Owner Required for All Identities',
    description: 'Every NHI must have an assigned owner for accountability.',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture', 'attestation', 'scope'],
    conditions: [{ field: 'owner', operator: 'not_exists' }],
    actions: [
      { type: 'flag', message: 'Identity has no assigned owner' },
      { type: 'notify', message: 'Unowned identity detected — assign an owner' },
    ],
  },

  'shadow-identity-detection': {
    name: 'Shadow Identity Detection',
    description: 'Shadow identities must be reviewed and either attested or decommissioned.',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture', 'attestation'],
    conditions: [{ field: 'is_shadow', operator: 'is_true' }],
    actions: [
      { type: 'flag', message: 'Shadow identity detected' },
      { type: 'require_attest', message: 'Attestation required to clear shadow status' },
    ],
  },

  'no-spiffe-production': {
    name: 'SPIFFE Identity Required in Production',
    description: 'All production workloads should have a SPIFFE identity for zero-trust mesh.',
    policy_type: 'compliance', severity: 'medium',
    tags: ['compliance', 'posture', 'agent', 'attestation'],
    conditions: [
      { field: 'environment', operator: 'equals', value: 'production' },
      { field: 'spiffe_id', operator: 'not_exists' },
    ],
    actions: [
      { type: 'flag', message: 'Production workload has no SPIFFE identity' },
      { type: 'notify', message: 'Deploy SPIRE agent to provision SPIFFE ID' },
    ],
  },

  'naming-convention': {
    name: 'NHI Naming Convention Required',
    description: 'All service accounts must follow svc-{env}-{purpose} naming convention.',
    policy_type: 'compliance', severity: 'medium',
    tags: ['compliance', 'posture', 'agent'],
    conditions: [
      { field: 'type', operator: 'in', value: 'service-account,iam-role,iam-user' },
      { field: 'name', operator: 'matches', value: '^(?!svc-(prod|staging|dev|test)-)' },
    ],
    actions: [
      { type: 'flag', message: 'Identity name does not follow naming convention (svc-{env}-{purpose})' },
      { type: 'notify', message: 'Rename identity to match organizational naming standard' },
    ],
  },

  'secret-engine-audit': {
    name: 'Secret Engine Audit',
    description: 'All secret engines and credential stores must be attested and have an owner.',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'secret,secret-engine' },
      { field: 'verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Unattested secret engine/credential store' },
      { type: 'require_attest', message: 'Secret engines must be attested for compliance' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 2. LIFECYCLE
  // ══════════════════════════════════════════════════════════════════════════

  'stale-credential-lifecycle': {
    name: 'Stale Credential Lifecycle',
    description: 'Identities not seen in 90+ days should be reviewed for decommissioning.',
    policy_type: 'lifecycle', severity: 'medium',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'last_seen', operator: 'older_than_days', value: '90' }],
    actions: [
      { type: 'flag', message: 'Identity is stale (>90 days inactive)' },
      { type: 'quarantine', message: 'Quarantine stale identity pending review' },
    ],
  },

  'credential-rotation-overdue': {
    name: 'Credential Rotation Overdue',
    description: 'Credentials not rotated in 90 days violate rotation policy.',
    policy_type: 'lifecycle', severity: 'high',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'last_rotation', operator: 'older_than_days', value: '90' }],
    actions: [
      { type: 'flag', message: 'Credential rotation overdue (>90 days)' },
      { type: 'force_rotation', message: 'Triggering automatic credential rotation' },
      { type: 'notify', message: 'Credential rotation required within 7 days' },
    ],
  },

  'max-credential-age': {
    name: 'Maximum Credential Age (365 Days)',
    description: 'No credential should be older than 365 days. Auto-disable after limit.',
    policy_type: 'lifecycle', severity: 'critical',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'created_at', operator: 'older_than_days', value: '365' }],
    actions: [
      { type: 'flag', message: 'Credential exceeds maximum age (365 days)' },
      { type: 'disable_identity', message: 'Identity disabled — credential age limit exceeded' },
      { type: 'schedule_decommission', message: 'Scheduled for decommission in 30 days' },
    ],
  },

  'inactivity-timeout-30': {
    name: 'Inactivity Timeout (30 Days)',
    description: 'Identities inactive for 30+ days are flagged; 60+ days are disabled.',
    policy_type: 'lifecycle', severity: 'medium',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'inactive_days', operator: 'gt', value: '30' }],
    actions: [
      { type: 'flag', message: 'Identity inactive for 30+ days' },
      { type: 'notify', message: 'Review inactive identity — disable if no longer needed' },
    ],
  },

  'expiry-enforcement': {
    name: 'Credential Expiry Enforcement',
    description: 'Credentials must be renewed before expiry. Flag 14 days before, disable on expiry.',
    policy_type: 'lifecycle', severity: 'high',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'expiry_date', operator: 'newer_than_days', value: '14' }],
    actions: [
      { type: 'flag', message: 'Credential expiring within 14 days' },
      { type: 'notify', message: 'Credential renewal required before expiry' },
      { type: 'force_rotation', message: 'Auto-rotate credential before expiry' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 3. ACCESS POLICIES
  // ══════════════════════════════════════════════════════════════════════════

  'cross-env-access-deny': {
    name: 'Block Cross-Environment Access',
    description: 'Production services cannot access staging/dev resources and vice versa.',
    policy_type: 'access', severity: 'critical',
    tags: ['access'],
    conditions: [
      { field: 'client.environment', operator: 'equals', value: 'production' },
      { field: 'server.environment', operator: 'not_equals', value: 'production' },
    ],
    actions: [
      { type: 'deny', message: 'Cross-environment access denied (prod → non-prod)' },
      { type: 'flag', message: 'Cross-environment access attempt detected' },
    ],
  },

  'prod-requires-attestation': {
    name: 'Attested Clients Only for Production Resources',
    description: 'Only attested workloads with HIGH+ trust can access production servers.',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'attestation'],
    conditions: [
      { field: 'server.environment', operator: 'equals', value: 'production' },
      { field: 'client.verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Unattested client cannot access production resource' },
      { type: 'require_attest', message: 'Client must be attested before accessing production' },
    ],
  },

  'prod-min-trust-access': {
    name: 'Minimum Trust Level for Production Access',
    description: 'Clients must have HIGH or above trust to access production servers.',
    policy_type: 'access', severity: 'critical',
    tags: ['access'],
    conditions: [
      { field: 'server.environment', operator: 'equals', value: 'production' },
      { field: 'client.trust_level', operator: 'in', value: 'low,none,medium' },
    ],
    actions: [
      { type: 'deny', message: 'Insufficient trust level for production access' },
      { type: 'flag', message: 'Low-trust client attempted production access' },
    ],
  },

  'pii-data-access': {
    name: 'PII Data Access Restriction',
    description: 'Only explicitly approved services can access PII-classified resources.',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'attestation'],
    conditions: [
      { field: 'server.data_classification', operator: 'in', value: 'pii,restricted' },
      { field: 'client.trust_level', operator: 'not_equals', value: 'cryptographic' },
    ],
    actions: [
      { type: 'deny', message: 'PII access requires cryptographic attestation' },
      { type: 'flag', message: 'Unauthorized PII access attempt' },
      { type: 'notify', message: 'Security alert: PII access attempt by non-crypto-attested client' },
    ],
  },

  // ── AI Agent Access Governance (Access Allow + Deny) ──────────────────

  'user-invoke-agent-allow': {
    name: 'Users Can Invoke AI Agents',
    description: 'Authenticated users can trigger AI agents. Enables the User → Agent hop in agentic workflows.',
    policy_type: 'access', severity: 'low',
    tags: ['access', 'agent'],
    conditions: [
      { field: 'client.type', operator: 'in', value: 'user' },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
    ],
    actions: [
      { type: 'log', message: 'User invoking AI agent — permitted' },
    ],
    tags: ['ai-agent', 'allow', 'agentic-governance'],
  },

  'agent-mcp-access-allow': {
    name: 'AI Agents Can Use MCP Servers',
    description: 'Attested AI agents can access MCP tool servers. Enables the Agent → MCP hop.',
    policy_type: 'access', severity: 'low',
    tags: ['access', 'agent', 'mcp', 'scope'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.is_mcp_server', operator: 'is_true', value: true },
    ],
    actions: [
      { type: 'log', message: 'AI agent accessing MCP server — scope ceiling enforced' },
    ],
    tags: ['ai-agent', 'mcp', 'allow', 'agentic-governance'],
  },

  'jit-credential-request-allow': {
    name: 'JIT Credential Request Allowed',
    description: 'High-trust workloads can request short-lived JIT tokens from the credential vault. Enables secure external API access without static keys.',
    policy_type: 'access', severity: 'low',
    tags: ['access', 'agent', 'mcp', 'credential', 'jit', 'external-api', 'scope'],
    conditions: [
      { field: 'server.name', operator: 'contains', value: 'credential' },
      { field: 'client.trust_level', operator: 'in', value: 'cryptographic,very-high,high' },
    ],
    actions: [
      { type: 'log', message: 'JIT credential request — trust level verified' },
    ],
    tags: ['jit', 'vault', 'allow', 'agentic-governance'],
  },

  'agent-delegation-allow': {
    name: 'Agent-to-Agent Delegation',
    description: 'Attested AI agents can delegate tasks to other attested agents. Both must have cryptographic or high trust.',
    policy_type: 'access', severity: 'medium',
    tags: ['access', 'agent', 'credential', 'delegation', 'jit'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
      { field: 'client.trust_level', operator: 'in', value: 'cryptographic,very-high,high' },
    ],
    actions: [
      { type: 'log', message: 'Agent-to-agent delegation — both attested' },
    ],
    tags: ['a2a', 'delegation', 'allow', 'agentic-governance'],
  },

  'internal-mesh-allow': {
    name: 'Internal Service Mesh Access',
    description: 'Attested internal services can communicate within the service mesh. Covers Cloud Run, GKE, and agent-protocol services.',
    policy_type: 'access', severity: 'info',
    tags: ['access', 'agent', 'delegation'],
    conditions: [
      { field: 'client.cloud_provider', operator: 'in', value: 'gcp,agent-protocol' },
      { field: 'server.cloud_provider', operator: 'in', value: 'gcp,agent-protocol' },
      { field: 'client.trust_level', operator: 'in', value: 'cryptographic,very-high,high' },
    ],
    actions: [
      { type: 'log', message: 'Internal service mesh communication — permitted' },
    ],
    tags: ['internal', 'mesh', 'allow'],
  },

  'agent-direct-external-api-deny': {
    name: 'AI Agent Direct External API Block',
    description: 'AI agents cannot directly access external APIs (Stripe, Salesforce, etc). Must use JIT credentials via the credential vault. Prevents credential sprawl.',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'agent', 'credential', 'jit', 'external-api'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.cloud_provider', operator: 'equals', value: 'external' },
    ],
    actions: [
      { type: 'deny', message: 'AI agent attempting direct external API access — must use JIT credentials' },
      { type: 'flag', message: 'Direct external API access blocked' },
    ],
    tags: ['ai-agent', 'external-api', 'deny', 'agentic-governance'],
  },

  'shared-sa-isolation-deny': {
    name: 'Shared Service Account Isolation',
    description: 'Shared service accounts (e.g. default compute SA) cannot access credential services or external APIs. Prevents lateral movement.',
    policy_type: 'access', severity: 'high',
    tags: ['access', 'agent', 'credential', 'jit', 'external-api'],
    conditions: [
      { field: 'client.type', operator: 'equals', value: 'service-account' },
      { field: 'server.category', operator: 'in', value: 'External APIs,Security Services' },
    ],
    actions: [
      { type: 'deny', message: 'Shared service account lateral movement blocked' },
      { type: 'flag', message: 'Shared SA attempted credential/external access' },
    ],
    tags: ['service-account', 'lateral-movement', 'deny'],
  },

  'untrusted-agent-invoke-deny': {
    name: 'Untrusted Workload Agent Block',
    description: 'Workloads without attestation (none/low trust) cannot invoke AI agents. Prevents unauthorized agent triggering.',
    policy_type: 'access', severity: 'high',
    tags: ['access', 'agent', 'credential', 'attestation', 'external-api'],
    conditions: [
      { field: 'client.trust_level', operator: 'in', value: 'none,low' },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
    ],
    actions: [
      { type: 'deny', message: 'Untrusted workload cannot invoke AI agent — attestation required' },
      { type: 'flag', message: 'Untrusted agent invocation attempt' },
    ],
    tags: ['ai-agent', 'trust', 'deny', 'agentic-governance'],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 4. LEAST PRIVILEGE / PERMISSION
  // ══════════════════════════════════════════════════════════════════════════

  'no-wildcard-permissions': {
    name: 'No Wildcard Permissions',
    description: 'Wildcard (*) permissions are prohibited. All access must be explicitly scoped.',
    policy_type: 'least_privilege', severity: 'critical',
    tags: ['general', 'agent', 'scope'],
    conditions: [{ field: 'has_wildcard', operator: 'is_true' }],
    actions: [
      { type: 'flag', message: 'Wildcard permissions detected' },
      { type: 'remove_wildcard', message: 'Replace wildcard with explicit resource list' },
      { type: 'notify', message: 'Wildcard permissions must be remediated within 7 days' },
    ],
  },

  'privilege-escalation-detection': {
    name: 'Privilege Escalation Detection',
    description: 'Identities with ability to escalate privileges must be flagged and reviewed.',
    policy_type: 'least_privilege', severity: 'critical',
    tags: ['general'],
    conditions: [{ field: 'can_escalate', operator: 'is_true' }],
    actions: [
      { type: 'flag', message: 'Identity can escalate privileges' },
      { type: 'notify', message: 'Review privilege escalation path — apply least privilege' },
      { type: 'downgrade_permissions', message: 'Remove escalation capability' },
    ],
  },

  'excessive-resource-access': {
    name: 'Excessive Resource Access',
    description: 'Identities with access to more than 25 resources need review.',
    policy_type: 'least_privilege', severity: 'high',
    tags: ['general', 'scope'],
    conditions: [{ field: 'resource_count', operator: 'gt', value: '25' }],
    actions: [
      { type: 'flag', message: 'Identity has access to too many resources (>25)' },
      { type: 'notify', message: 'Review and reduce resource access scope' },
    ],
  },

  'cross-account-restriction': {
    name: 'Cross-Account Access Restriction',
    description: 'Cross-account access must be explicitly approved and have cryptographic trust.',
    policy_type: 'least_privilege', severity: 'high',
    tags: ['general', 'attestation', 'scope'],
    conditions: [
      { field: 'cross_account', operator: 'is_true' },
      { field: 'trust_level', operator: 'not_equals', value: 'cryptographic' },
    ],
    actions: [
      { type: 'flag', message: 'Cross-account access without cryptographic attestation' },
      { type: 'require_attest', message: 'Cryptographic attestation required for cross-account access' },
    ],
  },

  'admin-requires-crypto': {
    name: 'Admin Roles Require Cryptographic Attestation',
    description: 'Admin/root IAM roles must have cryptographic (Tier 1) attestation.',
    policy_type: 'least_privilege', severity: 'critical',
    tags: ['general', 'attestation'],
    conditions: [
      { field: 'name', operator: 'matches', value: '(admin|root|superuser)' },
      { field: 'trust_level', operator: 'not_equals', value: 'cryptographic' },
    ],
    actions: [
      { type: 'flag', message: 'Admin role lacks cryptographic attestation' },
      { type: 'block_deploy', message: 'Admin deployment blocked — deploy SPIRE for Tier 1' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 5. CONDITIONAL ACCESS
  // ══════════════════════════════════════════════════════════════════════════

  'business-hours-only': {
    name: 'Business Hours Access Only',
    description: 'Restrict access to production resources to business hours (Mon-Fri 06:00-22:00 UTC).',
    policy_type: 'conditional_access', severity: 'high',
    tags: ['access', 'conditional'],
    conditions: [
      { field: 'server.environment', operator: 'equals', value: 'production' },
      { field: 'runtime.time', operator: 'outside_time_window', value: '06:00-22:00' },
    ],
    actions: [
      { type: 'deny', message: 'Access denied — outside business hours' },
      { type: 'flag', message: 'Out-of-hours access attempt to production' },
      { type: 'notify', message: 'After-hours production access attempted' },
    ],
  },

  'weekday-only-deploys': {
    name: 'Weekday-Only Deployments',
    description: 'Deployments and credential changes restricted to weekdays only.',
    policy_type: 'conditional_access', severity: 'medium',
    tags: ['access', 'conditional', 'credential'],
    conditions: [
      { field: 'runtime.day', operator: 'not_on_day', value: 'mon,tue,wed,thu,fri' },
    ],
    actions: [
      { type: 'deny', message: 'Deployments restricted to weekdays' },
      { type: 'flag', message: 'Weekend deployment attempt detected' },
    ],
  },

  'geo-restricted-access': {
    name: 'Geo-Restricted Access',
    description: 'Production access only from approved regions (us-east-1, eu-west-1).',
    policy_type: 'conditional_access', severity: 'critical',
    tags: ['access', 'conditional'],
    conditions: [
      { field: 'server.environment', operator: 'equals', value: 'production' },
      { field: 'runtime.geo', operator: 'not_in', value: 'us-east-1,us-west-2,eu-west-1' },
    ],
    actions: [
      { type: 'deny', message: 'Access denied — not from approved region' },
      { type: 'flag', message: 'Geo-restricted access violation' },
      { type: 'notify', message: 'Access attempt from unapproved region' },
    ],
  },

  'posture-check-required': {
    name: 'Runtime Posture Check',
    description: 'Client must pass posture check (score > 70) before accessing sensitive resources.',
    policy_type: 'conditional_access', severity: 'high',
    tags: ['access', 'conditional'],
    conditions: [
      { field: 'server.data_classification', operator: 'in', value: 'confidential,restricted,pii' },
      { field: 'runtime.posture_score', operator: 'lt', value: '70' },
    ],
    actions: [
      { type: 'deny', message: 'Posture check failed — score below threshold' },
      { type: 'flag', message: 'Low posture score access attempt' },
      { type: 'require_attest', message: 'Re-attest to improve posture score' },
    ],
  },

  'rate-limit-enforcement': {
    name: 'API Rate Limit Enforcement',
    description: 'No single client can exceed 5000 requests/hour to any server.',
    policy_type: 'conditional_access', severity: 'medium',
    tags: ['access', 'conditional'],
    conditions: [
      { field: 'runtime.request_rate', operator: 'gt', value: '5000' },
    ],
    actions: [
      { type: 'rate_limit', message: 'Rate limit exceeded (>5000 req/hr)' },
      { type: 'flag', message: 'Rate limit violation detected' },
    ],
  },

  'sensitive-requires-approval': {
    name: 'Sensitive Access Requires Approval',
    description: 'Access to restricted/PII resources requires human approval workflow.',
    policy_type: 'conditional_access', severity: 'critical',
    tags: ['access', 'conditional'],
    conditions: [
      { field: 'server.data_classification', operator: 'in', value: 'restricted,pii' },
      { field: 'runtime.approval_status', operator: 'not_equals', value: 'approved' },
    ],
    actions: [
      { type: 'require_approval', message: 'Human approval required for restricted data access' },
      { type: 'flag', message: 'Unapproved access attempt to restricted resource' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 6. AI AGENT POLICIES
  // ══════════════════════════════════════════════════════════════════════════

  'agent-must-have-delegator': {
    name: 'AI Agent Requires Human Delegator',
    description: 'Every AI agent must be bound to a human delegator for accountability.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'kill-switch'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.delegator', operator: 'not_exists' },
    ],
    actions: [
      { type: 'flag', message: 'AI agent has no human delegator' },
      { type: 'kill_agent', message: 'Agent session terminated — no delegator assigned' },
      { type: 'bind_delegator', message: 'Assign human delegator before agent can operate' },
    ],
  },

  'agent-scope-ceiling': {
    name: 'Agent Scope Ceiling Enforcement',
    description: 'AI agent permissions cannot exceed its delegator\'s permissions.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'kill-switch', 'scope'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.autonomous', operator: 'is_true' },
      { field: 'agent.scope_ceiling', operator: 'not_exists' },
    ],
    actions: [
      { type: 'flag', message: 'Autonomous agent has no scope ceiling defined' },
      { type: 'restrict_tools', message: 'Restricting agent to minimum tool set' },
      { type: 'require_human_loop', message: 'Forcing human-in-loop until scope ceiling set' },
    ],
  },

  'agent-kill-switch-required': {
    name: 'Agent Kill Switch Required',
    description: 'All AI agents must have kill switch enabled for immediate revocation.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'kill-switch', 'scope'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.kill_switch', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'AI agent has no kill switch' },
      { type: 'notify', message: 'Enable kill switch for agent compliance' },
    ],
  },

  'agent-session-ttl': {
    name: 'Agent Session TTL Limit',
    description: 'AI agent sessions cannot exceed 480 minutes (8 hours). Auto-terminate after.',
    policy_type: 'ai_agent', severity: 'medium',
    tags: ['agent', 'mcp', 'kill-switch'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.session_ttl', operator: 'gt', value: '480' },
    ],
    actions: [
      { type: 'flag', message: 'Agent session TTL exceeds 8-hour limit' },
      { type: 'kill_agent', message: 'Agent session terminated — TTL exceeded' },
    ],
  },

  'agent-tool-whitelist': {
    name: 'Agent MCP Tool Whitelist',
    description: 'AI agents can only use pre-approved MCP tools. Unapproved tools are blocked.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'kill-switch'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.tools_requested', operator: 'exists' },
    ],
    actions: [
      { type: 'restrict_tools', message: 'Agent restricted to approved MCP tool whitelist' },
      { type: 'allow_with_logging', message: 'Approved tools allowed with enhanced audit logging' },
    ],
  },

  'agent-human-loop-sensitive': {
    name: 'Human-in-Loop for Sensitive Operations',
    description: 'AI agents accessing PII or financial data must have human approval for each action.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.human_in_loop', operator: 'is_false' },
      { field: 'agent.autonomous', operator: 'is_true' },
    ],
    actions: [
      { type: 'require_human_loop', message: 'Human-in-loop required for autonomous agent' },
      { type: 'flag', message: 'Autonomous agent operating without human oversight' },
    ],
  },

  'low-score-quarantine': {
    name: 'Low Security Score Quarantine',
    description: 'Identities with security score below 40 are quarantined pending investigation.',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture', 'agent'],
    conditions: [{ field: 'security_score', operator: 'lt', value: '40' }],
    actions: [
      { type: 'quarantine', message: 'Low security score — identity quarantined' },
      { type: 'notify', message: 'Identity scored below threshold, needs investigation' },
    ],
  },

  'weak-trust-in-prod': {
    name: 'Minimum Trust Level for Production',
    description: 'Production workloads must have at least HIGH trust. LOW or MEDIUM trust triggers escalation.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'attestation'],
    conditions: [
      { field: 'environment', operator: 'equals', value: 'production' },
      { field: 'trust_level', operator: 'in', value: 'low,none,medium' },
    ],
    actions: [
      { type: 'flag', message: 'Production workload has insufficient trust level' },
      { type: 'require_attest', message: 'Re-attestation required for production access' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // NEW: OWASP NHI Top 10 + Real-World Breach Templates
  // ══════════════════════════════════════════════════════════════════════════

  // ── NHI1: Improper Offboarding (47% of AWS orgs have stale 3rd-party IAM roles) ──
  'improper-offboarding-detection': {
    name: 'Improper Offboarding Detection',
    description: 'Service accounts linked to deprovisioned owners must be disabled. #1 OWASP NHI risk.',
    policy_type: 'lifecycle', severity: 'critical',
    tags: ['lifecycle', 'credential'],
    conditions: [{ field: 'owner_status', operator: 'equals', value: 'deprovisioned' }],
    actions: [
      { type: 'disable_identity', message: 'Owner deprovisioned — NHI auto-disabled' },
      { type: 'flag', message: 'Orphaned NHI from deprovisioned owner' },
      { type: 'schedule_decommission', message: 'Scheduled for decommission in 14 days' },
    ],
  },

  // ── NHI2: Secret Leakage ──
  'secret-in-logs-detection': {
    name: 'Secret Leakage in Logs Detection',
    description: 'Workloads that log sensitive credentials are flagged. API keys and tokens must never appear in logs.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'credential'],
    conditions: [{ field: 'metadata.secrets_in_logs', operator: 'is_true' }],
    actions: [
      { type: 'flag', message: 'Secrets detected in application logs — critical leakage risk' },
      { type: 'quarantine', message: 'Workload quarantined until secret leakage remediated' },
    ],
  },

  'secret-in-env-plaintext': {
    name: 'Plaintext Secrets in Environment Variables',
    description: 'Secrets as plaintext env vars must be migrated to a secrets manager (Vault, GCP SM, AWS SM).',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture'],
    conditions: [{ field: 'metadata.plaintext_secrets_count', operator: 'gt', value: '0' }],
    actions: [
      { type: 'flag', message: 'Plaintext secrets detected in environment variables' },
      { type: 'notify', message: 'Migrate to secrets manager (Vault, GCP SM, AWS SM)' },
    ],
  },

  // ── NHI3: Vulnerable Third-Party NHI (Okta breach 2023) ──
  'third-party-nhi-review': {
    name: 'Third-Party NHI Quarterly Review',
    description: 'All third-party integrations must be reviewed quarterly. Based on Okta support system breach (2023).',
    policy_type: 'compliance', severity: 'high',
    tags: ['compliance', 'posture', 'oauth'],
    conditions: [
      { field: 'category', operator: 'in', value: 'integration,third-party,saas,oauth-app' },
      { field: 'last_seen', operator: 'older_than_days', value: '90' },
    ],
    actions: [
      { type: 'flag', message: 'Third-party integration not reviewed in 90+ days' },
      { type: 'require_attest', message: 'Quarterly review required for third-party NHI' },
    ],
  },

  // ── NHI5: Overprivileged NHI ──
  'editor-role-in-prod': {
    name: 'Editor/Writer Role Prohibited in Production',
    description: 'Production NHIs must not hold Editor, Writer, or Admin primitive roles.',
    policy_type: 'least_privilege', severity: 'critical',
    tags: ['general'],
    conditions: [
      { field: 'environment', operator: 'equals', value: 'production' },
      { field: 'metadata.roles', operator: 'includes_any', value: 'roles/editor,roles/owner,roles/admin' },
    ],
    actions: [
      { type: 'flag', message: 'Production NHI holds overprivileged primitive role' },
      { type: 'downgrade_permissions', message: 'Replace with custom least-privilege role' },
    ],
  },

  'unused-permissions-cleanup': {
    name: 'Unused Permissions Cleanup',
    description: 'Permissions not exercised in 60 days should be revoked.',
    policy_type: 'least_privilege', severity: 'medium',
    tags: ['general'],
    conditions: [
      { field: 'metadata.unused_permission_count', operator: 'gt', value: '5' },
      { field: 'metadata.last_permission_used', operator: 'older_than_days', value: '60' },
    ],
    actions: [
      { type: 'flag', message: 'NHI has 5+ unused permissions for 60+ days' },
      { type: 'notify', message: 'Revoke unused permissions to reduce blast radius' },
    ],
  },

  // ── NHI6: Insecure Cloud Deployment / CI/CD (CircleCI, SolarWinds) ──
  'cicd-oidc-required': {
    name: 'CI/CD Must Use OIDC Federation',
    description: 'CI/CD pipelines must use OIDC (GitHub OIDC, GitLab CI) instead of static credentials. Based on CircleCI breach.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'credential'],
    conditions: [
      { field: 'category', operator: 'in', value: 'cicd,pipeline,deployment' },
      { field: 'metadata.auth_method', operator: 'not_in', value: 'oidc,federated,workload-identity' },
    ],
    actions: [
      { type: 'flag', message: 'CI/CD pipeline uses static credentials instead of OIDC' },
      { type: 'quarantine', message: 'Pipeline quarantined until OIDC migration complete' },
    ],
  },

  'cicd-no-prod-creds-in-pr': {
    name: 'No Production Credentials in PR Builds',
    description: 'Pull request builds must never have access to production credentials.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'credential'],
    conditions: [
      { field: 'category', operator: 'in', value: 'cicd,pipeline' },
      { field: 'environment', operator: 'not_equals', value: 'production' },
      { field: 'metadata.has_prod_credentials', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Production credentials in non-production pipeline build' },
      { type: 'flag', message: 'PR/feature build has production credential access' },
    ],
  },

  // ── NHI7: Long-Lived Secrets ──
  'long-lived-api-key': {
    name: 'Long-Lived API Key Detection',
    description: 'API keys older than 90 days must be replaced with short-lived tokens.',
    policy_type: 'lifecycle', severity: 'high',
    tags: ['lifecycle', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'api-key,access-key,pat' },
      { field: 'created_at', operator: 'older_than_days', value: '90' },
    ],
    actions: [
      { type: 'flag', message: 'Long-lived API key detected (>90 days)' },
      { type: 'force_rotation', message: 'Replace with short-lived token or rotate immediately' },
    ],
  },

  'certificate-expiry-30d': {
    name: 'Certificate Expiry Warning (30 Days)',
    description: 'mTLS and TLS certificates expiring within 30 days must be renewed.',
    policy_type: 'lifecycle', severity: 'high',
    tags: ['lifecycle', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'certificate,mtls-cert,tls-cert' },
      { field: 'expiry_date', operator: 'newer_than_days', value: '30' },
    ],
    actions: [
      { type: 'flag', message: 'Certificate expiring within 30 days' },
      { type: 'notify', message: 'Certificate renewal required' },
    ],
  },

  'user-managed-key-prohibition': {
    name: 'User-Managed Key Prohibition',
    description: 'User-managed SA keys older than 14 days are prohibited. Use workload identity federation.',
    policy_type: 'lifecycle', severity: 'critical',
    tags: ['lifecycle', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'service-account-key,api-key,access-key' },
      { field: 'metadata.key_type', operator: 'equals', value: 'user-managed' },
      { field: 'created_at', operator: 'older_than_days', value: '14' },
    ],
    actions: [
      { type: 'flag', message: 'User-managed key older than 14 days — high leak risk' },
      { type: 'disable_identity', message: 'Use workload identity federation instead' },
    ],
  },

  // ── NHI8: Environment Isolation ──
  'env-credential-isolation': {
    name: 'Environment Credential Isolation',
    description: 'Same credential must not be used across environments. Enables lateral movement.',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'credential'],
    conditions: [{ field: 'credential.used_in_environments', operator: 'exceeds_count', value: '1' }],
    actions: [
      { type: 'deny', message: 'Credential used across multiple environments' },
      { type: 'flag', message: 'Same credential in multiple environments — isolation violation' },
    ],
  },

  // ── NHI9: NHI Reuse / Shared Service Account ──
  'shared-service-account-deny': {
    name: 'Shared Service Account Prohibition',
    description: 'Service accounts shared by 2+ workloads are prohibited. Each workload needs its own identity.',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'credential'],
    conditions: [
      { field: 'type', operator: 'equals', value: 'service-account' },
      { field: 'metadata.workload_count', operator: 'gt', value: '1' },
    ],
    actions: [
      { type: 'flag', message: 'Service account shared across multiple workloads' },
      { type: 'quarantine', message: 'Shared SA quarantined until workloads are separated' },
    ],
  },

  // ── NHI10: Human Use of NHI (Midnight Blizzard) ──
  'detect-human-use-of-nhi': {
    name: 'Detect Human Use of Service Account',
    description: 'Service accounts used from interactive sessions are flagged. Based on Midnight Blizzard attack (Microsoft 2024).',
    policy_type: 'compliance', severity: 'critical',
    tags: ['compliance', 'posture', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'service-account,iam-role' },
      { field: 'runtime.session_type', operator: 'in', value: 'interactive,console,ssh,browser' },
    ],
    actions: [
      { type: 'deny', message: 'Service accounts cannot be used from interactive sessions' },
      { type: 'flag', message: 'Human interactive session using NHI credentials' },
    ],
  },

  'anomalous-access-pattern': {
    name: 'Anomalous Access Pattern Detection',
    description: 'Flag NHIs accessing new resources during off-hours. Based on Midnight Blizzard lateral movement.',
    policy_type: 'conditional_access', severity: 'high',
    tags: ['access', 'conditional', 'credential'],
    conditions: [
      { field: 'runtime.is_first_access', operator: 'is_true' },
      { field: 'runtime.time', operator: 'outside_time_window', value: '06:00-22:00' },
    ],
    actions: [
      { type: 'flag', message: 'First-time access during off-hours — anomaly detected' },
      { type: 'require_approval', message: 'Manual approval required for anomalous access' },
    ],
  },

  'public-endpoint-requires-auth': {
    name: 'Public Endpoint Requires Authentication',
    description: 'Publicly exposed workloads must enforce authentication. Entry point for lateral movement.',
    policy_type: 'access', severity: 'critical',
    tags: ['access'],
    conditions: [
      { field: 'metadata.ingress', operator: 'equals', value: 'INGRESS_TRAFFIC_ALL' },
      { field: 'metadata.auth_required', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Public endpoint without authentication is prohibited' },
      { type: 'flag', message: 'Unauthenticated public endpoint detected' },
    ],
  },

  'public-resource-approval-required': {
    name: 'Public Resource Requires Security Approval Tag',
    description: 'Publicly accessible resources must have an approved-public tag from the security team. Untagged public resources are flagged for review.',
    policy_type: 'access', severity: 'high',
    tags: ['access', 'exposure', 'compliance'],
    conditions: [
      { field: 'metadata.is_public', operator: 'is_true' },
      { field: 'labels.approved-public', operator: 'not_exists' },
    ],
    actions: [
      { type: 'flag', message: 'Publicly accessible resource lacks security approval tag' },
      { type: 'notify', message: 'Requires approved-public label from security team' },
    ],
  },

  'restrict-public-access': {
    name: 'Restrict Unapproved Public Access',
    description: 'Block or restrict public access on resources that have not been explicitly approved for public exposure (S3, RDS, firewall rules).',
    policy_type: 'access', severity: 'critical',
    tags: ['access', 'exposure', 'network'],
    conditions: [
      { field: 'metadata.is_public', operator: 'is_true' },
      { field: 'labels.approved-public', operator: 'not_exists' },
    ],
    actions: [
      { type: 'deny', message: 'Unapproved public access is prohibited' },
      { type: 'quarantine', message: 'Resource quarantined until public access is reviewed' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // MCP-Specific Security (Astrix 2025: 53% static creds, CVE-2025-6514)
  // ══════════════════════════════════════════════════════════════════════════

  'mcp-static-credential-ban': {
    name: 'MCP Server Static Credential Ban',
    description: 'MCP servers must not use static API keys/PATs. 53% use insecure static creds (Astrix 2025). Migrate to OAuth 2.1 or Edge Gateway JIT.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'credential', 'jit', 'oauth'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.has_static_creds', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server uses static credentials — critical risk' },
      { type: 'quarantine', message: 'MCP server quarantined until credential migration' },
    ],
  },

  'mcp-oauth-required': {
    name: 'MCP OAuth 2.1 Required',
    description: 'Remote MCP servers must implement OAuth 2.1 per MCP Auth Spec (June 2025).',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'credential', 'oauth'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.has_oauth', operator: 'is_false' },
      { field: 'metadata.transport', operator: 'not_equals', value: 'stdio' },
    ],
    actions: [
      { type: 'deny', message: 'Remote MCP servers must implement OAuth 2.1' },
      { type: 'flag', message: 'Remote MCP without OAuth — violates MCP Auth Spec' },
    ],
  },

  'mcp-token-passthrough-ban': {
    name: 'MCP Token Passthrough Prohibition',
    description: 'MCP servers must not pass client tokens to upstream APIs (confused deputy). Explicitly forbidden in MCP June 2025 spec.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'oauth'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.token_passthrough', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Token passthrough prohibited — confused deputy vulnerability' },
      { type: 'flag', message: 'MCP server passing client tokens to upstream APIs' },
    ],
  },

  'mcp-localhost-binding': {
    name: 'MCP Server Localhost Binding Required',
    description: 'Local MCP servers must bind to localhost only. Network exposure enables RCE (CVE-2025-6514, 558K downloads affected).',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.transport', operator: 'equals', value: 'stdio' },
      { field: 'metadata.bound_to_localhost', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Local MCP server must bind to localhost' },
      { type: 'flag', message: 'MCP server exposed on network interface' },
    ],
  },

  'mcp-server-registry-verification': {
    name: 'MCP Server Registry Verification',
    description: 'MCP servers must be from verified registries. Based on Smithery.ai path traversal (3000+ servers compromised).',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.registry_verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Only verified MCP servers permitted in production' },
      { type: 'flag', message: 'MCP server from unverified registry' },
    ],
  },

  'tool-poisoning-prevention': {
    name: 'MCP Tool Poisoning Prevention',
    description: 'MCP tool descriptions must be validated against approved schemas. Prevents tool poisoning where malicious metadata is injected.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,mcp-ai-agent' },
      { field: 'metadata.tools_validated', operator: 'is_false' },
    ],
    actions: [
      { type: 'restrict_tools', message: 'Unvalidated tools blocked until schema review' },
      { type: 'flag', message: 'MCP tools not validated — tool poisoning risk' },
    ],
  },

  // ── A2A Agent Security ──
  'a2a-authentication-required': {
    name: 'A2A Agent Authentication Required',
    description: 'A2A agents must require authentication before accepting tasks.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,a2a-agent' },
      { field: 'metadata.a2a_auth_required', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'A2A agent accepts tasks without authentication' },
      { type: 'flag', message: 'Unauthenticated A2A agent detected' },
    ],
  },

  'a2a-agent-card-signing': {
    name: 'A2A Agent Card Must Be Signed',
    description: 'A2A Agent Cards must be JWS-signed for authenticity. Unsigned cards can be spoofed.',
    policy_type: 'ai_agent', severity: 'medium',
    tags: ['agent', 'mcp'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,a2a-agent' },
      { field: 'metadata.agent_card_signed', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'A2A Agent Card is not signed (no JWS)' },
      { type: 'notify', message: 'Sign Agent Card with JWS for authenticity' },
    ],
  },

  // ── Toxic Combo / Credential Isolation ──
  'toxic-combo-financial-crm': {
    name: 'Toxic Combo: Financial + CRM Credential Separation',
    description: 'No single agent may hold both financial (Stripe) and CRM (Salesforce) credentials. Compromise = customer data + financial transactions.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'credential'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server,mcp-ai-agent' },
      { field: 'metadata.credential_categories', operator: 'includes_all', value: 'financial,crm' },
    ],
    actions: [
      { type: 'deny', message: 'Toxic combination: financial + CRM on same agent' },
      { type: 'flag', message: 'Agent holds both financial and CRM credentials' },
    ],
  },

  'toxic-combo-code-infra': {
    name: 'Toxic Combo: Code Repository + Infrastructure Admin',
    description: 'No single NHI may hold both code repo and infra admin creds. Based on SolarWinds/CircleCI patterns.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'credential'],
    conditions: [
      { field: 'metadata.credential_categories', operator: 'includes_all', value: 'devops,infrastructure' },
    ],
    actions: [
      { type: 'deny', message: 'Toxic combination: code repo + infra admin credentials' },
      { type: 'flag', message: 'Supply chain risk: code + infra on same identity' },
    ],
  },

  // ── OBO Delegation Chain ──
  'obo-chain-max-depth': {
    name: 'OBO Delegation Chain Max Depth',
    description: 'On-Behalf-Of chains cannot exceed 3 hops. Deeper chains lose accountability.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'credential', 'delegation', 'kill-switch', 'scope'],
    conditions: [{ field: 'agent.chain_depth', operator: 'gt', value: '3' }],
    actions: [
      { type: 'deny', message: 'OBO delegation chain exceeds max depth (3 hops)' },
      { type: 'kill_agent', message: 'Agent terminated — delegation chain too deep' },
    ],
  },

  'obo-scope-must-narrow': {
    name: 'OBO Scope Must Narrow at Each Hop',
    description: 'Each delegation hop must narrow scope — never widen. Prevents privilege escalation through delegation.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'delegation', 'kill-switch', 'scope'],
    conditions: [{ field: 'agent.scope_wider_than_parent', operator: 'is_true' }],
    actions: [
      { type: 'deny', message: 'OBO scope exceeds parent — privilege escalation' },
      { type: 'kill_agent', message: 'Agent terminated — scope escalation in chain' },
    ],
  },

  'obo-human-root-required': {
    name: 'OBO Chain Must Originate from Human',
    description: 'Every delegation chain must trace back to a human at the root. Agent-only chains are prohibited.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'delegation', 'kill-switch', 'scope'],
    conditions: [{ field: 'agent.root_delegator_type', operator: 'not_equals', value: 'human' }],
    actions: [
      { type: 'deny', message: 'No human root in delegation chain' },
      { type: 'kill_agent', message: 'Agent terminated — no human in chain' },
    ],
  },

  'obo-token-ttl-limit': {
    name: 'OBO Token TTL Shortening per Hop',
    description: 'Each OBO token hop must have shorter TTL than parent. Root: 1hr → Hop1: 30min → Hop2: 15min → Hop3: 5min.',
    policy_type: 'ai_agent', severity: 'medium',
    tags: ['agent', 'mcp', 'delegation', 'kill-switch'],
    conditions: [
      { field: 'agent.token_ttl', operator: 'gte', value: '60' },
      { field: 'agent.chain_depth', operator: 'gt', value: '0' },
    ],
    actions: [
      { type: 'flag', message: 'OBO token TTL not shortened at delegation hop' },
    ],
  },

  // ── JIT Credential Brokering ──
  'jit-credential-required': {
    name: 'JIT Credential Required for External APIs',
    description: 'All external API access must use JIT credentials from the credential broker. Static env var credentials are prohibited.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'credential', 'delegation', 'jit', 'external-api'],
    conditions: [
      { field: 'metadata.has_static_creds', operator: 'is_true' },
      { field: 'metadata.uses_credential_broker', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'External API access without credential broker is prohibited' },
      { type: 'flag', message: 'Static credentials — must use JIT credential broker' },
    ],
  },

  'jit-token-max-ttl': {
    name: 'JIT Token Maximum TTL (5 Minutes)',
    description: 'JIT tokens from credential broker must not exceed 5 minutes TTL.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'credential', 'jit', 'external-api', 'scope'],
    conditions: [{ field: 'credential.ttl_minutes', operator: 'gt', value: '5' }],
    actions: [
      { type: 'flag', message: 'JIT token TTL exceeds 5-minute limit' },
    ],
  },

  'jit-scope-per-request': {
    name: 'JIT Credential Scoped Per Request',
    description: 'Each JIT credential must be scoped to the specific API operation, not broad access.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'credential', 'jit', 'scope'],
    conditions: [{ field: 'credential.scope', operator: 'equals', value: '*' }],
    actions: [
      { type: 'deny', message: 'Wildcard JIT credentials are prohibited' },
      { type: 'flag', message: 'JIT credential has wildcard scope' },
    ],
  },

  // ── Agent Consent & Multi-Tool ──
  'agent-consent-expiry': {
    name: 'Agent Consent Expiry (24 Hours)',
    description: 'User consent for agent delegation expires after 24 hours. Re-consent required.',
    policy_type: 'ai_agent', severity: 'medium',
    tags: ['agent', 'mcp', 'credential', 'delegation', 'jit', 'scope'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.consent_age_hours', operator: 'gt', value: '24' },
    ],
    actions: [
      { type: 'flag', message: 'Agent consent expired (>24 hours)' },
      { type: 'require_human_loop', message: 'Re-consent required from delegator' },
    ],
  },

  'agent-multi-tool-approval': {
    name: 'Multi-Tool Operation Requires Approval',
    description: 'Agent operations chaining 3+ MCP tools require human approval before execution.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'human-in-loop'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,mcp-server' },
      { field: 'agent.tool_chain_length', operator: 'gt', value: '3' },
    ],
    actions: [
      { type: 'require_approval', message: 'Multi-tool chain (3+) requires human approval' },
      { type: 'flag', message: 'Complex agent tool chain detected' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 8. BREACH-INFORMED POLICIES (CVE / Incident-Based)
  // Based on real MCP security incidents from 2025-2026
  // ══════════════════════════════════════════════════════════════════════════

  // CVE-2025-6514: mcp-remote OAuth RCE (437K+ downloads affected)
  'mcp-oauth-discovery-validation': {
    name: 'MCP OAuth Discovery Endpoint Validation',
    description: 'MCP servers must validate OAuth discovery endpoints to prevent RCE via malicious authorization URLs. Based on CVE-2025-6514 which affected 437K+ mcp-remote downloads.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'oauth', 'cve-2025-6514'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,a2a-agent' },
      { field: 'metadata.auth', operator: 'not_equals', value: 'oauth2.1' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server not using validated OAuth 2.1 flow — vulnerable to CVE-2025-6514 style attack' },
      { type: 'block_deploy', message: 'MCP servers must use OAuth 2.1 with validated discovery endpoints' },
    ],
  },

  // GitHub MCP Data Heist (Invariant Labs, 2025)
  'mcp-github-token-scope': {
    name: 'GitHub MCP Token Over-Privilege Prevention',
    description: 'GitHub MCP integrations must use minimal-scope tokens. Based on the GitHub MCP Data Heist where over-privileged PATs leaked private repo data via prompt injection.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'github', 'prompt-injection'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'metadata.tools', operator: 'contains', value: 'github' },
    ],
    actions: [
      { type: 'flag', message: 'GitHub MCP integration detected — verify token scope is minimal (no repo:write, no admin)' },
      { type: 'require_review', message: 'GitHub MCP tokens must be reviewed for least-privilege scope' },
    ],
  },

  // WhatsApp MCP Tool Poisoning (2025)
  'mcp-tool-description-sanitization': {
    name: 'MCP Tool Description Sanitization',
    description: 'MCP tool descriptions must be sanitized to prevent hidden prompt injection. Based on WhatsApp MCP breach where poisoned tool descriptions exfiltrated messages.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'tool-poisoning', 'prompt-injection'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must sanitize tool descriptions — tool poisoning can exfiltrate data via hidden instructions' },
      { type: 'require_review', message: 'Audit MCP tool metadata for hidden prompt injection payloads' },
    ],
  },

  // Supabase Cursor Agent Breach (mid-2025)
  'agent-privileged-input-isolation': {
    name: 'Agent Privileged Input Isolation',
    description: 'AI agents with privileged access must not process untrusted user input directly. Based on Supabase Cursor agent breach where support tickets contained SQL injection payloads.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'breach', 'prompt-injection', 'sql-injection', 'supabase'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,a2a-agent' },
      { field: 'is_ai_agent', operator: 'is_true' },
      { field: 'trust_level', operator: 'in', value: 'cryptographic,very-high' },
    ],
    actions: [
      { type: 'flag', message: 'Privileged agent must isolate untrusted input processing from tool execution' },
      { type: 'require_sandbox', message: 'Input processing must be sandboxed from privileged tool access' },
    ],
  },

  // Anthropic SQLite MCP SQLi → Stored Prompt Injection (Trend Micro, June 2025)
  'mcp-sql-injection-prevention': {
    name: 'MCP Database Query Parameterization',
    description: 'MCP servers accessing databases must use parameterized queries. Based on Trend Micro disclosure of SQLi in Anthropic reference SQLite MCP server (5000+ forks).',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'sql-injection', 'anthropic'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server with database access must use parameterized queries — SQLi leads to stored prompt injection' },
      { type: 'require_review', message: 'Audit all database queries in MCP server for parameterization' },
    ],
  },

  // Figma/Framelink MCP RCE (2025)
  'mcp-command-injection-prevention': {
    name: 'MCP Command Injection Prevention',
    description: 'MCP servers must not use unsanitized input in shell commands. Based on Figma/Framelink MCP CVE where child_process.exec with untrusted input enabled RCE.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'command-injection', 'rce'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must not pass unsanitized input to shell commands — RCE risk (Figma MCP CVE)' },
      { type: 'block_deploy', message: 'MCP servers using child_process.exec with user input are blocked' },
    ],
  },

  // Microsoft MarkItDown SSRF (Jan 2026) — 36.7% of MCP servers vulnerable
  'mcp-ssrf-uri-validation': {
    name: 'MCP Server URI/SSRF Validation',
    description: 'MCP servers processing URIs must validate and restrict allowed destinations. Based on MarkItDown SSRF where 36.7% of 7000+ MCP servers were vulnerable.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'breach', 'ssrf', 'microsoft'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must validate URIs to prevent SSRF — 36.7% of servers found vulnerable' },
      { type: 'restrict_network', message: 'MCP server egress must be restricted to approved destinations' },
    ],
  },

  // CVE-2025-68143/68144/68145: Anthropic Git MCP prompt injection
  'mcp-git-prompt-injection-guard': {
    name: 'Git MCP Prompt Injection Guard',
    description: 'Git MCP servers must sanitize repository content before passing to LLMs. Based on CVE-2025-68143/68144/68145 in Anthropic Git MCP server.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'prompt-injection', 'git', 'cve-2025-68143'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'metadata.tools', operator: 'contains', value: 'git' },
    ],
    actions: [
      { type: 'flag', message: 'Git MCP must sanitize repo content — prompt injection via malicious issues/PRs (CVE-2025-68143)' },
      { type: 'require_review', message: 'Git MCP server must be v2025.12.18 or later' },
    ],
  },

  // CVE-2025-6515: MCP prompt hijacking / session takeover
  'mcp-session-integrity': {
    name: 'MCP Session Integrity Protection',
    description: 'MCP sessions must be protected against prompt hijacking and session takeover. Based on CVE-2025-6515 enabling session takeover via intercepted prompts.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'session-hijack', 'cve-2025-6515'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server,a2a-agent' },
    ],
    actions: [
      { type: 'flag', message: 'MCP sessions must use signed request tokens to prevent prompt hijacking (CVE-2025-6515)' },
      { type: 'require_tls', message: 'All MCP communication must use mutual TLS' },
    ],
  },

  // Cursor IDE MCP RCE (Aug 2025)
  'mcp-ide-sandbox-required': {
    name: 'IDE MCP Integration Sandbox Required',
    description: 'MCP integrations in development tools (Cursor, VS Code) must run in sandboxed environments. Based on Cursor IDE MCP RCE affecting developer environments.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'breach', 'rce', 'ide', 'cursor'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
    ],
    actions: [
      { type: 'flag', message: 'IDE MCP integrations must be containerized or sandboxed — RCE risk from Cursor CVE' },
      { type: 'require_container', message: 'MCP server must run in isolated container' },
    ],
  },

  // MCP localhost exploitation (Tenable, 2025)
  'mcp-localhost-exposure-prevention': {
    name: 'MCP Localhost Exposure Prevention',
    description: 'MCP servers must not trust localhost connections blindly. Based on Tenable research where malicious websites compromised local MCP environments.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'breach', 'localhost', 'tenable'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must not trust localhost — drive-by exploitation via malicious websites' },
      { type: 'require_auth', message: 'All MCP endpoints require authentication, even localhost' },
    ],
  },

  // MCP Typosquatting (Noma Security, Nov 2025)
  'mcp-registry-verification': {
    name: 'MCP Server Registry Verification',
    description: 'MCP servers must be verified against an approved registry to prevent typosquatting. Based on Noma Security research on MCP package supply chain attacks.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'breach', 'supply-chain', 'typosquatting'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
      { field: 'verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server not verified — typosquatting risk from supply chain attacks' },
      { type: 'block_deploy', message: 'Only verified MCP servers from approved registries allowed' },
    ],
  },

  // ── Allow Templates for Agent Governance ──

  'allow-user-agent-invocation': {
    name: 'Users Can Invoke AI Agents',
    description: 'Authenticated users with appropriate roles can trigger AI agent workflows.',
    policy_type: 'access', effect: 'allow', severity: 'low',
    tags: ['agent', 'access', 'allow'],
    conditions: [
      { field: 'client.type', operator: 'in', value: ['user'] },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
    ],
    actions: [{ type: 'log', message: 'User invoking AI agent — permitted' }],
  },

  'allow-agent-mcp-access': {
    name: 'AI Agents Can Use MCP Servers',
    description: 'Attested AI agents can access MCP tool servers for authorized operations with scope ceiling enforcement.',
    policy_type: 'access', effect: 'allow', severity: 'low',
    tags: ['agent', 'mcp', 'access', 'allow'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.is_mcp_server', operator: 'is_true', value: true },
    ],
    actions: [{ type: 'log', message: 'AI agent accessing MCP server — scope ceiling enforced' }],
  },

  'allow-jit-credential-request': {
    name: 'JIT Credential Request Allowed',
    description: 'High-trust workloads can request short-lived JIT tokens from the credential vault for external API access.',
    policy_type: 'access', effect: 'allow', severity: 'low',
    tags: ['agent', 'access', 'allow', 'jit', 'vault'],
    conditions: [
      { field: 'server.name', operator: 'equals', value: 'jit-credential-vault' },
      { field: 'client.trust_level', operator: 'in', value: ['cryptographic', 'very-high', 'high'] },
    ],
    actions: [{ type: 'log', message: 'JIT credential request — trust level verified' }],
  },

  'allow-agent-delegation': {
    name: 'Agent-to-Agent Delegation',
    description: 'Attested AI agents can delegate tasks to other attested agents with scope ceiling inheritance.',
    policy_type: 'access', effect: 'allow', severity: 'low',
    tags: ['agent', 'access', 'allow', 'a2a', 'delegation'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
      { field: 'client.trust_level', operator: 'in', value: ['cryptographic', 'very-high', 'high'] },
    ],
    actions: [{ type: 'log', message: 'Agent delegation — scope ceiling inherited from delegator' }],
  },

  'allow-internal-service-mesh': {
    name: 'Internal Service Mesh Access',
    description: 'Attested internal services can communicate within the service mesh.',
    policy_type: 'access', effect: 'allow', severity: 'info',
    tags: ['access', 'allow', 'internal'],
    conditions: [
      { field: 'client.cloud_provider', operator: 'in', value: ['gcp', 'agent-protocol'] },
      { field: 'server.cloud_provider', operator: 'in', value: ['gcp', 'agent-protocol'] },
      { field: 'client.trust_level', operator: 'in', value: ['cryptographic', 'very-high', 'high'] },
    ],
    actions: [{ type: 'log', message: 'Internal service mesh — permitted' }],
  },

  // ── Deny Templates for Agent Governance ──

  'deny-agent-direct-external': {
    name: 'Block AI Agent Direct External API Access',
    description: 'AI agents cannot directly access external APIs. Must route through JIT credential vault to enforce scope ceiling.',
    policy_type: 'access', effect: 'deny', severity: 'critical',
    tags: ['agent', 'access', 'deny', 'external-api'],
    conditions: [
      { field: 'client.is_ai_agent', operator: 'is_true', value: true },
      { field: 'server.cloud_provider', operator: 'equals', value: 'external' },
    ],
    actions: [{ type: 'log', message: 'BLOCKED: AI agent direct external API access — must use JIT vault' }],
  },

  'deny-shared-sa-external': {
    name: 'Shared SA External Access Block',
    description: 'Shared service accounts cannot access external APIs or credential services to prevent lateral movement.',
    policy_type: 'access', effect: 'deny', severity: 'critical',
    tags: ['access', 'deny', 'shared-sa', 'lateral-movement'],
    conditions: [
      { field: 'client.name', operator: 'equals', value: 'wid-dev-run' },
      { field: 'server.category', operator: 'in', value: ['External APIs', 'Security Services'] },
    ],
    actions: [{ type: 'log', message: 'BLOCKED: Shared SA accessing external/credential services' }],
  },

  'deny-untrusted-agent-invocation': {
    name: 'Block Untrusted Agent Invocation',
    description: 'Workloads without attestation cannot invoke AI agents to prevent unauthorized automation.',
    policy_type: 'access', effect: 'deny', severity: 'high',
    tags: ['agent', 'access', 'deny', 'attestation'],
    conditions: [
      { field: 'client.trust_level', operator: 'in', value: ['none', 'low'] },
      { field: 'server.is_ai_agent', operator: 'is_true', value: true },
    ],
    actions: [{ type: 'log', message: 'BLOCKED: Untrusted workload invoking AI agent' }],
  },

  // Agent confused deputy prevention  
  'agent-confused-deputy-prevention': {
    name: 'Agent Confused Deputy Prevention',
    description: 'MCP servers must verify requestor identity before acting on their behalf. Prevents OAuth token confusion where servers act with wrong user credentials.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'mcp', 'breach', 'confused-deputy', 'oauth'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must verify caller identity before using stored OAuth tokens — confused deputy risk' },
      { type: 'require_identity_binding', message: 'Each OAuth token must be bound to a specific caller identity' },
    ],
  },

  // Agent data exfiltration prevention
  'agent-data-exfiltration-dlp': {
    name: 'Agent Data Loss Prevention',
    description: 'AI agents must not transmit sensitive data to external endpoints without DLP review. Prevents data exfiltration via poisoned tools.',
    policy_type: 'ai_agent', severity: 'critical',
    tags: ['agent', 'breach', 'dlp', 'data-exfiltration'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,a2a-agent' },
      { field: 'is_ai_agent', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'Agent external data transmission must pass through DLP gateway' },
      { type: 'restrict_egress', message: 'Agent egress restricted to approved API endpoints only' },
    ],
  },

  // MCP tool permission over-provisioning (Noma: 90% have dangerous defaults)
  'mcp-tool-least-privilege': {
    name: 'MCP Server Tool Least Privilege',
    description: 'MCP servers must disable destructive tools by default. Based on Noma research showing 90%+ of MCP servers run with excessive permissions.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'mcp', 'breach', 'least-privilege', 'noma'],
    conditions: [
      { field: 'type', operator: 'in', value: 'mcp-server' },
      { field: 'is_mcp_server', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'MCP server must explicitly whitelist allowed tools — disable destructive operations by default' },
      { type: 'restrict_tools', message: 'Only approved tools enabled per deployment profile' },
    ],
  },

  // Agent attribution / audit trail
  'agent-action-attribution': {
    name: 'Agent Action Attribution Required',
    description: 'Every agent action must be attributable to a specific agent identity and human delegator. Addresses the agent accountability challenge in multi-agent systems.',
    policy_type: 'ai_agent', severity: 'high',
    tags: ['agent', 'audit', 'attribution', 'compliance'],
    conditions: [
      { field: 'type', operator: 'in', value: 'ai-agent,a2a-agent' },
      { field: 'is_ai_agent', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'Agent actions must include attribution chain: human delegator → agent → tool' },
      { type: 'require_audit_log', message: 'All agent actions logged with full attribution chain' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // 7. AI REQUEST COST / USAGE POLICIES (live traffic dimensions)
  // ══════════════════════════════════════════════════════════════════════════

  'ai-daily-cost-limit': {
    name: 'AI Daily Cost Limit',
    description: 'Block AI API calls when a workload exceeds its daily cost threshold. Prevents runaway AI spending from compromised or misconfigured agents.',
    policy_type: 'access', severity: 'high',
    tags: ['ai', 'cost', 'budget', 'guardrail'],
    conditions: [
      { field: 'ai.cost_today_usd', operator: 'gte', value: 100 },
    ],
    actions: [
      { type: 'flag', message: 'AI daily cost limit exceeded' },
    ],
    effect: 'deny',
  },

  'ai-daily-request-limit': {
    name: 'AI Daily Request Limit',
    description: 'Rate limit AI API calls per workload per day. Prevents excessive API usage from runaway loops or compromised agents.',
    policy_type: 'access', severity: 'medium',
    tags: ['ai', 'rate-limit', 'guardrail'],
    conditions: [
      { field: 'ai.requests_today', operator: 'gte', value: 1000 },
    ],
    actions: [
      { type: 'flag', message: 'AI daily request limit exceeded' },
    ],
    effect: 'deny',
  },

  'ai-provider-restriction': {
    name: 'AI Provider Restriction',
    description: 'Only allow approved AI providers. Blocks calls to unapproved or shadow AI services.',
    policy_type: 'access', severity: 'high',
    tags: ['ai', 'provider', 'shadow-ai', 'compliance'],
    conditions: [
      { field: 'ai.provider', operator: 'not_in', value: ['openai', 'anthropic'] },
    ],
    actions: [
      { type: 'flag', message: 'Unapproved AI provider detected' },
    ],
    effect: 'deny',
  },

  // ══════════════════════════════════════════════════════════════════════════
  // IAM Boundaries & Cross-Account
  // ══════════════════════════════════════════════════════════════════════════

  'restrict-iam-pass-role': {
    name: 'Restrict IAM PassRole',
    description: 'Limit iam:PassRole to specific roles. Unrestricted PassRole enables privilege escalation by attaching high-privilege roles to compute resources.',
    policy_type: 'access', severity: 'critical',
    tags: ['iam', 'privilege-escalation', 'aws'],
    conditions: [
      { field: 'metadata.permissions', operator: 'contains', value: 'iam:PassRole' },
      { field: 'metadata.passrole_resource', operator: 'equals', value: '*' },
    ],
    actions: [
      { type: 'deny', message: 'Unrestricted iam:PassRole is prohibited' },
      { type: 'flag', message: 'Scope PassRole to specific role ARNs' },
    ],
  },

  'permission-boundary-required': {
    name: 'Permission Boundary Required',
    description: 'All IAM roles must have a permission boundary attached. Prevents privilege escalation beyond organizational limits.',
    policy_type: 'compliance', severity: 'high',
    tags: ['iam', 'boundary', 'compliance'],
    conditions: [
      { field: 'type', operator: 'in', value: 'iam-role,iam-user' },
      { field: 'metadata.permission_boundary', operator: 'not_exists' },
    ],
    actions: [
      { type: 'flag', message: 'IAM entity missing permission boundary' },
      { type: 'notify', message: 'Attach a permission boundary to limit blast radius' },
    ],
  },

  'cross-account-external-id': {
    name: 'Cross-Account Requires External ID',
    description: 'Cross-account role assumptions must use an external ID to prevent confused deputy attacks.',
    policy_type: 'access', severity: 'critical',
    tags: ['iam', 'cross-account', 'confused-deputy'],
    conditions: [
      { field: 'metadata.trust_policy.cross_account', operator: 'is_true' },
      { field: 'metadata.trust_policy.external_id', operator: 'not_exists' },
    ],
    actions: [
      { type: 'deny', message: 'Cross-account trust without external ID is prohibited' },
      { type: 'flag', message: 'Add external ID condition to trust policy' },
    ],
  },

  'restrict-trust-principal': {
    name: 'Restrict Trust Policy Principals',
    description: 'Trust policies must specify exact account IDs or ARNs. Wildcard principals (*) allow any AWS account to assume the role.',
    policy_type: 'access', severity: 'critical',
    tags: ['iam', 'cross-account', 'trust-policy'],
    conditions: [
      { field: 'metadata.trust_policy.principal', operator: 'equals', value: '*' },
    ],
    actions: [
      { type: 'deny', message: 'Wildcard trust principal is prohibited' },
    ],
  },

  'cross-account-trust-policy': {
    name: 'Cross-Account Trust Policy Review',
    description: 'Roles with cross-account trust must be reviewed and approved. Ensure the trusted account is within the organization.',
    policy_type: 'compliance', severity: 'high',
    tags: ['iam', 'cross-account', 'compliance'],
    conditions: [
      { field: 'metadata.trust_policy.cross_account', operator: 'is_true' },
      { field: 'metadata.trust_policy.org_verified', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Cross-account trust to account outside organization' },
      { type: 'require_approval', message: 'Security team approval required for external trust' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // Data & Storage Security
  // ══════════════════════════════════════════════════════════════════════════

  'public-bucket-deny': {
    name: 'Public Bucket Access Denied',
    description: 'S3/GCS buckets must not be publicly accessible. Enable block public access and restrict bucket policies.',
    policy_type: 'access', severity: 'critical',
    tags: ['storage', 'public-access', 'data'],
    conditions: [
      { field: 'type', operator: 'in', value: 's3-bucket,gcs-bucket,storage-bucket' },
      { field: 'metadata.is_public', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Public bucket access is prohibited' },
      { type: 'quarantine', message: 'Bucket quarantined until public access removed' },
    ],
  },

  'encryption-at-rest-required': {
    name: 'Encryption at Rest Required',
    description: 'All data stores (S3, RDS, Disks) must have encryption at rest enabled using KMS keys.',
    policy_type: 'compliance', severity: 'high',
    tags: ['encryption', 'data', 'compliance'],
    conditions: [
      { field: 'metadata.encryption_at_rest', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Data store lacks encryption at rest' },
      { type: 'notify', message: 'Enable encryption using customer-managed KMS key' },
    ],
  },

  'public-database-deny': {
    name: 'Public Database Access Denied',
    description: 'Databases (RDS, Cloud SQL) must not be publicly accessible. Restrict to private subnets and VPC-only access.',
    policy_type: 'access', severity: 'critical',
    tags: ['database', 'public-access', 'network'],
    conditions: [
      { field: 'type', operator: 'in', value: 'rds-instance,cloud-sql,database' },
      { field: 'metadata.publicly_accessible', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Public database access is prohibited' },
      { type: 'quarantine', message: 'Database quarantined until access restricted' },
    ],
  },

  'db-iam-auth-required': {
    name: 'Database IAM Authentication Required',
    description: 'Databases must use IAM authentication instead of static passwords. Eliminates credential management burden.',
    policy_type: 'access', severity: 'high',
    tags: ['database', 'iam', 'authentication'],
    conditions: [
      { field: 'type', operator: 'in', value: 'rds-instance,cloud-sql' },
      { field: 'metadata.iam_auth_enabled', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Database using password auth instead of IAM' },
      { type: 'notify', message: 'Enable IAM authentication for passwordless access' },
    ],
  },

  'backup-pitr-required': {
    name: 'Backup and PITR Required',
    description: 'Databases must have automated backups and point-in-time recovery (PITR) enabled for data protection.',
    policy_type: 'compliance', severity: 'medium',
    tags: ['database', 'backup', 'resilience'],
    conditions: [
      { field: 'type', operator: 'in', value: 'rds-instance,cloud-sql' },
      { field: 'metadata.backup_enabled', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Database backup/PITR not enabled' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // Network Security
  // ══════════════════════════════════════════════════════════════════════════

  'restrict-sg-public-ingress': {
    name: 'Restrict Security Group Public Ingress',
    description: 'Security groups must not allow unrestricted ingress from 0.0.0.0/0 on sensitive ports.',
    policy_type: 'access', severity: 'critical',
    tags: ['network', 'firewall', 'public-access'],
    conditions: [
      { field: 'type', operator: 'in', value: 'security-group,firewall-rule' },
      { field: 'metadata.allows_public_ingress', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Unrestricted public ingress is prohibited' },
      { type: 'flag', message: 'Restrict source CIDR to internal ranges' },
    ],
  },

  'private-subnet-required': {
    name: 'Private Subnet Required',
    description: 'Workloads handling sensitive data must be deployed in private subnets without direct internet access.',
    policy_type: 'access', severity: 'high',
    tags: ['network', 'subnet', 'isolation'],
    conditions: [
      { field: 'metadata.subnet_type', operator: 'equals', value: 'public' },
      { field: 'metadata.handles_sensitive_data', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'Sensitive workload in public subnet' },
      { type: 'notify', message: 'Move to private subnet with NAT gateway for outbound' },
    ],
  },

  'internal-service-isolation': {
    name: 'Internal Service Network Isolation',
    description: 'Internal services must not be reachable from public internet. Enforce VPC-only access and internal load balancers.',
    policy_type: 'access', severity: 'critical',
    tags: ['network', 'isolation', 'internal'],
    conditions: [
      { field: 'metadata.is_internal', operator: 'is_true' },
      { field: 'metadata.is_public', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Internal service must not be publicly accessible' },
      { type: 'quarantine', message: 'Service isolated until network configuration corrected' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // Key & Secret Management
  // ══════════════════════════════════════════════════════════════════════════

  'kms-rotation-required': {
    name: 'KMS Key Rotation Required',
    description: 'KMS encryption keys must have automatic rotation enabled. Maximum rotation period: 365 days.',
    policy_type: 'compliance', severity: 'high',
    tags: ['encryption', 'kms', 'rotation'],
    conditions: [
      { field: 'type', operator: 'in', value: 'kms-key,crypto-key' },
      { field: 'metadata.rotation_enabled', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'KMS key rotation not enabled' },
      { type: 'notify', message: 'Enable automatic key rotation' },
    ],
  },

  'secret-rotation-required': {
    name: 'Secret Rotation Required',
    description: 'Secrets in Secret Manager must have rotation configured. Stale secrets increase blast radius of credential theft.',
    policy_type: 'compliance', severity: 'high',
    tags: ['secret', 'rotation', 'lifecycle'],
    conditions: [
      { field: 'type', operator: 'in', value: 'managed-secret,secret' },
      { field: 'metadata.rotation_enabled', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Secret has no rotation policy' },
      { type: 'notify', message: 'Configure automatic rotation' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // Identity Attestation
  // ══════════════════════════════════════════════════════════════════════════

  'require-cryptographic-attestation': {
    name: 'Cryptographic Attestation Required',
    description: 'Workloads in sensitive environments must have cryptographic attestation (SPIFFE/SPIRE) — not just platform-level trust.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['attestation', 'spiffe', 'zero-trust'],
    conditions: [
      { field: 'environment', operator: 'in', value: 'production,staging' },
      { field: 'trust_level', operator: 'not_in', value: ['cryptographic', 'very-high'] },
    ],
    actions: [
      { type: 'flag', message: 'Workload lacks cryptographic attestation' },
      { type: 'notify', message: 'Deploy SPIRE agent for SPIFFE identity provisioning' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // AI/ML Security
  // ══════════════════════════════════════════════════════════════════════════

  'ai-endpoint-registration': {
    name: 'AI Endpoint Registration Required',
    description: 'All AI/ML API endpoints must be registered in the workload inventory. Unregistered endpoints are shadow AI.',
    policy_type: 'compliance', severity: 'high',
    tags: ['ai', 'inventory', 'shadow-ai'],
    conditions: [
      { field: 'metadata.calls_ai_api', operator: 'is_true' },
      { field: 'metadata.ai_endpoint_registered', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'Unregistered AI endpoint detected' },
      { type: 'notify', message: 'Register AI endpoint in workload inventory' },
    ],
  },

  'ai-vpc-only': {
    name: 'AI Endpoints VPC-Only Access',
    description: 'AI/ML endpoints must be accessed through VPC private endpoints or the LLM gateway — not over public internet.',
    policy_type: 'access', severity: 'high',
    tags: ['ai', 'network', 'private-access'],
    conditions: [
      { field: 'metadata.calls_ai_api', operator: 'is_true' },
      { field: 'metadata.ai_access_via_vpc', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'AI API accessed over public internet' },
      { type: 'notify', message: 'Route through VPC endpoint or LLM gateway' },
    ],
  },

  'shadow-ai-detection': {
    name: 'Shadow AI Detection',
    description: 'Detect workloads making undeclared calls to AI/ML APIs. Shadow AI bypasses security controls and data governance.',
    policy_type: 'compliance', severity: 'critical',
    tags: ['ai', 'shadow-ai', 'detection'],
    conditions: [
      { field: 'metadata.undeclared_ai_calls', operator: 'is_true' },
    ],
    actions: [
      { type: 'flag', message: 'Shadow AI usage detected — undeclared AI API calls' },
      { type: 'quarantine', message: 'Workload quarantined pending AI usage review' },
    ],
  },

  'llm-gateway-enforcement': {
    name: 'LLM Gateway Enforcement',
    description: 'All LLM/AI API calls must be routed through the centralized LLM gateway for logging, rate limiting, and PII filtering.',
    policy_type: 'access', severity: 'high',
    tags: ['ai', 'gateway', 'compliance'],
    conditions: [
      { field: 'metadata.calls_ai_api', operator: 'is_true' },
      { field: 'metadata.uses_llm_gateway', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Direct AI API calls must go through LLM gateway' },
      { type: 'flag', message: 'Route AI calls through gateway for audit and DLP' },
    ],
  },

  'ai-permission-audit': {
    name: 'AI Permission Audit',
    description: 'Audit IAM permissions that grant access to AI/ML services (Bedrock, Vertex AI, SageMaker). Ensure least privilege.',
    policy_type: 'compliance', severity: 'medium',
    tags: ['ai', 'iam', 'audit'],
    conditions: [
      { field: 'metadata.has_ai_permissions', operator: 'is_true' },
      { field: 'metadata.ai_workload_registered', operator: 'is_false' },
    ],
    actions: [
      { type: 'flag', message: 'AI permissions granted without registered AI workload' },
    ],
  },

  'ai-permission-revoke': {
    name: 'Revoke Unused AI Permissions',
    description: 'Revoke AI/ML service permissions from identities that have not used them in 90 days.',
    policy_type: 'compliance', severity: 'medium',
    tags: ['ai', 'iam', 'lifecycle'],
    conditions: [
      { field: 'metadata.has_ai_permissions', operator: 'is_true' },
      { field: 'metadata.ai_last_used_days', operator: 'gte', value: 90 },
    ],
    actions: [
      { type: 'flag', message: 'AI permissions unused for 90+ days' },
      { type: 'notify', message: 'Revoke unused AI permissions' },
    ],
  },

  'public-ai-endpoint-lockdown': {
    name: 'Public AI Endpoint Lockdown',
    description: 'AI model endpoints exposed to the internet must have authentication, rate limiting, and input validation.',
    policy_type: 'access', severity: 'critical',
    tags: ['ai', 'public-access', 'endpoint'],
    conditions: [
      { field: 'metadata.is_ai_endpoint', operator: 'is_true' },
      { field: 'metadata.is_public', operator: 'is_true' },
    ],
    actions: [
      { type: 'deny', message: 'Unprotected public AI endpoint is prohibited' },
      { type: 'quarantine', message: 'AI endpoint locked down pending security review' },
    ],
  },

  'ai-endpoint-auth': {
    name: 'AI Endpoint Authentication Required',
    description: 'AI/ML serving endpoints must require authentication. Unauthenticated endpoints risk model theft and abuse.',
    policy_type: 'access', severity: 'critical',
    tags: ['ai', 'authentication', 'endpoint'],
    conditions: [
      { field: 'metadata.is_ai_endpoint', operator: 'is_true' },
      { field: 'metadata.auth_required', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'AI endpoint without authentication is prohibited' },
    ],
  },

  // ══════════════════════════════════════════════════════════════════════════
  // CHAIN-AWARE ENFORCEMENT — Anti-Confused-Deputy (P1.1)
  // ══════════════════════════════════════════════════════════════════════════

  'require-authorized-chain': {
    name: 'Require Authorized Delegation Chain',
    description: 'Deny access when the delegation chain contains unauthorized hops. Prevents confused deputy attacks where sub-agents act with authority they should not have.',
    policy_type: 'access', severity: 'critical', effect: 'deny',
    tags: ['access', 'chain', 'delegation', 'anti-confused-deputy', 'agentic-governance'],
    conditions: [
      { field: 'chain.authorized', operator: 'is_false' },
    ],
    actions: [
      { type: 'deny', message: 'Delegation chain contains unauthorized hop — access denied (anti-confused-deputy)' },
    ],
  },

  'chain-max-depth': {
    name: 'Chain Depth Limit (Max 3 Hops)',
    description: 'Deny requests that exceed the maximum delegation chain depth. Limits blast radius by preventing excessively deep agent delegation chains.',
    policy_type: 'access', severity: 'high', effect: 'deny',
    tags: ['access', 'chain', 'delegation', 'depth-limit'],
    conditions: [
      { field: 'chain.depth', operator: 'gt', value: 3 },
    ],
    actions: [
      { type: 'deny', message: 'Delegation chain exceeds max depth of 3 hops — too many intermediaries' },
    ],
  },

  'chain-require-origin': {
    name: 'Require Known Chain Origin',
    description: 'Deny access when the chain origin (hop 0) is not a known, authorized workload. Ensures delegation chains start from trusted sources.',
    policy_type: 'access', severity: 'critical', effect: 'deny',
    tags: ['access', 'chain', 'delegation', 'origin-verification'],
    conditions: [
      { field: 'chain.origin', operator: 'not_exists' },
    ],
    actions: [
      { type: 'deny', message: 'Chain origin unknown — cannot verify delegation authority' },
    ],
  },
};


// ══════════════════════════════════════════════════════════════════════════════
// FINDING → TEMPLATE MAPPING
// ══════════════════════════════════════════════════════════════════════════════
// Maps graph finding types to recommended remediation templates.
// Used by the "Remediate" button on attack paths in the UI.
// ══════════════════════════════════════════════════════════════════════════════

const FINDING_REMEDIATION_MAP = {
  'toxic-combo': [
    { template_id: 'toxic-combo-financial-crm', name: 'Toxic Combo: Financial + CRM Separation', severity: 'critical' },
    { template_id: 'agent-scope-ceiling', name: 'Agent Scope Ceiling Enforcement', severity: 'critical' },
    { template_id: 'agent-tool-whitelist', name: 'Agent MCP Tool Whitelist', severity: 'high' },
    { template_id: 'jit-credential-required', name: 'JIT Credential Required for External APIs', severity: 'critical' },
  ],
  'a2a-no-auth': [
    { template_id: 'a2a-authentication-required', name: 'A2A Agent Authentication Required', severity: 'critical' },
    { template_id: 'agent-must-have-delegator', name: 'AI Agent Requires Human Delegator', severity: 'critical' },
    { template_id: 'agent-kill-switch-required', name: 'Agent Kill Switch Required', severity: 'high' },
  ],
  'a2a-unsigned-card': [
    { template_id: 'a2a-agent-card-signing', name: 'A2A Agent Card Must Be Signed', severity: 'medium' },
    { template_id: 'weak-trust-in-prod', name: 'Minimum Trust Level for Production', severity: 'critical' },
  ],
  'mcp-static-credentials': [
    { template_id: 'mcp-static-credential-ban', name: 'MCP Server Static Credential Ban', severity: 'critical' },
    { template_id: 'mcp-oauth-required', name: 'MCP OAuth 2.1 Required', severity: 'high' },
    { template_id: 'jit-credential-required', name: 'JIT Credential Required', severity: 'critical' },
  ],
  'static-external-credential': [
    { template_id: 'jit-credential-required', name: 'JIT Credential Required for External APIs', severity: 'critical' },
    { template_id: 'mcp-static-credential-ban', name: 'MCP Static Credential Ban', severity: 'critical' },
    { template_id: 'long-lived-api-key', name: 'Long-Lived API Key Detection', severity: 'high' },
    { template_id: 'secret-in-env-plaintext', name: 'Plaintext Secrets in Env Vars', severity: 'high' },
  ],
  'shared-sa': [
    { template_id: 'shared-service-account-deny', name: 'Shared Service Account Prohibition', severity: 'critical' },
    { template_id: 'env-credential-isolation', name: 'Environment Credential Isolation', severity: 'critical' },
  ],
  'key-leak': [
    { template_id: 'user-managed-key-prohibition', name: 'User-Managed Key Prohibition', severity: 'critical' },
    { template_id: 'credential-rotation-overdue', name: 'Credential Rotation Overdue', severity: 'high' },
    { template_id: 'long-lived-api-key', name: 'Long-Lived API Key Detection', severity: 'high' },
  ],
  'over-privileged': [
    { template_id: 'no-wildcard-permissions', name: 'No Wildcard Permissions', severity: 'critical' },
    { template_id: 'privilege-escalation-detection', name: 'Privilege Escalation Detection', severity: 'critical' },
    { template_id: 'editor-role-in-prod', name: 'Editor Role Prohibited in Production', severity: 'critical' },
    { template_id: 'admin-requires-crypto', name: 'Admin Requires Cryptographic Attestation', severity: 'critical' },
  ],
  'public-internal-pivot': [
    { template_id: 'public-endpoint-requires-auth', name: 'Public Endpoint Requires Authentication', severity: 'critical' },
    { template_id: 'cross-env-access-deny', name: 'Block Cross-Environment Access', severity: 'critical' },
  ],
  'public-exposure-untagged': [
    { template_id: 'public-resource-approval-required', name: 'Public Resource Requires Security Approval Tag', severity: 'high' },
    { template_id: 'restrict-public-access', name: 'Restrict Unapproved Public Access', severity: 'critical' },
    { template_id: 'public-endpoint-requires-auth', name: 'Public Endpoint Requires Authentication', severity: 'critical' },
  ],
  'privilege-escalation': [
    { template_id: 'restrict-iam-pass-role', name: 'Restrict IAM PassRole', severity: 'critical' },
    { template_id: 'permission-boundary-required', name: 'Permission Boundary Required', severity: 'high' },
    { template_id: 'privilege-escalation-detection', name: 'Privilege Escalation Detection', severity: 'critical' },
  ],
  'cross-account-trust': [
    { template_id: 'cross-account-external-id', name: 'Cross-Account Requires External ID', severity: 'critical' },
    { template_id: 'restrict-trust-principal', name: 'Restrict Trust Policy Principals', severity: 'critical' },
    { template_id: 'cross-account-restriction', name: 'Cross-Account Restriction', severity: 'high' },
  ],
  'unbounded-admin': [
    { template_id: 'permission-boundary-required', name: 'Permission Boundary Required', severity: 'high' },
    { template_id: 'admin-requires-crypto', name: 'Admin Requires Cryptographic Attestation', severity: 'critical' },
    { template_id: 'no-wildcard-permissions', name: 'No Wildcard Permissions', severity: 'critical' },
  ],
  'public-data-exposure': [
    { template_id: 'public-bucket-deny', name: 'Public Bucket Access Denied', severity: 'critical' },
    { template_id: 'encryption-at-rest-required', name: 'Encryption at Rest Required', severity: 'high' },
  ],
  'public-database': [
    { template_id: 'public-database-deny', name: 'Public Database Access Denied', severity: 'critical' },
    { template_id: 'db-iam-auth-required', name: 'Database IAM Authentication Required', severity: 'high' },
  ],
  'unencrypted-data-store': [
    { template_id: 'encryption-at-rest-required', name: 'Encryption at Rest Required', severity: 'high' },
    { template_id: 'backup-pitr-required', name: 'Backup and PITR Required', severity: 'medium' },
  ],
  'overly-permissive-sg': [
    { template_id: 'restrict-sg-public-ingress', name: 'Restrict Security Group Public Ingress', severity: 'critical' },
    { template_id: 'private-subnet-required', name: 'Private Subnet Required', severity: 'high' },
  ],
  'unrotated-kms-key': [
    { template_id: 'kms-rotation-required', name: 'KMS Key Rotation Required', severity: 'high' },
  ],
  'stale-secret': [
    { template_id: 'secret-rotation-required', name: 'Secret Rotation Required', severity: 'high' },
    { template_id: 'credential-rotation-overdue', name: 'Credential Rotation Overdue', severity: 'high' },
  ],
  'internet-to-data': [
    { template_id: 'internal-service-isolation', name: 'Internal Service Network Isolation', severity: 'critical' },
    { template_id: 'restrict-sg-public-ingress', name: 'Restrict Security Group Public Ingress', severity: 'critical' },
    { template_id: 'private-subnet-required', name: 'Private Subnet Required', severity: 'high' },
  ],
  'zombie-workload': [
    { template_id: 'stale-credential-lifecycle', name: 'Stale Credential Lifecycle', severity: 'high' },
    { template_id: 'inactivity-timeout-30', name: 'Inactivity Timeout 30 Days', severity: 'medium' },
    { template_id: 'max-credential-age', name: 'Maximum Credential Age', severity: 'high' },
  ],
  'rogue-workload': [
    { template_id: 'require-cryptographic-attestation', name: 'Cryptographic Attestation Required', severity: 'critical' },
    { template_id: 'shadow-identity-detection', name: 'Shadow Identity Detection', severity: 'high' },
  ],
  'unused-iam-role': [
    { template_id: 'stale-credential-lifecycle', name: 'Stale Credential Lifecycle', severity: 'high' },
    { template_id: 'max-credential-age', name: 'Maximum Credential Age', severity: 'high' },
    { template_id: 'unused-permissions-cleanup', name: 'Unused Permissions Cleanup', severity: 'medium' },
  ],
  'orphaned-asset': [
    { template_id: 'shadow-identity-detection', name: 'Shadow Identity Detection', severity: 'high' },
    { template_id: 'stale-credential-lifecycle', name: 'Stale Credential Lifecycle', severity: 'high' },
  ],
  'account-outside-org': [
    { template_id: 'cross-account-trust-policy', name: 'Cross-Account Trust Policy Review', severity: 'high' },
    { template_id: 'cross-account-external-id', name: 'Cross-Account Requires External ID', severity: 'critical' },
    { template_id: 'restrict-trust-principal', name: 'Restrict Trust Policy Principals', severity: 'critical' },
  ],
  'unregistered-ai-endpoint': [
    { template_id: 'ai-endpoint-registration', name: 'AI Endpoint Registration Required', severity: 'high' },
    { template_id: 'ai-vpc-only', name: 'AI Endpoints VPC-Only Access', severity: 'high' },
  ],
  'shadow-ai-usage': [
    { template_id: 'shadow-ai-detection', name: 'Shadow AI Detection', severity: 'critical' },
    { template_id: 'llm-gateway-enforcement', name: 'LLM Gateway Enforcement', severity: 'high' },
    { template_id: 'ai-provider-restriction', name: 'AI Provider Restriction', severity: 'high' },
  ],
  'ai-permission-without-workload': [
    { template_id: 'ai-permission-audit', name: 'AI Permission Audit', severity: 'medium' },
    { template_id: 'ai-permission-revoke', name: 'Revoke Unused AI Permissions', severity: 'medium' },
  ],
  'public-ai-endpoint': [
    { template_id: 'public-ai-endpoint-lockdown', name: 'Public AI Endpoint Lockdown', severity: 'critical' },
    { template_id: 'ai-endpoint-auth', name: 'AI Endpoint Authentication Required', severity: 'critical' },
    { template_id: 'public-endpoint-requires-auth', name: 'Public Endpoint Requires Authentication', severity: 'critical' },
  ],
};

module.exports = { POLICY_TEMPLATES, FINDING_REMEDIATION_MAP };