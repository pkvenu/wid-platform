// =============================================================================
// Policy Evaluator — Unified Engine for All 6 Policy Types
// =============================================================================
// Supports: Access, Least Privilege, Lifecycle, Compliance/Posture,
//           Conditional Access, and AI Agent policies.
//
// This module has ZERO coupling to any policy runtime (OPA, Cedar, etc.)
// It evaluates conditions against workloads, relationships, and runtime context.
// =============================================================================

// ── Condition Operators ──
const OPERATORS = {
  // String
  equals:       (a, b) => String(a||'').toLowerCase() === String(b||'').toLowerCase(),
  not_equals:   (a, b) => String(a||'').toLowerCase() !== String(b||'').toLowerCase(),
  contains:     (a, b) => String(a||'').toLowerCase().includes(String(b||'').toLowerCase()),
  not_contains: (a, b) => !String(a||'').toLowerCase().includes(String(b||'').toLowerCase()),
  starts_with:  (a, b) => String(a||'').toLowerCase().startsWith(String(b||'').toLowerCase()),
  ends_with:    (a, b) => String(a||'').toLowerCase().endsWith(String(b||'').toLowerCase()),
  in:           (a, b) => (Array.isArray(b) ? b : String(b).split(',')).map(s => s.trim().toLowerCase()).includes(String(a||'').toLowerCase()),
  not_in:       (a, b) => !(Array.isArray(b) ? b : String(b).split(',')).map(s => s.trim().toLowerCase()).includes(String(a||'').toLowerCase()),
  matches:      (a, b) => { try { return new RegExp(b, 'i').test(String(a||'')); } catch { return false; } },
  // Numeric
  gt:           (a, b) => Number(a) > Number(b),
  gte:          (a, b) => Number(a) >= Number(b),
  lt:           (a, b) => Number(a) < Number(b),
  lte:          (a, b) => Number(a) <= Number(b),
  between:      (a, b) => { const [lo, hi] = Array.isArray(b) ? b : String(b).split(',').map(Number); return Number(a) >= lo && Number(a) <= hi; },
  // Boolean / existence
  is_true:      (a) => a === true || a === 'true',
  is_false:     (a) => a === false || a === 'false' || !a,
  exists:       (a) => a !== null && a !== undefined && a !== '',
  not_exists:   (a) => a === null || a === undefined || a === '',
  // Time
  older_than_days: (a, b) => { if (!a) return true; return (Date.now() - new Date(a).getTime()) / 86400000 > Number(b); },
  newer_than_days: (a, b) => { if (!a) return false; return (Date.now() - new Date(a).getTime()) / 86400000 < Number(b); },
  // Time window (value = "HH:MM-HH:MM" or { start: "HH:MM", end: "HH:MM" })
  within_time_window: (a, b) => {
    const now = a ? new Date(a) : new Date();
    const hhmm = now.getUTCHours() * 60 + now.getUTCMinutes();
    let start, end;
    if (typeof b === 'object' && b.start) {
      const [sh, sm] = b.start.split(':').map(Number);
      const [eh, em] = b.end.split(':').map(Number);
      start = sh * 60 + sm; end = eh * 60 + em;
    } else {
      const parts = String(b).split('-');
      const [sh, sm] = parts[0].split(':').map(Number);
      const [eh, em] = parts[1].split(':').map(Number);
      start = sh * 60 + sm; end = eh * 60 + em;
    }
    return start <= end ? (hhmm >= start && hhmm <= end) : (hhmm >= start || hhmm <= end);
  },
  outside_time_window: (a, b) => !OPERATORS.within_time_window(a, b),
  // Day-of-week (value = "mon,tue,wed,thu,fri" or array)
  on_day: (a, b) => {
    const now = a ? new Date(a) : new Date();
    const days = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
    const today = days[now.getUTCDay()];
    const allowed = (Array.isArray(b) ? b : String(b).split(',')).map(s => s.trim().toLowerCase());
    return allowed.includes(today);
  },
  not_on_day: (a, b) => !OPERATORS.on_day(a, b),
  // Array/set operations
  includes_any: (a, b) => {
    const arr = Array.isArray(a) ? a : String(a||'').split(',').map(s => s.trim());
    const target = Array.isArray(b) ? b : String(b).split(',').map(s => s.trim());
    return arr.some(item => target.map(t => t.toLowerCase()).includes(item.toLowerCase()));
  },
  includes_all: (a, b) => {
    const arr = Array.isArray(a) ? a : String(a||'').split(',').map(s => s.trim());
    const target = Array.isArray(b) ? b : String(b).split(',').map(s => s.trim());
    return target.every(t => arr.map(a => a.toLowerCase()).includes(t.toLowerCase()));
  },
  is_subset_of: (a, b) => {
    const arr = Array.isArray(a) ? a : String(a||'').split(',').map(s => s.trim());
    const allowed = Array.isArray(b) ? b : String(b).split(',').map(s => s.trim());
    return arr.every(item => allowed.map(a => a.toLowerCase()).includes(item.toLowerCase()));
  },
  exceeds_count: (a, b) => {
    const arr = Array.isArray(a) ? a : String(a||'').split(',').filter(Boolean);
    return arr.length > Number(b);
  },
};

// ══════════════════════════════════════════════════════════════════════════════
// POLICY TYPES — Each type defines what fields, operators, and context it uses
// ══════════════════════════════════════════════════════════════════════════════

const POLICY_TYPES = {
  compliance: {
    label: 'Compliance / Posture',
    description: 'Ensure workloads meet organizational security standards and compliance requirements.',
    icon: 'shield-check',
    binding: 'workload',           // evaluates single workload attributes
    examples: ['Owner required', 'SPIFFE ID required', 'Shadow detection', 'Naming conventions'],
  },
  lifecycle: {
    label: 'Lifecycle',
    description: 'Govern credential rotation, staleness, expiry, and decommissioning of NHIs.',
    icon: 'clock',
    binding: 'workload',
    examples: ['Stale credentials', 'Rotation overdue', 'Expiry enforcement', 'Inactivity timeout'],
  },
  access: {
    label: 'Access',
    description: 'Control which workloads can access which resources, under what conditions.',
    icon: 'arrow-right-left',
    binding: 'relationship',       // evaluates client→server pair
    examples: ['Service A → Service B allowed', 'Prod-only access', 'Time-windowed access'],
  },
  least_privilege: {
    label: 'Least Privilege / Permission',
    description: 'Enforce minimal necessary permissions — scopes, actions, resource boundaries.',
    icon: 'lock',
    binding: 'workload',
    examples: ['No wildcard permissions', 'Read-only for non-prod', 'Scope restrictions'],
  },
  conditional_access: {
    label: 'Conditional Access',
    description: 'Dynamic runtime conditions — time, geo, posture score, approval workflows.',
    icon: 'filter',
    binding: 'relationship',       // evaluated at access time with runtime context
    examples: ['Business hours only', 'Geo-restricted', 'Posture check', 'Anomaly detection'],
  },
  ai_agent: {
    label: 'AI Agent',
    description: 'Govern autonomous AI agent access — scope ceilings, delegation, attribution, kill switches.',
    icon: 'bot',
    binding: 'workload',           // evaluated against agent workloads (type=ai-agent)
    examples: ['Agent scope ceiling', 'Human delegation binding', 'MCP gateway control'],
  },
};

// ══════════════════════════════════════════════════════════════════════════════
// CONDITION FIELDS — Extended for all 6 policy types
// ══════════════════════════════════════════════════════════════════════════════

const CONDITION_FIELDS = [
  // ── Workload Attributes (compliance, lifecycle, least-privilege) ──
  { key: 'trust_level',           label: 'Trust Level',            type: 'select',    options: ['cryptographic', 'very-high', 'high', 'medium', 'low', 'none'], category: 'identity' },
  { key: 'security_score',        label: 'Security Score',         type: 'number',    category: 'identity' },
  { key: 'environment',           label: 'Environment',            type: 'select',    options: ['production', 'staging', 'development', 'testing', 'unknown'], category: 'identity' },
  { key: 'type',                  label: 'Identity Type',          type: 'select',    options: ['lambda', 'container', 'iam-role', 'iam-user', 'service-account', 'api-key', 'secret', 'secret-engine', 'oidc-provider', 'ai-agent', 'mcp-server'], category: 'identity' },
  { key: 'cloud_provider',        label: 'Cloud Provider',         type: 'select',    options: ['aws', 'gcp', 'azure', 'docker', 'kubernetes', 'vault', 'github'], category: 'identity' },
  { key: 'verified',              label: 'Attested',               type: 'boolean',   category: 'identity' },
  { key: 'is_shadow',             label: 'Is Shadow',              type: 'boolean',   category: 'identity' },
  { key: 'owner',                 label: 'Has Owner',              type: 'existence', category: 'identity' },
  { key: 'team',                  label: 'Has Team',               type: 'existence', category: 'identity' },
  { key: 'spiffe_id',             label: 'Has SPIFFE ID',          type: 'existence', category: 'identity' },
  { key: 'name',                  label: 'Identity Name',          type: 'string',    category: 'identity' },
  { key: 'category',              label: 'Category',               type: 'string',    category: 'identity' },

  // ── Lifecycle / Temporal ──
  { key: 'last_seen',             label: 'Last Seen',              type: 'date',      category: 'lifecycle' },
  { key: 'created_at',            label: 'Created At',             type: 'date',      category: 'lifecycle' },
  { key: 'attestation_expires',   label: 'Attestation Expiry',     type: 'date',      category: 'lifecycle' },
  { key: 'credential_age_days',   label: 'Credential Age (days)',  type: 'number',    category: 'lifecycle', computed: true },
  { key: 'last_rotation',         label: 'Last Credential Rotation', type: 'date',    category: 'lifecycle' },
  { key: 'expiry_date',           label: 'Credential Expiry Date', type: 'date',      category: 'lifecycle' },
  { key: 'inactive_days',         label: 'Days Inactive',          type: 'number',    category: 'lifecycle', computed: true },

  // ── Permission / Least Privilege ──
  { key: 'permissions',           label: 'Permissions',            type: 'array',     category: 'permission' },
  { key: 'scopes',                label: 'Granted Scopes',         type: 'array',     category: 'permission' },
  { key: 'allowed_actions',       label: 'Allowed Actions',        type: 'array',     category: 'permission' },
  { key: 'resource_count',        label: 'Accessible Resources',   type: 'number',    category: 'permission' },
  { key: 'has_wildcard',          label: 'Has Wildcard Permissions', type: 'boolean',  category: 'permission' },
  { key: 'is_privileged',         label: 'Is Privileged/Admin',    type: 'boolean',   category: 'permission' },
  { key: 'can_escalate',          label: 'Can Escalate Privileges', type: 'boolean',  category: 'permission' },
  { key: 'cross_account',         label: 'Cross-Account Access',   type: 'boolean',   category: 'permission' },

  // ── Access Relationship (access + conditional access) ──
  { key: 'client.name',           label: 'Client Workload Name',   type: 'string',    category: 'access' },
  { key: 'client.type',           label: 'Client Type',            type: 'select',    options: ['lambda', 'container', 'iam-role', 'iam-user', 'service-account', 'api-key', 'ai-agent'], category: 'access' },
  { key: 'client.environment',    label: 'Client Environment',     type: 'select',    options: ['production', 'staging', 'development', 'testing'], category: 'access' },
  { key: 'client.trust_level',    label: 'Client Trust Level',     type: 'select',    options: ['cryptographic', 'very-high', 'high', 'medium', 'low', 'none'], category: 'access' },
  { key: 'client.verified',       label: 'Client Attested',        type: 'boolean',   category: 'access' },
  { key: 'client.team',           label: 'Client Team',            type: 'string',    category: 'access' },
  { key: 'server.name',           label: 'Server Workload Name',   type: 'string',    category: 'access' },
  { key: 'server.type',           label: 'Server Type',            type: 'string',    category: 'access' },
  { key: 'server.environment',    label: 'Server Environment',     type: 'select',    options: ['production', 'staging', 'development', 'testing'], category: 'access' },
  { key: 'server.data_classification', label: 'Data Classification', type: 'select', options: ['public', 'internal', 'confidential', 'restricted', 'pii'], category: 'access' },

  // ── Runtime Context (conditional access) ──
  { key: 'runtime.time',          label: 'Current Time (UTC)',     type: 'time_window', category: 'runtime' },
  { key: 'runtime.day',           label: 'Day of Week',            type: 'day',       category: 'runtime' },
  { key: 'runtime.source_ip',     label: 'Source IP / CIDR',       type: 'string',    category: 'runtime' },
  { key: 'runtime.geo',           label: 'Geo Location',           type: 'string',    category: 'runtime' },
  { key: 'runtime.network_zone',  label: 'Network Zone',           type: 'select',    options: ['internal', 'dmz', 'external', 'vpn'], category: 'runtime' },
  { key: 'runtime.posture_score', label: 'Runtime Posture Score',  type: 'number',    category: 'runtime' },
  { key: 'runtime.request_rate',  label: 'Request Rate (req/hr)',  type: 'number',    category: 'runtime' },
  { key: 'runtime.mfa_verified',  label: 'MFA Verified',           type: 'boolean',   category: 'runtime' },
  { key: 'runtime.approval_status', label: 'Approval Status',      type: 'select',    options: ['approved', 'pending', 'denied', 'not_required'], category: 'runtime' },

  // ── AI Request Context (live traffic attributes from gateway) ──
  { key: 'ai.provider',           label: 'AI Provider',            type: 'string',    category: 'ai_request' },
  { key: 'ai.model',              label: 'AI Model (request)',     type: 'string',    category: 'ai_request' },
  { key: 'ai.operation',          label: 'AI Operation',           type: 'select',    options: ['chat', 'embeddings', 'completions', 'images'], category: 'ai_request' },
  { key: 'ai.estimated_tokens',   label: 'Estimated Input Tokens', type: 'number',   category: 'ai_request' },
  { key: 'ai.tool_names',         label: 'Tools Requested',        type: 'array',    category: 'ai_request' },
  { key: 'ai.cost_today_usd',     label: 'Daily Cost (USD)',       type: 'number',   category: 'ai_request' },
  { key: 'ai.requests_today',     label: 'Daily Request Count',    type: 'number',   category: 'ai_request' },
  { key: 'ai.tokens_today',       label: 'Daily Token Count',      type: 'number',   category: 'ai_request' },

  // ── AI Agent fields ──
  { key: 'agent.model',           label: 'Agent Model',            type: 'string',    category: 'ai_agent' },
  { key: 'agent.delegator',       label: 'Human Delegator',        type: 'existence', category: 'ai_agent' },
  { key: 'agent.scope_ceiling',   label: 'Scope Ceiling',          type: 'array',     category: 'ai_agent' },
  { key: 'agent.autonomous',      label: 'Is Autonomous',          type: 'boolean',   category: 'ai_agent' },
  { key: 'agent.session_ttl',     label: 'Session TTL (minutes)',  type: 'number',    category: 'ai_agent' },
  { key: 'agent.tools_allowed',   label: 'Allowed MCP Tools',      type: 'array',     category: 'ai_agent' },
  { key: 'agent.tools_requested', label: 'Requested MCP Tools',    type: 'array',     category: 'ai_agent' },
  { key: 'agent.kill_switch',     label: 'Kill Switch Enabled',    type: 'boolean',   category: 'ai_agent' },
  { key: 'agent.human_in_loop',   label: 'Human-in-Loop Required', type: 'boolean',   category: 'ai_agent' },

  // ── Delegation Chain fields (chain-aware enforcement) ──
  { key: 'chain.depth',           label: 'Chain Depth',            type: 'number',    category: 'chain' },
  { key: 'chain.origin',          label: 'Chain Origin (hop 0)',   type: 'string',    category: 'chain' },
  { key: 'chain.delegator',       label: 'Immediate Delegator',    type: 'string',    category: 'chain' },
  { key: 'chain.has_delegator',   label: 'Has Delegator',          type: 'existence', category: 'chain' },
  { key: 'chain.authorized',      label: 'Chain Authorized',       type: 'boolean',   category: 'chain' },
  { key: 'chain.all_hops_allowed', label: 'All Hops Allowed',     type: 'boolean',   category: 'chain' },
  { key: 'chain.has_revoked_hop', label: 'Has Revoked Hop',        type: 'boolean',   category: 'chain' },
  { key: 'chain.root_jti',        label: 'Root Token JTI',         type: 'existence', category: 'chain' },
  { key: 'chain.hops',            label: 'Chain Hops',             type: 'array',     category: 'chain' },
];

// ── Operators grouped by field type ──
const OPERATORS_BY_TYPE = {
  string:      ['equals', 'not_equals', 'contains', 'not_contains', 'starts_with', 'ends_with', 'in', 'not_in', 'matches'],
  number:      ['equals', 'not_equals', 'gt', 'gte', 'lt', 'lte', 'between'],
  select:      ['equals', 'not_equals', 'in', 'not_in'],
  boolean:     ['is_true', 'is_false'],
  existence:   ['exists', 'not_exists'],
  date:        ['exists', 'not_exists', 'older_than_days', 'newer_than_days'],
  time_window: ['within_time_window', 'outside_time_window'],
  day:         ['on_day', 'not_on_day'],
  array:       ['includes_any', 'includes_all', 'is_subset_of', 'exceeds_count', 'exists', 'not_exists'],
};

// ── Action types — extended for all 6 policy types ──
const ACTION_TYPES = [
  // Compliance / General
  { key: 'flag',              label: 'Flag as violation',           description: 'Create a violation record for review', applies_to: ['compliance', 'lifecycle', 'access', 'least_privilege', 'conditional_access', 'ai_agent'] },
  { key: 'block_deploy',      label: 'Block deployment',           description: 'Prevent workload from deploying', applies_to: ['compliance', 'least_privilege'] },
  { key: 'require_attest',    label: 'Require re-attestation',     description: 'Force re-attestation before access', applies_to: ['compliance', 'access', 'conditional_access'] },
  { key: 'revoke_access',     label: 'Revoke access',              description: 'Immediately revoke credentials/tokens', applies_to: ['access', 'lifecycle', 'conditional_access', 'ai_agent'] },
  { key: 'notify',            label: 'Notify owner/team',          description: 'Send notification to assigned owner or team', applies_to: ['compliance', 'lifecycle', 'access', 'least_privilege', 'conditional_access', 'ai_agent'] },
  { key: 'quarantine',        label: 'Quarantine identity',        description: 'Isolate identity from production access', applies_to: ['compliance', 'lifecycle', 'conditional_access'] },
  { key: 'auto_remediate',    label: 'Auto-remediate',             description: 'Attempt automatic fix (rotate key, assign owner)', applies_to: ['compliance', 'lifecycle', 'least_privilege'] },
  // Access-specific
  { key: 'allow',             label: 'Allow access',               description: 'Explicitly permit this access path', applies_to: ['access', 'conditional_access'] },
  { key: 'deny',              label: 'Deny access',                description: 'Explicitly deny this access path', applies_to: ['access', 'conditional_access'] },
  { key: 'allow_with_logging', label: 'Allow with enhanced logging', description: 'Permit but log every request for audit', applies_to: ['access', 'conditional_access', 'ai_agent'] },
  { key: 'rate_limit',        label: 'Rate limit',                 description: 'Throttle access to max requests/hour', applies_to: ['access', 'conditional_access'] },
  { key: 'require_approval',  label: 'Require human approval',     description: 'Queue access request for human approval before granting', applies_to: ['access', 'conditional_access', 'ai_agent'] },
  // Lifecycle
  { key: 'force_rotation',    label: 'Force credential rotation',  description: 'Trigger immediate credential rotation', applies_to: ['lifecycle'] },
  { key: 'disable_identity',  label: 'Disable identity',           description: 'Disable the identity pending review', applies_to: ['lifecycle', 'compliance'] },
  { key: 'schedule_decommission', label: 'Schedule decommission',  description: 'Mark identity for decommission after grace period', applies_to: ['lifecycle'] },
  // Permission
  { key: 'downgrade_permissions', label: 'Downgrade permissions',  description: 'Reduce permissions to minimum required set', applies_to: ['least_privilege'] },
  { key: 'remove_wildcard',   label: 'Remove wildcard access',     description: 'Replace wildcard (*) with explicit resource list', applies_to: ['least_privilege'] },
  // AI Agent
  { key: 'kill_agent',        label: 'Kill agent session',         description: 'Immediately terminate agent session and revoke all tokens', applies_to: ['ai_agent'] },
  { key: 'restrict_tools',    label: 'Restrict MCP tools',         description: 'Limit agent to approved tool set only', applies_to: ['ai_agent'] },
  { key: 'require_human_loop', label: 'Require human-in-loop',     description: 'Force human approval for each agent action', applies_to: ['ai_agent'] },
  { key: 'bind_delegator',    label: 'Bind to delegator identity', description: 'Ensure agent operates within delegator permissions', applies_to: ['ai_agent'] },
];


// ══════════════════════════════════════════════════════════════════════════════
// Credential Policy Schema (for access policies)
// ══════════════════════════════════════════════════════════════════════════════

const CREDENTIAL_TYPES = [
  { key: 'ephemeral_token',  label: 'Ephemeral Token',      description: 'Short-lived token issued at runtime' },
  { key: 'mtls',             label: 'Mutual TLS (mTLS)',    description: 'Certificate-based mutual authentication' },
  { key: 'spiffe_svid',      label: 'SPIFFE SVID',          description: 'SPIFFE Verifiable Identity Document' },
  { key: 'oidc_token',       label: 'OIDC Token',           description: 'OpenID Connect identity token' },
  { key: 'api_key',          label: 'API Key',              description: 'Static API key (discouraged)' },
  { key: 'aws_sts',          label: 'AWS STS Assume Role',  description: 'Temporary AWS credentials via STS' },
  { key: 'service_account_key', label: 'Service Account Key', description: 'Cloud service account key (rotate frequently)' },
];

// ══════════════════════════════════════════════════════════════════════════════
// Evaluator Class — Unified for all 6 policy types
// ══════════════════════════════════════════════════════════════════════════════

class PolicyEvaluator {

  // ── Resolve a field from a context object (supports dot notation) ──
  resolveField(context, field) {
    if (!field) return undefined;
    // Handle computed fields
    if (field === 'credential_age_days' && context.created_at) {
      return Math.floor((Date.now() - new Date(context.created_at).getTime()) / 86400000);
    }
    if (field === 'inactive_days' && context.last_seen) {
      return Math.floor((Date.now() - new Date(context.last_seen).getTime()) / 86400000);
    }
    // Canonical aliases: source → client, destination → server
    // Policies authored with source.name / destination.name resolve against client/server context
    let resolved = field;
    if (field.startsWith('source.')) resolved = 'client.' + field.slice(7);
    else if (field.startsWith('destination.')) resolved = 'server.' + field.slice(12);
    // Dot notation traversal
    return resolved.split('.').reduce((obj, key) => obj?.[key], context);
  }

  // ── Evaluate a single condition against a context ──
  evaluateCondition(condition, context) {
    const { field, operator, value } = condition;
    const actual = this.resolveField(context, field);
    const fn = OPERATORS[operator];
    if (!fn) return { passed: false, field, operator, error: `Unknown operator: ${operator}` };
    try {
      return { passed: fn(actual, value), field, operator, expected: value, actual };
    } catch (err) {
      return { passed: false, field, operator, error: err.message };
    }
  }

  // ── Build evaluation context based on policy type ──
  buildContext(policy, workload, opts = {}) {
    const policyType = POLICY_TYPES[policy.policy_type];
    if (!policyType) return workload; // fallback

    const ctx = { ...workload };

    // For relationship-based policies, merge client + server + runtime
    if (policyType.binding === 'relationship') {
      if (opts.client) ctx.client = opts.client;
      if (opts.server) ctx.server = opts.server;
      if (opts.runtime) ctx.runtime = opts.runtime;
    }

    // For conditional access, always include runtime context
    if (policy.policy_type === 'conditional_access' && opts.runtime) {
      ctx.runtime = { ...ctx.runtime, ...opts.runtime };
    }

    // For AI agent policies, merge agent metadata
    if (policy.policy_type === 'ai_agent' && (workload.agent || opts.agent)) {
      ctx.agent = { ...workload.agent, ...opts.agent };
    }

    // AI request context (live traffic attributes from gateway evaluate)
    if (opts.ai) {
      ctx.ai = opts.ai;
    }

    return ctx;
  }

  // ── Scope check (unchanged, extended for relationships) ──
  inScope(policy, workload) {
    if (policy.scope_environment && workload.environment !== policy.scope_environment) return false;
    if (policy.scope_types?.length && !policy.scope_types.includes(workload.type)) return false;
    if (policy.scope_teams?.length && workload.team && !policy.scope_teams.includes(workload.team)) return false;
    // Access policies: check client/server binding
    if (policy.client_workload_id && workload.id !== policy.client_workload_id) return false;
    if (policy.server_workload_id && workload.server_id !== policy.server_workload_id) return false;
    return true;
  }

  // ── Evaluate a single policy against a context ──
  evaluatePolicy(policy, workload, opts = {}) {
    if (!this.inScope(policy, workload)) {
      return { violated: false, skipped: true, reason: 'Out of scope' };
    }

    const context = this.buildContext(policy, workload, opts);
    const conditions = Array.isArray(policy.conditions) ? policy.conditions : [];
    const results = conditions.map(c => this.evaluateCondition(c, context));

    // For access policies with effect='allow': violation = conditions NOT met
    // For all others: violation = ALL conditions met (they describe the bad state)
    const isAccessAllow = (policy.policy_type === 'access' || policy.policy_type === 'conditional_access') && policy.effect === 'allow';
    const allMatch = results.every(r => r.passed);
    const violated = isAccessAllow ? !allMatch : allMatch;

    return {
      violated,
      conditions: results,
      workload_id: workload.id,
      workload_name: workload.name,
      policy_id: policy.id,
      policy_name: policy.name,
      policy_type: policy.policy_type,
      severity: policy.severity,
      effect: policy.effect || null,
      actions: violated ? (policy.actions || []) : [],
      message: violated ? (policy.actions?.[0]?.message || `Policy "${policy.name}" violated`) : null,
    };
  }

  // ── Evaluate multiple policies against one workload ──
  evaluateAll(policies, workload, opts = {}) {
    return policies
      .filter(p => p.enabled && p.enforcement_mode !== 'disabled')
      .map(p => this.evaluatePolicy(p, workload, opts))
      .filter(r => !r.skipped);
  }

  // ── Evaluate one policy against many workloads ──
  evaluateAgainstAll(policy, workloads, opts = {}) {
    const results = [];
    let violations = 0, evaluated = 0;
    for (const w of workloads) {
      const r = this.evaluatePolicy(policy, w, opts);
      if (!r.skipped) {
        evaluated++;
        if (r.violated) { violations++; results.push(r); }
      }
    }
    return { total: workloads.length, evaluated, violations, results };
  }

  // ── Evaluate an access request (client→server with runtime + chain context) ──
  evaluateAccessRequest(policies, client, server, runtime = {}, chainContext = null) {
    // Extract AI context from runtime so it's available as a top-level field
    const { ai: aiContext, ...runtimeRest } = runtime;

    const context = {
      id: `${client.id}->${server.id}`,
      name: `${client.name} → ${server.name}`,
      environment: client.environment,
      type: client.type,
      client,
      server,
      runtime: {
        time: new Date().toISOString(),
        day: new Date().toISOString(),
        ...runtimeRest,
      },
    };

    // Merge AI context at top level for policy evaluation
    if (aiContext) context.ai = aiContext;

    // Merge chain context for delegation chain policy evaluation
    // chain = { depth, origin, delegator, has_delegator, authorized, all_hops_allowed,
    //           has_revoked_hop, root_jti, hops: [{source, destination, verdict, hop_index}] }
    if (chainContext) context.chain = chainContext;

    const decisions = [];
    let finalDecision = 'no-match'; // no-match until a policy explicitly allows or denies

    for (const policy of policies.filter(p => p.enabled && p.enforcement_mode !== 'disabled')) {
      if (policy.policy_type !== 'access' && policy.policy_type !== 'conditional_access') continue;

      const result = this.evaluatePolicy(policy, context, { client, server, runtime: context.runtime, ai: aiContext });

      if (!result.skipped) {
        decisions.push(result);

        // Explicit deny is final (highest priority)
        if (result.violated && policy.effect === 'deny') {
          finalDecision = 'deny';
          break;
        }
        // First explicit allow wins (policies are priority-ordered)
        if (!result.violated && policy.effect === 'allow') {
          finalDecision = 'allow';
          break;
        }
      }
    }

    return {
      decision: finalDecision,
      client: { id: client.id, name: client.name },
      server: { id: server.id, name: server.name },
      evaluated: decisions.length,
      decisions,
      runtime: context.runtime,
      chain_context: chainContext || null,
      timestamp: new Date().toISOString(),
    };
  }
}


module.exports = {
  PolicyEvaluator,
  OPERATORS,
  OPERATORS_BY_TYPE,
  CONDITION_FIELDS,
  ACTION_TYPES,
  POLICY_TYPES,
  CREDENTIAL_TYPES,
};