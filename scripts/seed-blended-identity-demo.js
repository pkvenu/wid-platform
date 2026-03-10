#!/usr/bin/env node

// =============================================================================
// Blended Identity Demo — Seed Script (Token Chains + Decisions)
//
// Agent containers are discovered automatically by the Docker scanner.
// This script seeds:
//   1. Human delegator workloads (users — not containers, so must be seeded)
//   2. Token chain records (OBO delegation flows)
//   3. Authorization decisions (blended identity allow/deny records)
//
// Run AFTER containers are up and first discovery scan completes (~30s).
// =============================================================================

const { Client } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://wip_user:wip_password@localhost:5432/workload_identity';
const DISCOVERY_URL = process.env.DISCOVERY_URL || 'http://localhost:3004';
const NAMESPACE = 'demo-blended';

function rand(len = 6) { return [...Array(len)].map(() => Math.random().toString(36)[2]).join(''); }
function jti(prefix) { return `${prefix}-${Date.now()}-${rand(4)}`; }

// =============================================================================
// Human Delegators (seeded — these are users, not containers)
// =============================================================================
const HUMAN_DELEGATORS = [
  // UC1: ServiceNow
  {
    name: 'sarah-chen-it-ops',
    type: 'user',
    namespace: NAMESPACE,
    environment: 'production',
    category: 'human-identity',
    subcategory: 'it-operations',
    cloud_provider: 'local',
    is_ai_agent: false,
    is_mcp_server: false,
    verified: true,
    trust_level: 'high',
    verification_method: 'sso-saml',
    security_score: 92,
    owner: 'sarah.chen@acme.com',
    team: 'it-operations',
    cost_center: 'IT-001',
    labels: { 'identity.type': 'human', 'identity.department': 'it-operations' },
    metadata: {
      email: 'sarah.chen@acme.com',
      role: 'IT Operations Engineer',
      department: 'IT Operations',
      entitlements: ['jira:write', 'pagerduty:read', 'pagerduty:ack'],
      sso_provider: 'Okta',
      mfa_enabled: true,
      networks: ['demo-blended-servicenow'],
    },
    spiffe_id: 'spiffe://acme.com/user/sarah-chen-it-ops',
  },
  {
    name: 'mike-rogers-hr',
    type: 'user',
    namespace: NAMESPACE,
    environment: 'production',
    category: 'human-identity',
    subcategory: 'human-resources',
    cloud_provider: 'local',
    is_ai_agent: false,
    is_mcp_server: false,
    verified: true,
    trust_level: 'high',
    verification_method: 'sso-saml',
    security_score: 90,
    owner: 'mike.rogers@acme.com',
    team: 'human-resources',
    cost_center: 'HR-001',
    labels: { 'identity.type': 'human', 'identity.department': 'human-resources' },
    metadata: {
      email: 'mike.rogers@acme.com',
      role: 'HR Business Partner',
      department: 'Human Resources',
      entitlements: ['workday:read', 'workday:employee-data', 'workday:benefits'],
      sso_provider: 'Okta',
      mfa_enabled: true,
      networks: ['demo-blended-servicenow'],
    },
    spiffe_id: 'spiffe://acme.com/user/mike-rogers-hr',
  },
  {
    name: 'dr-lisa-park-medical',
    type: 'user',
    namespace: NAMESPACE,
    environment: 'production',
    category: 'human-identity',
    subcategory: 'medical-staff',
    cloud_provider: 'local',
    is_ai_agent: false,
    is_mcp_server: false,
    verified: true,
    trust_level: 'very-high',
    verification_method: 'piv-card',
    security_score: 95,
    owner: 'dr.lisa.park@acme.com',
    team: 'medical',
    cost_center: 'MED-001',
    labels: { 'identity.type': 'human', 'identity.department': 'medical', 'identity.clearance': 'hipaa' },
    metadata: {
      email: 'dr.lisa.park@acme.com',
      role: 'Chief Medical Officer',
      department: 'Medical',
      entitlements: ['epic:fhir-read', 'epic:patient-records', 'epic:clinical-notes'],
      sso_provider: 'Okta',
      mfa_enabled: true,
      piv_card: true,
      networks: ['demo-blended-servicenow'],
    },
    spiffe_id: 'spiffe://acme.com/user/dr-lisa-park-medical',
  },
  // UC2: Code Review
  {
    name: 'alex-dev-engineer',
    type: 'user',
    namespace: NAMESPACE,
    environment: 'production',
    category: 'human-identity',
    subcategory: 'engineering',
    cloud_provider: 'local',
    is_ai_agent: false,
    is_mcp_server: false,
    verified: true,
    trust_level: 'high',
    verification_method: 'sso-oidc',
    security_score: 88,
    owner: 'alex.dev@acme.com',
    team: 'platform-engineering',
    cost_center: 'ENG-001',
    labels: { 'identity.type': 'human', 'identity.department': 'engineering' },
    metadata: {
      email: 'alex.dev@acme.com',
      role: 'Principal Engineer',
      department: 'Platform Engineering',
      entitlements: ['github:repo:write', 'github:pr:approve', 'snyk:scan:read'],
      sso_provider: 'Okta',
      mfa_enabled: true,
      networks: ['demo-blended-cicd'],
    },
    spiffe_id: 'spiffe://acme.com/user/alex-dev-engineer',
  },
  // UC3: Customer Support
  {
    name: 'emma-support-rep',
    type: 'user',
    namespace: NAMESPACE,
    environment: 'production',
    category: 'human-identity',
    subcategory: 'customer-support',
    cloud_provider: 'local',
    is_ai_agent: false,
    is_mcp_server: false,
    verified: true,
    trust_level: 'high',
    verification_method: 'sso-saml',
    security_score: 85,
    owner: 'emma.support@acme.com',
    team: 'customer-support',
    cost_center: 'CS-001',
    labels: { 'identity.type': 'human', 'identity.department': 'customer-support' },
    metadata: {
      email: 'emma.support@acme.com',
      role: 'Senior Support Engineer',
      department: 'Customer Support',
      entitlements: ['billing:read', 'crm:read', 'crm:update', 'zendesk:tickets:write'],
      sso_provider: 'Okta',
      mfa_enabled: true,
      networks: ['demo-blended-support'],
    },
    spiffe_id: 'spiffe://acme.com/user/emma-support-rep',
  },
];

// =============================================================================
// Token Chain Records (OBO delegation flows)
// =============================================================================
function buildTokenChains() {
  const now = new Date();
  const chains = [];
  const demo = { demo: 'blended-identity' };

  // --- UC1: ServiceNow Blended Identity ---
  // Sarah → Agent → Jira (allowed)
  const sarahRoot = jti('obo-sarah-sn');
  chains.push({
    jti: sarahRoot, parent_jti: null, root_jti: sarahRoot, chain_depth: 0,
    subject: 'sarah.chen@acme.com', audience: 'servicenow-it-agent', actor: null,
    scopes: ['jira:write', 'pagerduty:read', 'pagerduty:ack'],
    issued_at: now, expires_at: new Date(+now + 15 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'sarah', flow: 'root' },
  });
  chains.push({
    jti: jti('obo-sarah-jira'), parent_jti: sarahRoot, root_jti: sarahRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/servicenow-it-agent', audience: 'jira-api', actor: 'sarah.chen@acme.com',
    scopes: ['jira:write'],
    issued_at: new Date(+now + 200), expires_at: new Date(+now + 5 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'sarah', flow: 'jira-allowed' },
  });

  // Mike → Agent → Workday (allowed)
  const mikeRoot = jti('obo-mike-sn');
  chains.push({
    jti: mikeRoot, parent_jti: null, root_jti: mikeRoot, chain_depth: 0,
    subject: 'mike.rogers@acme.com', audience: 'servicenow-it-agent', actor: null,
    scopes: ['workday:read', 'workday:employee-data'],
    issued_at: new Date(+now - 3600000), expires_at: new Date(+now + 12 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'mike', flow: 'root' },
  });
  chains.push({
    jti: jti('obo-mike-wd'), parent_jti: mikeRoot, root_jti: mikeRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/servicenow-it-agent', audience: 'workday-api', actor: 'mike.rogers@acme.com',
    scopes: ['workday:read'],
    issued_at: new Date(+now - 3600000 + 200), expires_at: new Date(+now - 3600000 + 5 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'mike', flow: 'workday-allowed' },
  });

  // Dr. Lisa → Agent → Epic FHIR (allowed)
  const lisaRoot = jti('obo-lisa-sn');
  chains.push({
    jti: lisaRoot, parent_jti: null, root_jti: lisaRoot, chain_depth: 0,
    subject: 'dr.lisa.park@acme.com', audience: 'servicenow-it-agent', actor: null,
    scopes: ['epic:fhir-read', 'epic:patient-records'],
    issued_at: new Date(+now - 7200000), expires_at: new Date(+now + 10 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'lisa', flow: 'root' },
  });
  chains.push({
    jti: jti('obo-lisa-epic'), parent_jti: lisaRoot, root_jti: lisaRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/servicenow-it-agent', audience: 'epic-fhir-api', actor: 'dr.lisa.park@acme.com',
    scopes: ['epic:fhir-read'],
    issued_at: new Date(+now - 7200000 + 200), expires_at: new Date(+now - 7200000 + 5 * 60000), metadata: { ...demo, use_case: 'uc1', human: 'lisa', flow: 'epic-allowed' },
  });

  // --- UC2: Code Review Pipeline (chain depth 3) ---
  const alexRoot = jti('obo-alex-gh');
  const alexHop1 = jti('obo-alex-cr');
  const alexHop2 = jti('obo-alex-ss');
  chains.push({
    jti: alexRoot, parent_jti: null, root_jti: alexRoot, chain_depth: 0,
    subject: 'alex.dev@acme.com', audience: 'github-actions-agent', actor: null,
    scopes: ['github:repo:write', 'github:pr:approve', 'snyk:scan:read'],
    issued_at: new Date(+now - 1800000), expires_at: new Date(+now + 30 * 60000), metadata: { ...demo, use_case: 'uc2', human: 'alex', flow: 'root' },
  });
  chains.push({
    jti: alexHop1, parent_jti: alexRoot, root_jti: alexRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/github-actions-agent', audience: 'code-review-agent-gpt4', actor: 'alex.dev@acme.com',
    scopes: ['github:pr:review', 'snyk:scan:read'],
    issued_at: new Date(+now - 1800000 + 500), expires_at: new Date(+now + 15 * 60000), metadata: { ...demo, use_case: 'uc2', flow: 'gh-to-codereview' },
  });
  chains.push({
    jti: alexHop2, parent_jti: alexHop1, root_jti: alexRoot, chain_depth: 2,
    subject: 'spiffe://acme.com/agent/code-review-agent-gpt4', audience: 'security-scanner-agent', actor: 'spiffe://acme.com/agent/github-actions-agent',
    scopes: ['snyk:scan:read'],
    issued_at: new Date(+now - 1800000 + 1000), expires_at: new Date(+now + 5 * 60000), metadata: { ...demo, use_case: 'uc2', flow: 'codereview-to-scanner' },
  });

  // --- UC3: Customer Support (fan-out) ---
  const emmaRoot = jti('obo-emma-zd');
  chains.push({
    jti: emmaRoot, parent_jti: null, root_jti: emmaRoot, chain_depth: 0,
    subject: 'emma.support@acme.com', audience: 'zendesk-ai-orchestrator', actor: null,
    scopes: ['billing:read', 'crm:read', 'crm:update', 'zendesk:tickets:write'],
    issued_at: new Date(+now - 900000), expires_at: new Date(+now + 15 * 60000), metadata: { ...demo, use_case: 'uc3', human: 'emma', flow: 'root' },
  });
  chains.push({
    jti: jti('obo-emma-bill'), parent_jti: emmaRoot, root_jti: emmaRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/zendesk-ai-orchestrator', audience: 'billing-agent', actor: 'emma.support@acme.com',
    scopes: ['billing:read'],
    issued_at: new Date(+now - 900000 + 200), expires_at: new Date(+now + 5 * 60000), metadata: { ...demo, use_case: 'uc3', flow: 'orchestrator-to-billing' },
  });
  chains.push({
    jti: jti('obo-emma-crm'), parent_jti: emmaRoot, root_jti: emmaRoot, chain_depth: 1,
    subject: 'spiffe://acme.com/agent/zendesk-ai-orchestrator', audience: 'crm-agent', actor: 'emma.support@acme.com',
    scopes: ['crm:read', 'crm:update'],
    issued_at: new Date(+now - 900000 + 400), expires_at: new Date(+now + 5 * 60000), metadata: { ...demo, use_case: 'uc3', flow: 'orchestrator-to-crm' },
  });

  return chains;
}

// =============================================================================
// Authorization Decisions (blended identity allow/deny)
// =============================================================================
function buildDecisions() {
  const decisions = [];
  const now = Date.now();

  function decision(uc, source, dest, verdict, mode, humanDelegator, agentId, scopes, extra = {}) {
    const ts = now - Math.floor(Math.random() * 86400000);
    const traceId = `trace-demo-blended-uc${uc}-${ts}-${mode}`;
    return {
      decision_id: `blended-${uc}-${rand(8)}`,
      source_name: source,
      destination_name: dest,
      source_principal: `spiffe://acme.com/agent/${agentId}`,
      destination_principal: `spiffe://acme.com/external/${dest.toLowerCase().replace(/\s/g, '-')}`,
      method: extra.method || 'POST',
      path_pattern: extra.path || '/api/v1/resource',
      verdict,
      policy_name: 'blended-identity-scope-check',
      adapter_mode: mode,
      trace_id: traceId,
      hop_index: extra.hop_index || 1,
      total_hops: extra.total_hops || 2,
      chain_depth: extra.chain_depth || 1,
      enforcement_action: verdict === 'deny' ? 'BLOCK' : verdict === 'audit-deny' ? 'WOULD_BLOCK' : null,
      token_context: JSON.stringify({
        human_delegator: humanDelegator,
        agent_identity: agentId,
        effective_scopes: scopes,
        delegation_verified: verdict === 'allow',
        blended_identity: true,
        scope_violation: verdict !== 'allow',
        ...(verdict !== 'allow' && { reason: `Delegator ${humanDelegator} lacks required scope for ${dest}` }),
      }),
      created_at: new Date(ts),
    };
  }

  // --- UC1: ServiceNow decisions ---
  for (let i = 0; i < 5; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Jira API', 'allow', 'audit', 'sarah.chen@acme.com', 'servicenow-it-agent', ['jira:write'], { path: '/rest/api/3/issue' }));
  for (let i = 0; i < 3; i++) decisions.push(decision(1, 'servicenow-it-agent', 'PagerDuty API', 'allow', 'audit', 'sarah.chen@acme.com', 'servicenow-it-agent', ['pagerduty:read'], { path: '/incidents' }));
  for (let i = 0; i < 3; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Epic FHIR API', 'deny', 'enforce', 'sarah.chen@acme.com', 'servicenow-it-agent', ['epic:fhir-read'], { path: '/api/FHIR/R4/Patient' }));
  for (let i = 0; i < 2; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Workday API', 'deny', 'enforce', 'sarah.chen@acme.com', 'servicenow-it-agent', ['workday:read'], { path: '/ccx/service/api' }));
  for (let i = 0; i < 4; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Workday API', 'allow', 'audit', 'mike.rogers@acme.com', 'servicenow-it-agent', ['workday:read'], { path: '/ccx/service/api' }));
  for (let i = 0; i < 2; i++) decisions.push(decision(1, 'servicenow-it-agent', 'PagerDuty API', 'deny', 'enforce', 'mike.rogers@acme.com', 'servicenow-it-agent', ['pagerduty:read'], { path: '/incidents' }));
  for (let i = 0; i < 3; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Epic FHIR API', 'allow', 'audit', 'dr.lisa.park@acme.com', 'servicenow-it-agent', ['epic:fhir-read'], { path: '/api/FHIR/R4/Patient' }));
  for (let i = 0; i < 2; i++) decisions.push(decision(1, 'servicenow-it-agent', 'Jira API', 'audit-deny', 'simulate', 'NONE', 'servicenow-it-agent', ['jira:write'], { path: '/rest/api/3/issue' }));

  // --- UC2: Code Review Pipeline ---
  for (let i = 0; i < 4; i++) {
    const ts = now - Math.floor(Math.random() * 86400000);
    const traceId = `trace-demo-blended-uc2-chain-${ts}`;
    decisions.push({ ...decision(2, 'github-actions-agent', 'code-review-agent-gpt4', 'allow', 'audit', 'alex.dev@acme.com', 'github-actions-agent', ['github:pr:review'], { path: '/api/review', hop_index: 0, total_hops: 3, chain_depth: 0 }), trace_id: traceId });
    decisions.push({ ...decision(2, 'code-review-agent-gpt4', 'security-scanner-agent', 'allow', 'audit', 'alex.dev@acme.com', 'code-review-agent-gpt4', ['snyk:scan:read'], { path: '/api/scan', hop_index: 1, total_hops: 3, chain_depth: 1 }), trace_id: traceId });
    decisions.push({ ...decision(2, 'security-scanner-agent', 'Snyk API', 'allow', 'audit', 'alex.dev@acme.com', 'security-scanner-agent', ['snyk:scan:read'], { path: '/v1/test/npm', hop_index: 2, total_hops: 3, chain_depth: 2 }), trace_id: traceId });
  }
  for (let i = 0; i < 3; i++) decisions.push(decision(2, 'security-scanner-agent', 'GitHub API', 'deny', 'enforce', 'alex.dev@acme.com', 'security-scanner-agent', ['github:repo:write'], { path: '/repos/acme/app/contents' }));

  // --- UC3: Customer Support ---
  for (let i = 0; i < 4; i++) decisions.push(decision(3, 'zendesk-ai-orchestrator', 'Stripe API', 'allow', 'audit', 'emma.support@acme.com', 'zendesk-ai-orchestrator', ['billing:read'], { path: '/v1/charges', hop_index: 1, total_hops: 2 }));
  for (let i = 0; i < 4; i++) decisions.push(decision(3, 'zendesk-ai-orchestrator', 'Salesforce API', 'allow', 'audit', 'emma.support@acme.com', 'zendesk-ai-orchestrator', ['crm:read'], { path: '/services/data/v58.0/query', hop_index: 1, total_hops: 2 }));
  for (let i = 0; i < 3; i++) decisions.push(decision(3, 'zendesk-ai-orchestrator', 'Stripe API', 'deny', 'enforce', 'NONE', 'zendesk-ai-orchestrator', ['billing:read'], { path: '/v1/refunds' }));
  for (let i = 0; i < 3; i++) decisions.push(decision(3, 'zendesk-ai-orchestrator', 'Salesforce API', 'audit-deny', 'simulate', 'emma.support@acme.com', 'zendesk-ai-orchestrator', ['crm:update', 'billing:read'], { path: '/services/data/v58.0/sobjects/Account' }));

  return decisions;
}

// =============================================================================
// Insert Functions
// =============================================================================
async function insertWorkload(client, w) {
  await client.query(`
    INSERT INTO workloads (
      spiffe_id, name, type, namespace, environment,
      cloud_provider, category, subcategory,
      is_ai_agent, is_mcp_server,
      discovered_by, labels, metadata,
      security_score, status, verified,
      verification_method, trust_level,
      owner, team, cost_center,
      is_shadow, is_dormant
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
      $11, $12, $13, $14, $15, $16, $17, $18,
      $19, $20, $21, $22, $23
    ) ON CONFLICT (spiffe_id) DO UPDATE SET
      name = EXCLUDED.name,
      type = EXCLUDED.type,
      namespace = EXCLUDED.namespace,
      metadata = EXCLUDED.metadata,
      labels = EXCLUDED.labels,
      is_ai_agent = EXCLUDED.is_ai_agent,
      security_score = EXCLUDED.security_score,
      verified = EXCLUDED.verified,
      trust_level = EXCLUDED.trust_level
  `, [
    w.spiffe_id, w.name, w.type, w.namespace, w.environment,
    w.cloud_provider, w.category, w.subcategory,
    w.is_ai_agent || false, w.is_mcp_server || false,
    'blended-identity-seed', JSON.stringify(w.labels || {}), JSON.stringify(w.metadata || {}),
    w.security_score || 50, 'active', w.verified || false,
    w.verification_method || null, w.trust_level || 'none',
    w.owner || null, w.team || null, w.cost_center || null,
    false, false,
  ]);
}

async function insertTokenChain(client, tc) {
  await client.query(`
    INSERT INTO token_chain (jti, parent_jti, root_jti, chain_depth, subject, audience, actor, scopes, issued_at, expires_at, metadata)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    ON CONFLICT (jti) DO NOTHING
  `, [
    tc.jti, tc.parent_jti, tc.root_jti, tc.chain_depth,
    tc.subject, tc.audience, tc.actor,
    JSON.stringify(tc.scopes), tc.issued_at, tc.expires_at,
    JSON.stringify(tc.metadata),
  ]);
}

async function insertDecision(client, d) {
  await client.query(`
    INSERT INTO ext_authz_decisions (
      decision_id, source_name, destination_name, source_principal, destination_principal,
      method, path_pattern, verdict, policy_name, adapter_mode,
      trace_id, hop_index, total_hops, chain_depth,
      enforcement_action, token_context, created_at
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
  `, [
    d.decision_id, d.source_name, d.destination_name, d.source_principal, d.destination_principal,
    d.method, d.path_pattern, d.verdict, d.policy_name, d.adapter_mode,
    d.trace_id, d.hop_index, d.total_hops, d.chain_depth,
    d.enforcement_action, d.token_context, d.created_at,
  ]);
}

// =============================================================================
// Main
// =============================================================================
async function main() {
  const client = new Client(DATABASE_URL);
  await client.connect();
  console.log('Connected to PostgreSQL');

  try {
    // Clean previous demo data
    console.log('\n--- Cleaning previous demo data ---');
    const del1 = await client.query(`DELETE FROM workloads WHERE namespace = $1 AND type = 'user'`, [NAMESPACE]);
    const del2 = await client.query(`DELETE FROM token_chain WHERE metadata->>'demo' = 'blended-identity'`);
    const del3 = await client.query(`DELETE FROM ext_authz_decisions WHERE trace_id LIKE 'trace-demo-blended-%'`);
    console.log(`  Cleaned: ${del1.rowCount} user workloads, ${del2.rowCount} tokens, ${del3.rowCount} decisions`);

    // Insert human delegators (users — not containers, so must be seeded)
    console.log(`\n--- Inserting ${HUMAN_DELEGATORS.length} human delegators ---`);
    for (const w of HUMAN_DELEGATORS) {
      await insertWorkload(client, w);
      console.log(`  [user] ${w.name} (trust=${w.trust_level}, score=${w.security_score})`);
    }

    // Insert token chains
    const chains = buildTokenChains();
    console.log(`\n--- Inserting ${chains.length} token chain records ---`);
    for (const tc of chains) {
      await insertTokenChain(client, tc);
      const arrow = tc.chain_depth === 0 ? '[ROOT]' : `  -> depth=${tc.chain_depth}`;
      console.log(`  ${arrow} ${tc.subject} -> ${tc.audience} [${tc.scopes.join(', ')}]`);
    }

    // Insert authorization decisions
    const decisions = buildDecisions();
    console.log(`\n--- Inserting ${decisions.length} authorization decisions ---`);
    let allows = 0, denies = 0, simulates = 0;
    for (const d of decisions) {
      await insertDecision(client, d);
      if (d.verdict === 'allow') allows++;
      else if (d.verdict === 'deny') denies++;
      else simulates++;
    }
    console.log(`  ${allows} allow, ${denies} deny, ${simulates} simulate`);

    // Trigger graph rebuild
    console.log('\n--- Triggering graph rebuild ---');
    try {
      await fetch(`${DISCOVERY_URL}/api/v1/graph/reset`, { method: 'POST' });
      console.log('  Graph cache cleared');
      await new Promise(r => setTimeout(r, 2000));
      const graphResp = await fetch(`${DISCOVERY_URL}/api/v1/graph`);
      const graph = await graphResp.json();
      console.log(`  Graph rebuilt: ${graph.nodes?.length || 0} nodes, ${graph.relationships?.length || 0} edges`);
      console.log(`  Attack paths: ${graph.attack_paths?.length || 0}`);
    } catch (e) {
      console.log(`  Graph rebuild skipped (discovery service may not be running): ${e.message}`);
    }

    // Summary
    console.log('\n===================================================');
    console.log('  Blended Identity Demo Data Seeded!');
    console.log('===================================================');
    console.log(`  Human delegators: ${HUMAN_DELEGATORS.length}`);
    console.log(`  Agent containers: 7 (discovered by Docker scanner)`);
    console.log(`  Token chains: ${chains.length}`);
    console.log(`  Decisions: ${decisions.length} (${allows} allow, ${denies} deny, ${simulates} simulate)`);
    console.log('\n  Use Cases:');
    console.log('    UC1: ServiceNow Agent -> Jira/PagerDuty/Workday/Epic FHIR');
    console.log('    UC2: GitHub Actions -> Code Review GPT-4 -> Security Scanner -> Snyk');
    console.log('    UC3: Zendesk AI -> Billing (Stripe) + CRM (Salesforce)');
    console.log('\n  Open http://localhost:3100/graph to see the demo');

  } finally {
    await client.end();
  }
}

main().catch(err => { console.error('Seed failed:', err); process.exit(1); });
