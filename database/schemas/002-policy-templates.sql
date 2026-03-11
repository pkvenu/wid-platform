-- =============================================================================
-- Migration 002: policy_templates + finding_remediation_map
-- =============================================================================
-- Creates separate policy_templates table, seeds 69 templates, and maps
-- finding types to remediation templates.
--
-- Run:
--   psql -U wid_admin -h 10.141.0.3 -d workload_identity -f 002-policy-templates.sql
--
-- Safe to re-run (uses ON CONFLICT DO UPDATE).
-- =============================================================================

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- 1. CREATE policy_templates TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS policy_templates (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    policy_type VARCHAR(30) NOT NULL
        CHECK (policy_type IN (
            'enforcement', 'compliance', 'lifecycle',
            'access', 'least_privilege', 'conditional_access', 'ai_agent'
        )),
    severity VARCHAR(20) NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    conditions JSONB NOT NULL DEFAULT '[]',
    actions JSONB NOT NULL DEFAULT '[]',
    scope_environment VARCHAR(50) DEFAULT NULL,
    scope_types TEXT[] DEFAULT NULL,
    effect VARCHAR(20) DEFAULT NULL
        CHECK (effect IS NULL OR effect IN ('allow', 'deny')),
    tags TEXT[] DEFAULT '{}',
    enabled BOOLEAN DEFAULT true,
    version INTEGER DEFAULT 1,
    created_by VARCHAR(255) DEFAULT 'system',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_templates_type ON policy_templates(policy_type);
CREATE INDEX IF NOT EXISTS idx_policy_templates_severity ON policy_templates(severity);
CREATE INDEX IF NOT EXISTS idx_policy_templates_enabled ON policy_templates(enabled);

COMMENT ON TABLE policy_templates IS 'Policy template catalog — editable via SQL/API without redeployment';
COMMENT ON COLUMN policy_templates.id IS 'Unique slug ID (e.g. prod-attestation-required)';
COMMENT ON COLUMN policy_templates.version IS 'Auto-incremented on update; deployed policies track source version';

-- Auto-update updated_at + version on edit
CREATE OR REPLACE FUNCTION update_policy_template_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    NEW.version = OLD.version + 1;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_policy_template_updated_at ON policy_templates;
CREATE TRIGGER trigger_policy_template_updated_at
    BEFORE UPDATE ON policy_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_policy_template_updated_at();


-- ═══════════════════════════════════════════════════════════════════════════════
-- 2. CREATE finding_remediation_map TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS finding_remediation_map (
    id SERIAL PRIMARY KEY,
    finding_type VARCHAR(100) NOT NULL,
    template_id VARCHAR(100) NOT NULL REFERENCES policy_templates(id) ON DELETE CASCADE,
    priority INTEGER DEFAULT 1,
    reason TEXT DEFAULT '',
    UNIQUE(finding_type, template_id)
);

CREATE INDEX IF NOT EXISTS idx_frm_finding ON finding_remediation_map(finding_type);
CREATE INDEX IF NOT EXISTS idx_frm_template ON finding_remediation_map(template_id);

COMMENT ON TABLE finding_remediation_map IS 'Maps graph finding types to recommended remediation templates';
COMMENT ON COLUMN finding_remediation_map.priority IS '1 = highest priority recommendation';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 3. ADD template_version TO policies TABLE
-- ═══════════════════════════════════════════════════════════════════════════════

ALTER TABLE policies ADD COLUMN IF NOT EXISTS template_version INTEGER DEFAULT NULL;
COMMENT ON COLUMN policies.template_version IS 'Version of the source template at deployment time';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 4. SEED 69 TEMPLATES (upsert)
-- ═══════════════════════════════════════════════════════════════════════════════

INSERT INTO policy_templates (id, name, description, policy_type, severity, conditions, actions, scope_environment, effect)
VALUES
  ('prod-attestation-required', 'Production Attestation Required', 'All production workloads must be attested before deployment.', 'compliance', 'critical', '[{"field":"environment","operator":"equals","value":"production"},{"field":"verified","operator":"is_false"}]'::jsonb, '[{"type":"flag","message":"Production workload is not attested"},{"type":"block_deploy","message":"Deployment blocked — attestation required"}]'::jsonb, 'production', NULL),
  ('no-owner-violation', 'Owner Required for All Identities', 'Every NHI must have an assigned owner for accountability.', 'compliance', 'high', '[{"field":"owner","operator":"not_exists"}]'::jsonb, '[{"type":"flag","message":"Identity has no assigned owner"},{"type":"notify","message":"Unowned identity detected — assign an owner"}]'::jsonb, NULL, NULL),
  ('shadow-identity-detection', 'Shadow Identity Detection', 'Shadow identities must be reviewed and either attested or decommissioned.', 'compliance', 'high', '[{"field":"is_shadow","operator":"is_true"}]'::jsonb, '[{"type":"flag","message":"Shadow identity detected"},{"type":"require_attest","message":"Attestation required to clear shadow status"}]'::jsonb, NULL, NULL),
  ('no-spiffe-production', 'SPIFFE Identity Required in Production', 'All production workloads should have a SPIFFE identity for zero-trust mesh.', 'compliance', 'medium', '[{"field":"environment","operator":"equals","value":"production"},{"field":"spiffe_id","operator":"not_exists"}]'::jsonb, '[{"type":"flag","message":"Production workload has no SPIFFE identity"},{"type":"notify","message":"Deploy SPIRE agent to provision SPIFFE ID"}]'::jsonb, NULL, NULL),
  ('naming-convention', 'NHI Naming Convention Required', 'All service accounts must follow svc-{env}-{purpose} naming convention.', 'compliance', 'medium', '[{"field":"type","operator":"in","value":"service-account,iam-role,iam-user"},{"field":"name","operator":"matches","value":"^(?!svc-(prod|staging|dev|test)-)"}]'::jsonb, '[{"type":"flag","message":"Identity name does not follow naming convention (svc-{env}-{purpose})"},{"type":"notify","message":"Rename identity to match organizational naming standard"}]'::jsonb, NULL, NULL),
  ('secret-engine-audit', 'Secret Engine Audit', 'All secret engines and credential stores must be attested and have an owner.', 'compliance', 'high', '[{"field":"type","operator":"in","value":"secret,secret-engine"},{"field":"verified","operator":"is_false"}]'::jsonb, '[{"type":"flag","message":"Unattested secret engine/credential store"},{"type":"require_attest","message":"Secret engines must be attested for compliance"}]'::jsonb, NULL, NULL),
  ('stale-credential-lifecycle', 'Stale Credential Lifecycle', 'Identities not seen in 90+ days should be reviewed for decommissioning.', 'lifecycle', 'medium', '[{"field":"last_seen","operator":"older_than_days","value":"90"}]'::jsonb, '[{"type":"flag","message":"Identity is stale (>90 days inactive)"},{"type":"quarantine","message":"Quarantine stale identity pending review"}]'::jsonb, NULL, NULL),
  ('credential-rotation-overdue', 'Credential Rotation Overdue', 'Credentials not rotated in 90 days violate rotation policy.', 'lifecycle', 'high', '[{"field":"last_rotation","operator":"older_than_days","value":"90"}]'::jsonb, '[{"type":"flag","message":"Credential rotation overdue (>90 days)"},{"type":"force_rotation","message":"Triggering automatic credential rotation"},{"type":"notify","message":"Credential rotation required within 7 days"}]'::jsonb, NULL, NULL),
  ('max-credential-age', 'Maximum Credential Age (365 Days)', 'No credential should be older than 365 days. Auto-disable after limit.', 'lifecycle', 'critical', '[{"field":"created_at","operator":"older_than_days","value":"365"}]'::jsonb, '[{"type":"flag","message":"Credential exceeds maximum age (365 days)"},{"type":"disable_identity","message":"Identity disabled — credential age limit exceeded"},{"type":"schedule_decommission","message":"Scheduled for decommission in 30 days"}]'::jsonb, NULL, NULL),
  ('inactivity-timeout-30', 'Inactivity Timeout (30 Days)', 'Identities inactive for 30+ days are flagged; 60+ days are disabled.', 'lifecycle', 'medium', '[{"field":"inactive_days","operator":"gt","value":"30"}]'::jsonb, '[{"type":"flag","message":"Identity inactive for 30+ days"},{"type":"notify","message":"Review inactive identity — disable if no longer needed"}]'::jsonb, NULL, NULL),
  ('expiry-enforcement', 'Credential Expiry Enforcement', 'Credentials must be renewed before expiry. Flag 14 days before, disable on expiry.', 'lifecycle', 'high', '[{"field":"expiry_date","operator":"newer_than_days","value":"14"}]'::jsonb, '[{"type":"flag","message":"Credential expiring within 14 days"},{"type":"notify","message":"Credential renewal required before expiry"},{"type":"force_rotation","message":"Auto-rotate credential before expiry"}]'::jsonb, NULL, NULL),
  ('cross-env-access-deny', 'Block Cross-Environment Access', 'Production services cannot access staging/dev resources and vice versa.', 'access', 'critical', '[{"field":"client.environment","operator":"equals","value":"production"},{"field":"server.environment","operator":"not_equals","value":"production"}]'::jsonb, '[{"type":"deny","message":"Cross-environment access denied (prod → non-prod)"},{"type":"flag","message":"Cross-environment access attempt detected"}]'::jsonb, NULL, 'deny'),
  ('prod-requires-attestation', 'Attested Clients Only for Production Resources', 'Only attested workloads with HIGH+ trust can access production servers.', 'access', 'critical', '[{"field":"server.environment","operator":"equals","value":"production"},{"field":"client.verified","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"Unattested client cannot access production resource"},{"type":"require_attest","message":"Client must be attested before accessing production"}]'::jsonb, NULL, 'deny'),
  ('prod-min-trust-access', 'Minimum Trust Level for Production Access', 'Clients must have HIGH or above trust to access production servers.', 'access', 'critical', '[{"field":"server.environment","operator":"equals","value":"production"},{"field":"client.trust_level","operator":"in","value":"low,none,medium"}]'::jsonb, '[{"type":"deny","message":"Insufficient trust level for production access"},{"type":"flag","message":"Low-trust client attempted production access"}]'::jsonb, NULL, 'deny'),
  ('pii-data-access', 'PII Data Access Restriction', 'Only explicitly approved services can access PII-classified resources.', 'access', 'critical', '[{"field":"server.data_classification","operator":"in","value":"pii,restricted"},{"field":"client.trust_level","operator":"not_equals","value":"cryptographic"}]'::jsonb, '[{"type":"deny","message":"PII access requires cryptographic attestation"},{"type":"flag","message":"Unauthorized PII access attempt"},{"type":"notify","message":"Security alert: PII access attempt by non-crypto-attested client"}]'::jsonb, NULL, 'deny'),
  ('no-wildcard-permissions', 'No Wildcard Permissions', 'Wildcard (*) permissions are prohibited. All access must be explicitly scoped.', 'least_privilege', 'critical', '[{"field":"has_wildcard","operator":"is_true"}]'::jsonb, '[{"type":"flag","message":"Wildcard permissions detected"},{"type":"remove_wildcard","message":"Replace wildcard with explicit resource list"},{"type":"notify","message":"Wildcard permissions must be remediated within 7 days"}]'::jsonb, NULL, NULL),
  ('privilege-escalation-detection', 'Privilege Escalation Detection', 'Identities with ability to escalate privileges must be flagged and reviewed.', 'least_privilege', 'critical', '[{"field":"can_escalate","operator":"is_true"}]'::jsonb, '[{"type":"flag","message":"Identity can escalate privileges"},{"type":"notify","message":"Review privilege escalation path — apply least privilege"},{"type":"downgrade_permissions","message":"Remove escalation capability"}]'::jsonb, NULL, NULL),
  ('excessive-resource-access', 'Excessive Resource Access', 'Identities with access to more than 25 resources need review.', 'least_privilege', 'high', '[{"field":"resource_count","operator":"gt","value":"25"}]'::jsonb, '[{"type":"flag","message":"Identity has access to too many resources (>25)"},{"type":"notify","message":"Review and reduce resource access scope"}]'::jsonb, NULL, NULL),
  ('cross-account-restriction', 'Cross-Account Access Restriction', 'Cross-account access must be explicitly approved and have cryptographic trust.', 'least_privilege', 'high', '[{"field":"cross_account","operator":"is_true"},{"field":"trust_level","operator":"not_equals","value":"cryptographic"}]'::jsonb, '[{"type":"flag","message":"Cross-account access without cryptographic attestation"},{"type":"require_attest","message":"Cryptographic attestation required for cross-account access"}]'::jsonb, NULL, NULL),
  ('admin-requires-crypto', 'Admin Roles Require Cryptographic Attestation', 'Admin/root IAM roles must have cryptographic (Tier 1) attestation.', 'least_privilege', 'critical', '[{"field":"name","operator":"matches","value":"(admin|root|superuser)"},{"field":"trust_level","operator":"not_equals","value":"cryptographic"}]'::jsonb, '[{"type":"flag","message":"Admin role lacks cryptographic attestation"},{"type":"block_deploy","message":"Admin deployment blocked — deploy SPIRE for Tier 1"}]'::jsonb, NULL, NULL),
  ('business-hours-only', 'Business Hours Access Only', 'Restrict access to production resources to business hours (Mon-Fri 06:00-22:00 UTC).', 'conditional_access', 'high', '[{"field":"server.environment","operator":"equals","value":"production"},{"field":"runtime.time","operator":"outside_time_window","value":"06:00-22:00"}]'::jsonb, '[{"type":"deny","message":"Access denied — outside business hours"},{"type":"flag","message":"Out-of-hours access attempt to production"},{"type":"notify","message":"After-hours production access attempted"}]'::jsonb, NULL, 'deny'),
  ('weekday-only-deploys', 'Weekday-Only Deployments', 'Deployments and credential changes restricted to weekdays only.', 'conditional_access', 'medium', '[{"field":"runtime.day","operator":"not_on_day","value":"mon,tue,wed,thu,fri"}]'::jsonb, '[{"type":"deny","message":"Deployments restricted to weekdays"},{"type":"flag","message":"Weekend deployment attempt detected"}]'::jsonb, NULL, 'deny'),
  ('geo-restricted-access', 'Geo-Restricted Access', 'Production access only from approved regions (us-east-1, eu-west-1).', 'conditional_access', 'critical', '[{"field":"server.environment","operator":"equals","value":"production"},{"field":"runtime.geo","operator":"not_in","value":"us-east-1,us-west-2,eu-west-1"}]'::jsonb, '[{"type":"deny","message":"Access denied — not from approved region"},{"type":"flag","message":"Geo-restricted access violation"},{"type":"notify","message":"Access attempt from unapproved region"}]'::jsonb, NULL, 'deny'),
  ('posture-check-required', 'Runtime Posture Check', 'Client must pass posture check (score > 70) before accessing sensitive resources.', 'conditional_access', 'high', '[{"field":"server.data_classification","operator":"in","value":"confidential,restricted,pii"},{"field":"runtime.posture_score","operator":"lt","value":"70"}]'::jsonb, '[{"type":"deny","message":"Posture check failed — score below threshold"},{"type":"flag","message":"Low posture score access attempt"},{"type":"require_attest","message":"Re-attest to improve posture score"}]'::jsonb, NULL, 'deny'),
  ('rate-limit-enforcement', 'API Rate Limit Enforcement', 'No single client can exceed 5000 requests/hour to any server.', 'conditional_access', 'medium', '[{"field":"runtime.request_rate","operator":"gt","value":"5000"}]'::jsonb, '[{"type":"rate_limit","message":"Rate limit exceeded (>5000 req/hr)"},{"type":"flag","message":"Rate limit violation detected"}]'::jsonb, NULL, 'deny'),
  ('sensitive-requires-approval', 'Sensitive Access Requires Approval', 'Access to restricted/PII resources requires human approval workflow.', 'conditional_access', 'critical', '[{"field":"server.data_classification","operator":"in","value":"restricted,pii"},{"field":"runtime.approval_status","operator":"not_equals","value":"approved"}]'::jsonb, '[{"type":"require_approval","message":"Human approval required for restricted data access"},{"type":"flag","message":"Unapproved access attempt to restricted resource"}]'::jsonb, NULL, 'deny'),
  ('agent-must-have-delegator', 'AI Agent Requires Human Delegator', 'Every AI agent must be bound to a human delegator for accountability.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.delegator","operator":"not_exists"}]'::jsonb, '[{"type":"flag","message":"AI agent has no human delegator"},{"type":"kill_agent","message":"Agent session terminated — no delegator assigned"},{"type":"bind_delegator","message":"Assign human delegator before agent can operate"}]'::jsonb, NULL, NULL),
  ('agent-scope-ceiling', 'Agent Scope Ceiling Enforcement', 'AI agent permissions cannot exceed its delegator''s permissions.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.autonomous","operator":"is_true"},{"field":"agent.scope_ceiling","operator":"not_exists"}]'::jsonb, '[{"type":"flag","message":"Autonomous agent has no scope ceiling defined"},{"type":"restrict_tools","message":"Restricting agent to minimum tool set"},{"type":"require_human_loop","message":"Forcing human-in-loop until scope ceiling set"}]'::jsonb, NULL, NULL),
  ('agent-kill-switch-required', 'Agent Kill Switch Required', 'All AI agents must have kill switch enabled for immediate revocation.', 'ai_agent', 'high', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.kill_switch","operator":"is_false"}]'::jsonb, '[{"type":"flag","message":"AI agent has no kill switch"},{"type":"notify","message":"Enable kill switch for agent compliance"}]'::jsonb, NULL, NULL),
  ('agent-session-ttl', 'Agent Session TTL Limit', 'AI agent sessions cannot exceed 480 minutes (8 hours). Auto-terminate after.', 'ai_agent', 'medium', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.session_ttl","operator":"gt","value":"480"}]'::jsonb, '[{"type":"flag","message":"Agent session TTL exceeds 8-hour limit"},{"type":"kill_agent","message":"Agent session terminated — TTL exceeded"}]'::jsonb, NULL, NULL),
  ('agent-tool-whitelist', 'Agent MCP Tool Whitelist', 'AI agents can only use pre-approved MCP tools. Unapproved tools are blocked.', 'ai_agent', 'high', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.tools_requested","operator":"exists"}]'::jsonb, '[{"type":"restrict_tools","message":"Agent restricted to approved MCP tool whitelist"},{"type":"allow_with_logging","message":"Approved tools allowed with enhanced audit logging"}]'::jsonb, NULL, NULL),
  ('agent-human-loop-sensitive', 'Human-in-Loop for Sensitive Operations', 'AI agents accessing PII or financial data must have human approval for each action.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.human_in_loop","operator":"is_false"},{"field":"agent.autonomous","operator":"is_true"}]'::jsonb, '[{"type":"require_human_loop","message":"Human-in-loop required for autonomous agent"},{"type":"flag","message":"Autonomous agent operating without human oversight"}]'::jsonb, NULL, NULL),
  ('low-score-quarantine', 'Low Security Score Quarantine', 'Identities with security score below 40 are quarantined pending investigation.', 'compliance', 'high', '[{"field":"security_score","operator":"lt","value":"40"}]'::jsonb, '[{"type":"quarantine","message":"Low security score — identity quarantined"},{"type":"notify","message":"Identity scored below threshold, needs investigation"}]'::jsonb, NULL, NULL),
  ('weak-trust-in-prod', 'Minimum Trust Level for Production', 'Production workloads must have at least HIGH trust. LOW or MEDIUM trust triggers escalation.', 'compliance', 'critical', '[{"field":"environment","operator":"equals","value":"production"},{"field":"trust_level","operator":"in","value":"low,none,medium"}]'::jsonb, '[{"type":"flag","message":"Production workload has insufficient trust level"},{"type":"require_attest","message":"Re-attestation required for production access"}]'::jsonb, NULL, NULL),
  ('improper-offboarding-detection', 'Improper Offboarding Detection', 'Service accounts linked to deprovisioned owners must be disabled. #1 OWASP NHI risk.', 'lifecycle', 'critical', '[{"field":"owner_status","operator":"equals","value":"deprovisioned"}]'::jsonb, '[{"type":"disable_identity","message":"Owner deprovisioned — NHI auto-disabled"},{"type":"flag","message":"Orphaned NHI from deprovisioned owner"},{"type":"schedule_decommission","message":"Scheduled for decommission in 14 days"}]'::jsonb, NULL, NULL),
  ('secret-in-logs-detection', 'Secret Leakage in Logs Detection', 'Workloads that log sensitive credentials are flagged. API keys and tokens must never appear in logs.', 'compliance', 'critical', '[{"field":"metadata.secrets_in_logs","operator":"is_true"}]'::jsonb, '[{"type":"flag","message":"Secrets detected in application logs — critical leakage risk"},{"type":"quarantine","message":"Workload quarantined until secret leakage remediated"}]'::jsonb, NULL, NULL),
  ('secret-in-env-plaintext', 'Plaintext Secrets in Environment Variables', 'Secrets as plaintext env vars must be migrated to a secrets manager (Vault, GCP SM, AWS SM).', 'compliance', 'high', '[{"field":"metadata.plaintext_secrets_count","operator":"gt","value":"0"}]'::jsonb, '[{"type":"flag","message":"Plaintext secrets detected in environment variables"},{"type":"notify","message":"Migrate to secrets manager (Vault, GCP SM, AWS SM)"}]'::jsonb, NULL, NULL),
  ('third-party-nhi-review', 'Third-Party NHI Quarterly Review', 'All third-party integrations must be reviewed quarterly. Based on Okta support system breach (2023).', 'compliance', 'high', '[{"field":"category","operator":"in","value":"integration,third-party,saas,oauth-app"},{"field":"last_seen","operator":"older_than_days","value":"90"}]'::jsonb, '[{"type":"flag","message":"Third-party integration not reviewed in 90+ days"},{"type":"require_attest","message":"Quarterly review required for third-party NHI"}]'::jsonb, NULL, NULL),
  ('editor-role-in-prod', 'Editor/Writer Role Prohibited in Production', 'Production NHIs must not hold Editor, Writer, or Admin primitive roles.', 'least_privilege', 'critical', '[{"field":"environment","operator":"equals","value":"production"},{"field":"metadata.roles","operator":"includes_any","value":"roles/editor,roles/owner,roles/admin"}]'::jsonb, '[{"type":"flag","message":"Production NHI holds overprivileged primitive role"},{"type":"downgrade_permissions","message":"Replace with custom least-privilege role"}]'::jsonb, NULL, NULL),
  ('unused-permissions-cleanup', 'Unused Permissions Cleanup', 'Permissions not exercised in 60 days should be revoked.', 'least_privilege', 'medium', '[{"field":"metadata.unused_permission_count","operator":"gt","value":"5"},{"field":"metadata.last_permission_used","operator":"older_than_days","value":"60"}]'::jsonb, '[{"type":"flag","message":"NHI has 5+ unused permissions for 60+ days"},{"type":"notify","message":"Revoke unused permissions to reduce blast radius"}]'::jsonb, NULL, NULL),
  ('cicd-oidc-required', 'CI/CD Must Use OIDC Federation', 'CI/CD pipelines must use OIDC (GitHub OIDC, GitLab CI) instead of static credentials. Based on CircleCI breach.', 'compliance', 'critical', '[{"field":"category","operator":"in","value":"cicd,pipeline,deployment"},{"field":"metadata.auth_method","operator":"not_in","value":"oidc,federated,workload-identity"}]'::jsonb, '[{"type":"flag","message":"CI/CD pipeline uses static credentials instead of OIDC"},{"type":"quarantine","message":"Pipeline quarantined until OIDC migration complete"}]'::jsonb, NULL, NULL),
  ('cicd-no-prod-creds-in-pr', 'No Production Credentials in PR Builds', 'Pull request builds must never have access to production credentials.', 'compliance', 'critical', '[{"field":"category","operator":"in","value":"cicd,pipeline"},{"field":"environment","operator":"not_equals","value":"production"},{"field":"metadata.has_prod_credentials","operator":"is_true"}]'::jsonb, '[{"type":"deny","message":"Production credentials in non-production pipeline build"},{"type":"flag","message":"PR/feature build has production credential access"}]'::jsonb, NULL, NULL),
  ('long-lived-api-key', 'Long-Lived API Key Detection', 'API keys older than 90 days must be replaced with short-lived tokens.', 'lifecycle', 'high', '[{"field":"type","operator":"in","value":"api-key,access-key,pat"},{"field":"created_at","operator":"older_than_days","value":"90"}]'::jsonb, '[{"type":"flag","message":"Long-lived API key detected (>90 days)"},{"type":"force_rotation","message":"Replace with short-lived token or rotate immediately"}]'::jsonb, NULL, NULL),
  ('certificate-expiry-30d', 'Certificate Expiry Warning (30 Days)', 'mTLS and TLS certificates expiring within 30 days must be renewed.', 'lifecycle', 'high', '[{"field":"type","operator":"in","value":"certificate,mtls-cert,tls-cert"},{"field":"expiry_date","operator":"newer_than_days","value":"30"}]'::jsonb, '[{"type":"flag","message":"Certificate expiring within 30 days"},{"type":"notify","message":"Certificate renewal required"}]'::jsonb, NULL, NULL),
  ('user-managed-key-prohibition', 'User-Managed Key Prohibition', 'User-managed SA keys older than 14 days are prohibited. Use workload identity federation.', 'lifecycle', 'critical', '[{"field":"type","operator":"in","value":"service-account-key,api-key,access-key"},{"field":"metadata.key_type","operator":"equals","value":"user-managed"},{"field":"created_at","operator":"older_than_days","value":"14"}]'::jsonb, '[{"type":"flag","message":"User-managed key older than 14 days — high leak risk"},{"type":"disable_identity","message":"Use workload identity federation instead"}]'::jsonb, NULL, NULL),
  ('env-credential-isolation', 'Environment Credential Isolation', 'Same credential must not be used across environments. Enables lateral movement.', 'access', 'critical', '[{"field":"credential.used_in_environments","operator":"exceeds_count","value":"1"}]'::jsonb, '[{"type":"deny","message":"Credential used across multiple environments"},{"type":"flag","message":"Same credential in multiple environments — isolation violation"}]'::jsonb, NULL, 'deny'),
  ('shared-service-account-deny', 'Shared Service Account Prohibition', 'Service accounts shared by 2+ workloads are prohibited. Each workload needs its own identity.', 'access', 'critical', '[{"field":"type","operator":"equals","value":"service-account"},{"field":"metadata.workload_count","operator":"gt","value":"1"}]'::jsonb, '[{"type":"flag","message":"Service account shared across multiple workloads"},{"type":"quarantine","message":"Shared SA quarantined until workloads are separated"}]'::jsonb, NULL, 'deny'),
  ('detect-human-use-of-nhi', 'Detect Human Use of Service Account', 'Service accounts used from interactive sessions are flagged. Based on Midnight Blizzard attack (Microsoft 2024).', 'compliance', 'critical', '[{"field":"type","operator":"in","value":"service-account,iam-role"},{"field":"runtime.session_type","operator":"in","value":"interactive,console,ssh,browser"}]'::jsonb, '[{"type":"deny","message":"Service accounts cannot be used from interactive sessions"},{"type":"flag","message":"Human interactive session using NHI credentials"}]'::jsonb, NULL, NULL),
  ('anomalous-access-pattern', 'Anomalous Access Pattern Detection', 'Flag NHIs accessing new resources during off-hours. Based on Midnight Blizzard lateral movement.', 'conditional_access', 'high', '[{"field":"runtime.is_first_access","operator":"is_true"},{"field":"runtime.time","operator":"outside_time_window","value":"06:00-22:00"}]'::jsonb, '[{"type":"flag","message":"First-time access during off-hours — anomaly detected"},{"type":"require_approval","message":"Manual approval required for anomalous access"}]'::jsonb, NULL, 'deny'),
  ('public-endpoint-requires-auth', 'Public Endpoint Requires Authentication', 'Publicly exposed workloads must enforce authentication. Entry point for lateral movement.', 'access', 'critical', '[{"field":"metadata.ingress","operator":"equals","value":"INGRESS_TRAFFIC_ALL"},{"field":"metadata.auth_required","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"Public endpoint without authentication is prohibited"},{"type":"flag","message":"Unauthenticated public endpoint detected"}]'::jsonb, NULL, 'deny'),
  ('mcp-static-credential-ban', 'MCP Server Static Credential Ban', 'MCP servers must not use static API keys/PATs. 53% use insecure static creds (Astrix 2025). Migrate to OAuth 2.1 or Edge Gateway JIT.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.has_static_creds","operator":"is_true"}]'::jsonb, '[{"type":"flag","message":"MCP server uses static credentials — critical risk"},{"type":"quarantine","message":"MCP server quarantined until credential migration"}]'::jsonb, NULL, NULL),
  ('mcp-oauth-required', 'MCP OAuth 2.1 Required', 'Remote MCP servers must implement OAuth 2.1 per MCP Auth Spec (June 2025).', 'ai_agent', 'high', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.has_oauth","operator":"is_false"},{"field":"metadata.transport","operator":"not_equals","value":"stdio"}]'::jsonb, '[{"type":"deny","message":"Remote MCP servers must implement OAuth 2.1"},{"type":"flag","message":"Remote MCP without OAuth — violates MCP Auth Spec"}]'::jsonb, NULL, NULL),
  ('mcp-token-passthrough-ban', 'MCP Token Passthrough Prohibition', 'MCP servers must not pass client tokens to upstream APIs (confused deputy). Explicitly forbidden in MCP June 2025 spec.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.token_passthrough","operator":"is_true"}]'::jsonb, '[{"type":"deny","message":"Token passthrough prohibited — confused deputy vulnerability"},{"type":"flag","message":"MCP server passing client tokens to upstream APIs"}]'::jsonb, NULL, NULL),
  ('mcp-localhost-binding', 'MCP Server Localhost Binding Required', 'Local MCP servers must bind to localhost only. Network exposure enables RCE (CVE-2025-6514, 558K downloads affected).', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.transport","operator":"equals","value":"stdio"},{"field":"metadata.bound_to_localhost","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"Local MCP server must bind to localhost"},{"type":"flag","message":"MCP server exposed on network interface"}]'::jsonb, NULL, NULL),
  ('mcp-server-registry-verification', 'MCP Server Registry Verification', 'MCP servers must be from verified registries. Based on Smithery.ai path traversal (3000+ servers compromised).', 'ai_agent', 'high', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.registry_verified","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"Only verified MCP servers permitted in production"},{"type":"flag","message":"MCP server from unverified registry"}]'::jsonb, NULL, NULL),
  ('tool-poisoning-prevention', 'MCP Tool Poisoning Prevention', 'MCP tool descriptions must be validated against approved schemas. Prevents tool poisoning where malicious metadata is injected.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"mcp-server,mcp-ai-agent"},{"field":"metadata.tools_validated","operator":"is_false"}]'::jsonb, '[{"type":"restrict_tools","message":"Unvalidated tools blocked until schema review"},{"type":"flag","message":"MCP tools not validated — tool poisoning risk"}]'::jsonb, NULL, NULL),
  ('a2a-authentication-required', 'A2A Agent Authentication Required', 'A2A agents must require authentication before accepting tasks.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"ai-agent,a2a-agent"},{"field":"metadata.a2a_auth_required","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"A2A agent accepts tasks without authentication"},{"type":"flag","message":"Unauthenticated A2A agent detected"}]'::jsonb, NULL, NULL),
  ('a2a-agent-card-signing', 'A2A Agent Card Must Be Signed', 'A2A Agent Cards must be JWS-signed for authenticity. Unsigned cards can be spoofed.', 'ai_agent', 'medium', '[{"field":"type","operator":"in","value":"ai-agent,a2a-agent"},{"field":"metadata.agent_card_signed","operator":"is_false"}]'::jsonb, '[{"type":"flag","message":"A2A Agent Card is not signed (no JWS)"},{"type":"notify","message":"Sign Agent Card with JWS for authenticity"}]'::jsonb, NULL, NULL),
  ('toxic-combo-financial-crm', 'Toxic Combo: Financial + CRM Credential Separation', 'No single agent may hold both financial (Stripe) and CRM (Salesforce) credentials. Compromise = customer data + financial transactions.', 'ai_agent', 'critical', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server,mcp-ai-agent"},{"field":"metadata.credential_categories","operator":"includes_all","value":"financial,crm"}]'::jsonb, '[{"type":"deny","message":"Toxic combination: financial + CRM on same agent"},{"type":"flag","message":"Agent holds both financial and CRM credentials"}]'::jsonb, NULL, NULL),
  ('toxic-combo-code-infra', 'Toxic Combo: Code Repository + Infrastructure Admin', 'No single NHI may hold both code repo and infra admin creds. Based on SolarWinds/CircleCI patterns.', 'ai_agent', 'critical', '[{"field":"metadata.credential_categories","operator":"includes_all","value":"devops,infrastructure"}]'::jsonb, '[{"type":"deny","message":"Toxic combination: code repo + infra admin credentials"},{"type":"flag","message":"Supply chain risk: code + infra on same identity"}]'::jsonb, NULL, NULL),
  ('obo-chain-max-depth', 'OBO Delegation Chain Max Depth', 'On-Behalf-Of chains cannot exceed 3 hops. Deeper chains lose accountability.', 'ai_agent', 'high', '[{"field":"agent.chain_depth","operator":"gt","value":"3"}]'::jsonb, '[{"type":"deny","message":"OBO delegation chain exceeds max depth (3 hops)"},{"type":"kill_agent","message":"Agent terminated — delegation chain too deep"}]'::jsonb, NULL, NULL),
  ('obo-scope-must-narrow', 'OBO Scope Must Narrow at Each Hop', 'Each delegation hop must narrow scope — never widen. Prevents privilege escalation through delegation.', 'ai_agent', 'critical', '[{"field":"agent.scope_wider_than_parent","operator":"is_true"}]'::jsonb, '[{"type":"deny","message":"OBO scope exceeds parent — privilege escalation"},{"type":"kill_agent","message":"Agent terminated — scope escalation in chain"}]'::jsonb, NULL, NULL),
  ('obo-human-root-required', 'OBO Chain Must Originate from Human', 'Every delegation chain must trace back to a human at the root. Agent-only chains are prohibited.', 'ai_agent', 'critical', '[{"field":"agent.root_delegator_type","operator":"not_equals","value":"human"}]'::jsonb, '[{"type":"deny","message":"No human root in delegation chain"},{"type":"kill_agent","message":"Agent terminated — no human in chain"}]'::jsonb, NULL, NULL),
  ('obo-token-ttl-limit', 'OBO Token TTL Shortening per Hop', 'Each OBO token hop must have shorter TTL than parent. Root: 1hr → Hop1: 30min → Hop2: 15min → Hop3: 5min.', 'ai_agent', 'medium', '[{"field":"agent.token_ttl","operator":"gte","value":"60"},{"field":"agent.chain_depth","operator":"gt","value":"0"}]'::jsonb, '[{"type":"flag","message":"OBO token TTL not shortened at delegation hop"}]'::jsonb, NULL, NULL),
  ('jit-credential-required', 'JIT Credential Required for External APIs', 'All external API access must use JIT credentials from the credential broker. Static env var credentials are prohibited.', 'ai_agent', 'critical', '[{"field":"metadata.has_static_creds","operator":"is_true"},{"field":"metadata.uses_credential_broker","operator":"is_false"}]'::jsonb, '[{"type":"deny","message":"External API access without credential broker is prohibited"},{"type":"flag","message":"Static credentials — must use JIT credential broker"}]'::jsonb, NULL, NULL),
  ('jit-token-max-ttl', 'JIT Token Maximum TTL (5 Minutes)', 'JIT tokens from credential broker must not exceed 5 minutes TTL.', 'ai_agent', 'high', '[{"field":"credential.ttl_minutes","operator":"gt","value":"5"}]'::jsonb, '[{"type":"flag","message":"JIT token TTL exceeds 5-minute limit"}]'::jsonb, NULL, NULL),
  ('jit-scope-per-request', 'JIT Credential Scoped Per Request', 'Each JIT credential must be scoped to the specific API operation, not broad access.', 'ai_agent', 'high', '[{"field":"credential.scope","operator":"equals","value":"*"}]'::jsonb, '[{"type":"deny","message":"Wildcard JIT credentials are prohibited"},{"type":"flag","message":"JIT credential has wildcard scope"}]'::jsonb, NULL, NULL),
  ('agent-consent-expiry', 'Agent Consent Expiry (24 Hours)', 'User consent for agent delegation expires after 24 hours. Re-consent required.', 'ai_agent', 'medium', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.consent_age_hours","operator":"gt","value":"24"}]'::jsonb, '[{"type":"flag","message":"Agent consent expired (>24 hours)"},{"type":"require_human_loop","message":"Re-consent required from delegator"}]'::jsonb, NULL, NULL),
  ('agent-multi-tool-approval', 'Multi-Tool Operation Requires Approval', 'Agent operations chaining 3+ MCP tools require human approval before execution.', 'ai_agent', 'high', '[{"field":"type","operator":"in","value":"ai-agent,mcp-server"},{"field":"agent.tool_chain_length","operator":"gt","value":"3"}]'::jsonb, '[{"type":"require_approval","message":"Multi-tool chain (3+) requires human approval"},{"type":"flag","message":"Complex agent tool chain detected"}]'::jsonb, NULL, NULL)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    policy_type = EXCLUDED.policy_type,
    severity = EXCLUDED.severity,
    conditions = EXCLUDED.conditions,
    actions = EXCLUDED.actions,
    scope_environment = EXCLUDED.scope_environment,
    effect = EXCLUDED.effect,
    updated_at = NOW();

-- Add compliance_frameworks column (idempotent)
ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS compliance_frameworks JSONB DEFAULT '[]';
CREATE INDEX IF NOT EXISTS idx_policy_templates_compliance ON policy_templates USING GIN (compliance_frameworks);
COMMENT ON COLUMN policy_templates.compliance_frameworks IS 'Array of {framework, controls[]} objects mapping this template to compliance standards';


-- ═══════════════════════════════════════════════════════════════════════════════
-- 5. SEED FINDING → REMEDIATION MAP (27 entries, 9 finding types)
-- ═══════════════════════════════════════════════════════════════════════════════

INSERT INTO finding_remediation_map (finding_type, template_id, priority, reason)
VALUES
  ('toxic-combo', 'toxic-combo-financial-crm', 1, 'Toxic Combo: Financial + CRM Separation'),
  ('toxic-combo', 'agent-scope-ceiling', 2, 'Agent Scope Ceiling Enforcement'),
  ('toxic-combo', 'agent-tool-whitelist', 3, 'Agent MCP Tool Whitelist'),
  ('toxic-combo', 'jit-credential-required', 4, 'JIT Credential Required for External APIs'),
  ('a2a-no-auth', 'a2a-authentication-required', 1, 'A2A Agent Authentication Required'),
  ('a2a-no-auth', 'agent-must-have-delegator', 2, 'AI Agent Requires Human Delegator'),
  ('a2a-no-auth', 'agent-kill-switch-required', 3, 'Agent Kill Switch Required'),
  ('a2a-unsigned-card', 'a2a-agent-card-signing', 1, 'A2A Agent Card Must Be Signed'),
  ('a2a-unsigned-card', 'weak-trust-in-prod', 2, 'Minimum Trust Level for Production'),
  ('mcp-static-credentials', 'mcp-static-credential-ban', 1, 'MCP Server Static Credential Ban'),
  ('mcp-static-credentials', 'mcp-oauth-required', 2, 'MCP OAuth 2.1 Required'),
  ('mcp-static-credentials', 'jit-credential-required', 3, 'JIT Credential Required'),
  ('static-external-credential', 'jit-credential-required', 1, 'JIT Credential Required for External APIs'),
  ('static-external-credential', 'mcp-static-credential-ban', 2, 'MCP Static Credential Ban'),
  ('static-external-credential', 'long-lived-api-key', 3, 'Long-Lived API Key Detection'),
  ('static-external-credential', 'secret-in-env-plaintext', 4, 'Plaintext Secrets in Env Vars'),
  ('shared-sa', 'shared-service-account-deny', 1, 'Shared Service Account Prohibition'),
  ('shared-sa', 'env-credential-isolation', 2, 'Environment Credential Isolation'),
  ('key-leak', 'user-managed-key-prohibition', 1, 'User-Managed Key Prohibition'),
  ('key-leak', 'credential-rotation-overdue', 2, 'Credential Rotation Overdue'),
  ('key-leak', 'long-lived-api-key', 3, 'Long-Lived API Key Detection'),
  ('over-privileged', 'no-wildcard-permissions', 1, 'No Wildcard Permissions'),
  ('over-privileged', 'privilege-escalation-detection', 2, 'Privilege Escalation Detection'),
  ('over-privileged', 'editor-role-in-prod', 3, 'Editor Role Prohibited in Production'),
  ('over-privileged', 'admin-requires-crypto', 4, 'Admin Requires Cryptographic Attestation'),
  ('public-internal-pivot', 'public-endpoint-requires-auth', 1, 'Public Endpoint Requires Authentication'),
  ('public-internal-pivot', 'cross-env-access-deny', 2, 'Block Cross-Environment Access')
ON CONFLICT (finding_type, template_id) DO UPDATE SET
    priority = EXCLUDED.priority,
    reason = EXCLUDED.reason;


-- ═══════════════════════════════════════════════════════════════════════════════
-- 6. VERIFICATION
-- ═══════════════════════════════════════════════════════════════════════════════

DO $$
DECLARE
    tpl_count INTEGER;
    frm_count INTEGER;
    ft_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO tpl_count FROM policy_templates;
    SELECT COUNT(*) INTO frm_count FROM finding_remediation_map;
    SELECT COUNT(DISTINCT finding_type) INTO ft_count FROM finding_remediation_map;

    RAISE NOTICE '';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  ✅ Policy Templates Migration Complete';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';
    RAISE NOTICE '  Templates:       % seeded', tpl_count;
    RAISE NOTICE '  Remediation map: % entries across % finding types', frm_count, ft_count;
    RAISE NOTICE '  policies.template_version column added';
    RAISE NOTICE '═══════════════════════════════════════════════════════════════';

    IF tpl_count < 69 THEN
        RAISE WARNING '  ⚠ Expected 69 templates, got %', tpl_count;
    END IF;
    IF ft_count < 9 THEN
        RAISE WARNING '  ⚠ Expected 9 finding types, got %', ft_count;
    END IF;
END $$;

COMMIT;
