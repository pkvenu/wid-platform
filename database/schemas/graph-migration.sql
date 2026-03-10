-- =============================================================================
-- Identity Graph & Timeline Tables
-- =============================================================================
-- Run this migration on your wid-platform database:
--   psql $DATABASE_URL -f graph-migration.sql
-- =============================================================================

-- Identity graph cache (stores the latest computed graph)
CREATE TABLE IF NOT EXISTS identity_graph (
  id              VARCHAR(50) PRIMARY KEY DEFAULT 'latest',
  graph_data      JSONB NOT NULL DEFAULT '{}',
  generated_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  scan_duration_ms INTEGER,
  node_count      INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_nodes')::int) STORED,
  rel_count       INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_relationships')::int) STORED,
  path_count      INTEGER GENERATED ALWAYS AS ((graph_data->'summary'->>'total_attack_paths')::int) STORED
);

-- Authorization events (audit log for identity access decisions)
CREATE TABLE IF NOT EXISTS authorization_events (
  id              SERIAL PRIMARY KEY,
  timestamp       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  workload_id     INTEGER REFERENCES workloads(id) ON DELETE SET NULL,
  workload_name   VARCHAR(255),
  source_identity VARCHAR(500),    -- e.g. spiffe://company.com/gcp/cloud-run-service/relay-service
  target_resource VARCHAR(500),    -- e.g. Cloud SQL, /api/v1/credentials
  action          VARCHAR(100),    -- e.g. read, write, invoke, assume-role
  decision        VARCHAR(20),     -- allow, deny
  policy_name     VARCHAR(255),    -- OPA policy that made the decision
  policy_violated BOOLEAN DEFAULT FALSE,
  reason          TEXT,
  metadata        JSONB DEFAULT '{}',
  trust_level     VARCHAR(50),     -- trust level at time of decision
  attestation_valid BOOLEAN,       -- was attestation current at time of access?
  created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_events_workload ON authorization_events(workload_id);
CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON authorization_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_auth_events_decision ON authorization_events(decision);
CREATE INDEX IF NOT EXISTS idx_auth_events_violation ON authorization_events(policy_violated) WHERE policy_violated = TRUE;

-- Policy evaluations (when OPA policies are evaluated against workloads)
CREATE TABLE IF NOT EXISTS policy_evaluations (
  id              SERIAL PRIMARY KEY,
  evaluated_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  workload_id     INTEGER REFERENCES workloads(id) ON DELETE SET NULL,
  workload_name   VARCHAR(255),
  policy_name     VARCHAR(255),
  policy_id       INTEGER,
  result          VARCHAR(20),     -- pass, fail, warn, skip
  violations      JSONB DEFAULT '[]',
  context         JSONB DEFAULT '{}',
  created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pol_eval_workload ON policy_evaluations(workload_id);
CREATE INDEX IF NOT EXISTS idx_pol_eval_timestamp ON policy_evaluations(evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_pol_eval_result ON policy_evaluations(result);

-- Graph history (optional — track graph changes over time)
CREATE TABLE IF NOT EXISTS identity_graph_history (
  id              SERIAL PRIMARY KEY,
  snapshot_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  node_count      INTEGER,
  rel_count       INTEGER,
  path_count      INTEGER,
  critical_paths  INTEGER,
  summary         JSONB DEFAULT '{}'
);

-- ─── Seed some sample authorization events for the timeline demo ───
-- These represent realistic events from your WID platform workloads.

INSERT INTO authorization_events (timestamp, workload_name, source_identity, target_resource, action, decision, policy_name, policy_violated, reason, trust_level, attestation_valid)
VALUES
  -- Normal operations
  (NOW() - INTERVAL '2 hours', 'token-service',
   'spiffe://company.com/gcp/cloud-run-service/token-service',
   'Cloud SQL (wid-db)', 'read', 'allow',
   'nhi-database-access', FALSE, 'Attested workload with valid trust level', 'cryptographic', TRUE),

  (NOW() - INTERVAL '1 hour 45 min', 'credential-broker',
   'spiffe://company.com/gcp/cloud-run-service/credential-broker',
   'Secret Manager', 'read', 'allow',
   'nhi-secrets-access', FALSE, 'Authorized: credential-broker has secretAccessor role', 'cryptographic', TRUE),

  (NOW() - INTERVAL '1 hour 30 min', 'discovery-service',
   'spiffe://company.com/gcp/cloud-run-service/discovery-service',
   'Cloud Run Admin API', 'list', 'allow',
   'nhi-discovery-permissions', FALSE, 'Scanner SA authorized for read-only discovery', 'high', TRUE),

  -- Policy violation — relay-service accessed DB (shouldn't)
  (NOW() - INTERVAL '1 hour', 'relay-service',
   'spiffe://company.com/gcp/cloud-run-service/relay-service',
   'Cloud SQL (wid-db)', 'write', 'deny',
   'nhi-database-access', TRUE,
   'VIOLATION: relay-service is not authorized to write to Cloud SQL. Shared SA (wid-dev-run) grants implicit access — create dedicated SA.',
   'cryptographic', TRUE),

  -- Attestation-related
  (NOW() - INTERVAL '45 min', 'web-ui',
   'spiffe://company.com/gcp/cloud-run-service/web-ui',
   '/api/v1/workloads', 'read', 'allow',
   'nhi-api-access', FALSE, 'Frontend service reading workload list', 'cryptographic', TRUE),

  -- Suspicious: access with expired attestation
  (NOW() - INTERVAL '30 min', 'terraform',
   'spiffe://company.com/gcp/service-account/terraform',
   'Cloud SQL (wid-db)', 'admin', 'allow',
   'nhi-database-access', TRUE,
   'WARNING: terraform SA accessed Cloud SQL with user-managed key. Attestation expired 2 hours ago.',
   'high', FALSE),

  -- Normal
  (NOW() - INTERVAL '15 min', 'policy-engine',
   'spiffe://company.com/gcp/cloud-run-service/policy-engine',
   'OPA Evaluation', 'evaluate', 'allow',
   'nhi-policy-engine', FALSE, 'Policy engine evaluating workload compliance', 'cryptographic', TRUE),

  -- Shared SA concern
  (NOW() - INTERVAL '5 min', 'relay-service',
   'spiffe://company.com/gcp/cloud-run-service/relay-service',
   'credential-broker (internal)', 'invoke', 'allow',
   'nhi-service-mesh', FALSE,
   'NOTE: relay-service can invoke credential-broker because they share wid-dev-run SA. Recommend dedicated SAs.',
   'cryptographic', TRUE)

ON CONFLICT DO NOTHING;

-- Seed policy evaluations
INSERT INTO policy_evaluations (evaluated_at, workload_name, policy_name, result, violations)
VALUES
  (NOW() - INTERVAL '2 hours', 'token-service', 'require-attestation', 'pass', '[]'),
  (NOW() - INTERVAL '2 hours', 'relay-service', 'nhi-database-access', 'fail',
   '[{"rule": "only credential-broker may access Cloud SQL", "actual": "relay-service attempted write via shared SA"}]'),
  (NOW() - INTERVAL '1 hour', 'terraform', 'require-dedicated-sa', 'fail',
   '[{"rule": "infrastructure SAs must not have user-managed keys older than 90 days", "actual": "key age: 1 day (ok) but user-managed key exists"}]'),
  (NOW() - INTERVAL '30 min', 'credential-broker', 'nhi-secrets-access', 'pass', '[]'),
  (NOW() - INTERVAL '15 min', 'discovery-service', 'require-attestation', 'pass', '[]')
ON CONFLICT DO NOTHING;

-- Done!
SELECT 'Identity graph tables created successfully' AS status;
