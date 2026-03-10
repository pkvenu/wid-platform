-- =============================================================================
-- ext_authz Decisions — Live audit log from data-plane adapter
-- =============================================================================
-- Run: docker compose exec -T postgres psql -U wid_user -d workload_identity < this_file.sql
-- =============================================================================

CREATE TABLE IF NOT EXISTS ext_authz_decisions (
  id SERIAL PRIMARY KEY,
  decision_id VARCHAR(64) NOT NULL,
  source_principal TEXT,
  destination_principal TEXT,
  source_name VARCHAR(255),
  destination_name VARCHAR(255),
  method VARCHAR(10) DEFAULT 'GET',
  path_pattern TEXT,
  verdict VARCHAR(30) NOT NULL DEFAULT 'no-match',
  policy_name VARCHAR(255),
  policies_evaluated INTEGER DEFAULT 0,
  adapter_mode VARCHAR(20) DEFAULT 'audit',
  latency_ms INTEGER DEFAULT 0,
  cached BOOLEAN DEFAULT false,
  token_jti VARCHAR(128),
  root_jti VARCHAR(128),
  chain_depth INTEGER DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ead_created ON ext_authz_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ead_verdict ON ext_authz_decisions(verdict);
CREATE INDEX IF NOT EXISTS idx_ead_source ON ext_authz_decisions(source_name);
CREATE INDEX IF NOT EXISTS idx_ead_dest ON ext_authz_decisions(destination_name);
CREATE INDEX IF NOT EXISTS idx_ead_decision_id ON ext_authz_decisions(decision_id);

-- Also ensure access_decisions and policies tables exist (from migration-v2)
CREATE TABLE IF NOT EXISTS access_decisions (
  id SERIAL PRIMARY KEY,
  client_workload_id UUID,
  server_workload_id UUID,
  client_name VARCHAR(255),
  server_name VARCHAR(255),
  decision VARCHAR(20) NOT NULL CHECK (decision IN ('allow', 'deny')),
  policies_evaluated INTEGER DEFAULT 0,
  policy_results JSONB DEFAULT '[]',
  runtime_context JSONB DEFAULT '{}',
  enforcement_mode VARCHAR(20) DEFAULT 'audit',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies table extensions (idempotent)
ALTER TABLE policies ADD COLUMN IF NOT EXISTS effect VARCHAR(20) DEFAULT NULL;
ALTER TABLE policies ADD COLUMN IF NOT EXISTS priority INTEGER DEFAULT 100;
