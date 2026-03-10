-- Migration: Provider Registry + Cloud Log Enrichments + Credential Rotations + Remediation Executions
-- Date: 2026-03-03
-- Description: DB-driven provider/domain registry, cloud log enrichment storage,
--              credential rotation tracking, remediation execution tracking,
--              and IETF AIMS delegation_type on workloads.

-- ═══════════════════════════════════════════════════════════════════════════════
-- Provider Registry
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS provider_registry (
    id              VARCHAR(100) PRIMARY KEY,
    registry_type   VARCHAR(50) NOT NULL,
    label           VARCHAR(255) NOT NULL,
    category        VARCHAR(100) NOT NULL,
    credential_keys TEXT[] DEFAULT '{}',
    ai_config       JSONB DEFAULT NULL,
    domain_patterns TEXT[] DEFAULT '{}',
    domain_type     VARCHAR(50),
    image_patterns  TEXT[] DEFAULT '{}',
    signal_patterns TEXT[] DEFAULT '{}',
    enabled         BOOLEAN DEFAULT TRUE,
    sort_order      INTEGER DEFAULT 100,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pr_type     ON provider_registry(registry_type);
CREATE INDEX IF NOT EXISTS idx_pr_category ON provider_registry(category);
CREATE INDEX IF NOT EXISTS idx_pr_enabled  ON provider_registry(enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_pr_keys     ON provider_registry USING GIN(credential_keys);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Cloud Log Enrichments
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS cloud_log_enrichments (
    id               SERIAL PRIMARY KEY,
    workload_id      UUID REFERENCES workloads(id) ON DELETE CASCADE,
    workload_name    VARCHAR(255),
    cloud_provider   VARCHAR(50) NOT NULL,
    log_source       VARCHAR(100) NOT NULL,
    api_called       VARCHAR(500),
    destination_host VARCHAR(255),
    method           VARCHAR(10),
    caller_identity  VARCHAR(500),
    provider_match   VARCHAR(100),
    call_count       INTEGER DEFAULT 1,
    first_seen       TIMESTAMPTZ,
    last_seen        TIMESTAMPTZ,
    raw_metadata     JSONB DEFAULT '{}',
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cle_workload ON cloud_log_enrichments(workload_id);
CREATE INDEX IF NOT EXISTS idx_cle_provider ON cloud_log_enrichments(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_cle_source   ON cloud_log_enrichments(log_source);
CREATE INDEX IF NOT EXISTS idx_cle_dest     ON cloud_log_enrichments(destination_host);
CREATE INDEX IF NOT EXISTS idx_cle_created  ON cloud_log_enrichments(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Credential Rotations
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS credential_rotations (
    id               SERIAL PRIMARY KEY,
    credential_path  VARCHAR(500) NOT NULL,
    provider         VARCHAR(50) NOT NULL,
    workload_id      UUID,
    status           VARCHAR(20) DEFAULT 'pending',
    triggered_by     VARCHAR(50),
    old_version      VARCHAR(100),
    new_version      VARCHAR(100),
    error_message    TEXT,
    scheduled_at     TIMESTAMPTZ,
    executed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cr_workload ON credential_rotations(workload_id);
CREATE INDEX IF NOT EXISTS idx_cr_status   ON credential_rotations(status);
CREATE INDEX IF NOT EXISTS idx_cr_created  ON credential_rotations(created_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Remediation Executions
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS remediation_executions (
    id                SERIAL PRIMARY KEY,
    control_id        VARCHAR(100) NOT NULL,
    node_id           VARCHAR(255) NOT NULL,
    channel           VARCHAR(20) NOT NULL,
    status            VARCHAR(20) DEFAULT 'pending',
    requested_by      VARCHAR(255),
    approved_by       VARCHAR(255),
    commands          JSONB,
    output            TEXT,
    error_message     TEXT,
    rollback_commands JSONB,
    requested_at      TIMESTAMPTZ DEFAULT NOW(),
    approved_at       TIMESTAMPTZ,
    executed_at       TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_re_node    ON remediation_executions(node_id);
CREATE INDEX IF NOT EXISTS idx_re_status  ON remediation_executions(status);
CREATE INDEX IF NOT EXISTS idx_re_created ON remediation_executions(requested_at DESC);

-- ═══════════════════════════════════════════════════════════════════════════════
-- Workloads: IETF AIMS delegation_type
-- ═══════════════════════════════════════════════════════════════════════════════

ALTER TABLE workloads ADD COLUMN IF NOT EXISTS delegation_type VARCHAR(50) DEFAULT NULL;
