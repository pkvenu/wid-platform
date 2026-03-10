-- =============================================================================
-- Finding Type Metadata — labels, descriptions, severity for each finding type
-- =============================================================================
-- Enables runtime CRUD of finding types without code changes.
-- Seeded from hardcoded FINDING_TYPE_DEFAULTS at discovery-service startup.

CREATE TABLE IF NOT EXISTS finding_type_metadata (
    finding_type   VARCHAR(100) PRIMARY KEY,
    label          VARCHAR(255) NOT NULL,
    description    TEXT NOT NULL,
    severity       VARCHAR(20) DEFAULT 'high',
    category       VARCHAR(50),
    enabled        BOOLEAN DEFAULT TRUE,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ftm_severity ON finding_type_metadata(severity);
CREATE INDEX IF NOT EXISTS idx_ftm_enabled  ON finding_type_metadata(enabled) WHERE enabled = TRUE;

COMMENT ON TABLE finding_type_metadata IS 'Finding type labels, descriptions, and severity — single source of truth for UI';
