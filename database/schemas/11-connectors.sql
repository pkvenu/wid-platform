-- =============================================================================
-- 11-connectors.sql — Cloud account connectors for customer onboarding
-- =============================================================================
-- Connectors represent a customer's cloud account connection to WID.
-- Discovery-only connectors scan remotely using stored credentials.
-- Enforcement connectors also have a gateway installed in the customer's env.
-- =============================================================================

-- ── Connectors table ──
CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Display
    name TEXT NOT NULL,                     -- "Production AWS", "Dev GCP"
    description TEXT DEFAULT '',

    -- Provider
    provider TEXT NOT NULL                  -- aws, gcp, azure, kubernetes, docker, vault
        CHECK (provider IN ('aws', 'gcp', 'azure', 'kubernetes', 'docker', 'vault')),

    -- Lifecycle
    status TEXT DEFAULT 'pending'           -- pending, validating, active, error, disabled
        CHECK (status IN ('pending', 'validating', 'active', 'error', 'disabled')),
    mode TEXT DEFAULT 'discovery'           -- discovery = scan only, enforcement = scan + gateway
        CHECK (mode IN ('discovery', 'enforcement')),

    -- Non-secret configuration (region, project_id, subscription_id, etc.)
    config JSONB DEFAULT '{}',

    -- Credential reference — stored in GCP Secret Manager, NEVER in DB
    credential_ref TEXT,                    -- secret name: connector-{id}-creds

    -- Scan state
    last_scan_at TIMESTAMPTZ,
    last_scan_status TEXT,                  -- running, completed, failed
    last_scan_duration_ms INTEGER,
    workload_count INTEGER DEFAULT 0,

    -- Error tracking
    error_message TEXT,
    error_at TIMESTAMPTZ,
    consecutive_errors INTEGER DEFAULT 0,

    -- Enforcement (gateway registration)
    gateway_env_name TEXT,                  -- environment name for the spoke relay
    gateway_connected BOOLEAN DEFAULT FALSE,
    gateway_last_heartbeat TIMESTAMPTZ,

    -- Ownership
    created_by TEXT DEFAULT 'system',

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connectors_provider ON connectors(provider);
CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
CREATE INDEX IF NOT EXISTS idx_connectors_mode ON connectors(mode);

COMMENT ON TABLE connectors IS 'Customer cloud account connectors — each represents one cloud account connection';
COMMENT ON COLUMN connectors.credential_ref IS 'GCP Secret Manager secret name — credentials never stored in DB';
COMMENT ON COLUMN connectors.config IS 'Non-secret config: region, project_id, subscription_id, org_id, etc.';

-- ── Link workloads to their source connector ──
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS connector_id UUID REFERENCES connectors(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_workloads_connector ON workloads(connector_id);

-- ── Auto-update updated_at ──
CREATE OR REPLACE FUNCTION update_connector_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_connector_updated_at ON connectors;
CREATE TRIGGER trigger_connector_updated_at
    BEFORE UPDATE ON connectors
    FOR EACH ROW
    EXECUTE FUNCTION update_connector_updated_at();
