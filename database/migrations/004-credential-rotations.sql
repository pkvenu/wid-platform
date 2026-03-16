-- =============================================================================
-- Migration 004: Rotation Policies
-- =============================================================================
-- Per-secret rotation policy configuration. Allows configurable rotation
-- intervals, auto-rotation toggles, and expiry warnings per credential path.
-- credential_rotations table already exists in init.sql (table 23).
-- =============================================================================

CREATE TABLE IF NOT EXISTS rotation_policies (
    id                  SERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    credential_path     VARCHAR(500) NOT NULL UNIQUE,
    provider            VARCHAR(50) NOT NULL,
    max_age_days        INTEGER NOT NULL DEFAULT 90,
    auto_rotate         BOOLEAN NOT NULL DEFAULT true,
    notify_before_days  INTEGER NOT NULL DEFAULT 7,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rp_credential ON rotation_policies(credential_path);
CREATE INDEX IF NOT EXISTS idx_rp_tenant     ON rotation_policies(tenant_id);

COMMENT ON TABLE rotation_policies IS 'Per-secret rotation policy: max age, auto-rotate toggle, notification window';

-- Add tenant_id index on credential_rotations if missing
CREATE INDEX IF NOT EXISTS idx_cr_tenant ON credential_rotations(tenant_id);
