-- =============================================================================
-- Migration 003: Spoke Relays + Federation Events
-- =============================================================================
-- Persists relay registry (replaces in-memory Map) and tracks federation events.
-- Part of ADR-13: mTLS Federation with SPIFFE SVIDs.
--
-- Usage:
--   psql -U wid_user -d workload_identity -f database/migrations/003-spoke-relays.sql
-- =============================================================================

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- spoke_relays — DB-backed relay registry with mTLS identity
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS spoke_relays (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    relay_id            VARCHAR(100) UNIQUE NOT NULL,
    environment_name    VARCHAR(255) NOT NULL,
    environment_type    VARCHAR(50) NOT NULL,
    region              VARCHAR(50) NOT NULL,
    cluster_id          VARCHAR(255),

    -- mTLS identity (populated when relay connects with client certificate)
    spiffe_id           TEXT UNIQUE,
    cert_fingerprint    VARCHAR(128),       -- SHA-256 of DER-encoded cert
    cert_issuer         TEXT,               -- CN/OU of issuing CA
    cert_not_before     TIMESTAMPTZ,
    cert_not_after      TIMESTAMPTZ,
    cert_serial         VARCHAR(128),

    -- Registration state
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, active, revoked, stale
    registered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_heartbeat_at   TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT,

    -- Webhook push config
    webhook_url         TEXT,               -- URL for push-based policy updates
    webhook_enabled     BOOLEAN DEFAULT TRUE,

    -- Metadata
    relay_version       VARCHAR(50),
    capabilities        TEXT[] DEFAULT '{}',
    data_region         TEXT NOT NULL DEFAULT 'us',
    data_residency_strict BOOLEAN DEFAULT FALSE,
    allowed_regions     TEXT[] DEFAULT '{us}',

    -- Health snapshot (updated on heartbeat)
    policy_version      INTEGER DEFAULT 0,
    policy_count        INTEGER DEFAULT 0,
    audit_buffer_size   INTEGER DEFAULT 0,
    adapter_count       INTEGER DEFAULT 0,
    uptime_seconds      INTEGER DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_spoke_relays_tenant ON spoke_relays(tenant_id);
CREATE INDEX IF NOT EXISTS idx_spoke_relays_status ON spoke_relays(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_spoke_relays_spiffe ON spoke_relays(spiffe_id) WHERE spiffe_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_spoke_relays_cert   ON spoke_relays(cert_fingerprint) WHERE cert_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_spoke_relays_region ON spoke_relays(data_region);

-- RLS policy for multi-tenant isolation
ALTER TABLE spoke_relays ENABLE ROW LEVEL SECURITY;
CREATE POLICY spoke_relays_tenant_policy ON spoke_relays
    USING (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));


-- ═══════════════════════════════════════════════════════════════════════════════
-- federation_events — Audit trail for all federation actions
-- ═══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS federation_events (
    id              SERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001',
    relay_id        VARCHAR(100) NOT NULL,
    event_type      VARCHAR(50) NOT NULL,   -- registered, heartbeat, cert_rotated, revoked, policy_pushed, auth_failed, stale_detected
    spiffe_id       TEXT,
    cert_fingerprint VARCHAR(128),
    details         JSONB DEFAULT '{}',
    source_ip       INET,
    data_region     TEXT NOT NULL DEFAULT 'us',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fed_events_relay ON federation_events(relay_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fed_events_type  ON federation_events(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fed_events_tenant ON federation_events(tenant_id);

-- RLS policy
ALTER TABLE federation_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY federation_events_tenant_policy ON federation_events
    USING (tenant_id::text = current_setting('app.current_tenant', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant', true));


-- ═══════════════════════════════════════════════════════════════════════════════
-- Alterations to existing tables — add relay identity fields
-- ═══════════════════════════════════════════════════════════════════════════════

ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS relay_spiffe_id TEXT;
ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS origin_relay_spiffe_id TEXT;
ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS origin_environment VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_authz_relay_spiffe ON ext_authz_decisions(relay_spiffe_id);


COMMIT;
