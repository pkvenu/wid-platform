-- =============================================================================
-- 09: Remediation Intents + Templates — DB-backed remediation catalog
-- =============================================================================
-- Replaces the static CONTROL_CATALOG with a queryable, extensible DB model.
-- remediation_intents: what to do (finding → control mapping with scoring metadata)
-- remediation_templates: how to do it (provider-specific CLI/Terraform/OPA templates)
-- =============================================================================

CREATE TABLE IF NOT EXISTS remediation_intents (
    id               VARCHAR(100) PRIMARY KEY,
    control_id       VARCHAR(100) NOT NULL,
    name             VARCHAR(255) NOT NULL,
    description      TEXT NOT NULL,
    goal             TEXT,
    action_type      VARCHAR(50) NOT NULL,
    remediation_type VARCHAR(50) NOT NULL,
    finding_types    TEXT[] DEFAULT '{}',
    scope            VARCHAR(50) DEFAULT 'resource',
    resource_types   TEXT[] DEFAULT '{}',
    path_break       JSONB NOT NULL DEFAULT '{}',
    feasibility      JSONB NOT NULL DEFAULT '{}',
    operational      JSONB NOT NULL DEFAULT '{}',
    risk_reduction   JSONB DEFAULT '{}',
    rollback_strategy TEXT,
    preconditions    JSONB DEFAULT '[]',
    validation       JSONB DEFAULT '[]',
    template_id      VARCHAR(100),
    enabled          BOOLEAN DEFAULT TRUE,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    updated_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ri_finding     ON remediation_intents USING GIN(finding_types);
CREATE INDEX IF NOT EXISTS idx_ri_control     ON remediation_intents(control_id);
CREATE INDEX IF NOT EXISTS idx_ri_action_type ON remediation_intents(action_type);
CREATE INDEX IF NOT EXISTS idx_ri_template    ON remediation_intents(template_id);

COMMENT ON TABLE remediation_intents IS 'DB-backed remediation controls — seeded from CONTROL_CATALOG, extensible';

CREATE TABLE IF NOT EXISTS remediation_templates (
    id                SERIAL PRIMARY KEY,
    intent_id         VARCHAR(100) NOT NULL REFERENCES remediation_intents(id) ON DELETE CASCADE,
    provider          VARCHAR(50) NOT NULL,
    resource_type     VARCHAR(100),
    channel           VARCHAR(50) NOT NULL,
    title             VARCHAR(255),
    template_body     TEXT NOT NULL,
    variables         JSONB DEFAULT '[]',
    validate_template TEXT,
    rollback_template TEXT,
    priority          INTEGER DEFAULT 100,
    enabled           BOOLEAN DEFAULT TRUE,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rt_intent ON remediation_templates(intent_id);
CREATE INDEX IF NOT EXISTS idx_rt_provider ON remediation_templates(provider);
CREATE INDEX IF NOT EXISTS idx_rt_channel ON remediation_templates(channel);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rt_unique
  ON remediation_templates(intent_id, provider, COALESCE(resource_type,''), channel);

COMMENT ON TABLE remediation_templates IS 'Provider-specific remediation templates (CLI, Terraform, OPA) per intent';
