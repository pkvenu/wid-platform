-- =============================================================================
-- 07 — Enterprise Shadow IT Classification Columns
-- =============================================================================
-- Adds Rogue IT, Orphan, Public Exposure, Unused IAM, and Composite
-- Classification columns to the workloads table.
-- Safe to run multiple times (IF NOT EXISTS / ADD COLUMN IF NOT EXISTS).
-- =============================================================================

-- Rogue IT Detection
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_rogue BOOLEAN DEFAULT FALSE;
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS rogue_score NUMERIC(5,2) DEFAULT 0;
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS rogue_reasons JSONB DEFAULT '[]'::jsonb;

-- Orphan Detection
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_orphan BOOLEAN DEFAULT FALSE;
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS orphan_reasons JSONB DEFAULT '[]'::jsonb;

-- Public Exposure
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_publicly_exposed BOOLEAN DEFAULT FALSE;
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS exposure_reasons JSONB DEFAULT '[]'::jsonb;

-- Unused IAM
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS is_unused_iam BOOLEAN DEFAULT FALSE;

-- Composite Classification
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS classification VARCHAR(50) DEFAULT 'pending';
ALTER TABLE workloads ADD COLUMN IF NOT EXISTS classification_tags JSONB DEFAULT '[]'::jsonb;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_workloads_classification ON workloads(classification);
CREATE INDEX IF NOT EXISTS idx_workloads_is_rogue ON workloads(is_rogue) WHERE is_rogue = TRUE;
CREATE INDEX IF NOT EXISTS idx_workloads_is_orphan ON workloads(is_orphan) WHERE is_orphan = TRUE;
CREATE INDEX IF NOT EXISTS idx_workloads_is_publicly_exposed ON workloads(is_publicly_exposed) WHERE is_publicly_exposed = TRUE;
