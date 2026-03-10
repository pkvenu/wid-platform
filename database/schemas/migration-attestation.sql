-- =============================================================================
-- Migration: Add attestation support
-- =============================================================================
-- docker compose cp migration-attestation.sql postgres:/tmp/migration-attestation.sql
-- docker compose exec postgres psql -U wip_user -d workload_identity -f /tmp/migration-attestation.sql

-- 1. Update trust_level constraint to support 'cryptographic'
DO $$
DECLARE
  constraint_name TEXT;
BEGIN
  SELECT con.conname INTO constraint_name
  FROM pg_constraint con
  WHERE con.conrelid = 'workloads'::regclass
    AND con.contype = 'c'
    AND pg_get_constraintdef(con.oid) ILIKE '%trust_level%';

  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE workloads DROP CONSTRAINT %I', constraint_name);
    RAISE NOTICE 'Dropped trust_level constraint: %', constraint_name;
  END IF;
END $$;

ALTER TABLE workloads ADD CONSTRAINT check_trust_level
  CHECK (trust_level IN ('cryptographic', 'very-high', 'high', 'medium', 'low', 'none'));

-- 2. Add verified_at column if it doesn't exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='workloads' AND column_name='verified_at') THEN
    ALTER TABLE workloads ADD COLUMN verified_at TIMESTAMPTZ DEFAULT NULL;
    RAISE NOTICE 'Added verified_at column';
  END IF;
END $$;

-- 3. Create attestation_history table
CREATE TABLE IF NOT EXISTS attestation_history (
  id SERIAL PRIMARY KEY,
  workload_id INTEGER REFERENCES workloads(id) ON DELETE CASCADE,
  workload_name VARCHAR(255),
  trust_level VARCHAR(20),
  methods_passed INTEGER DEFAULT 0,
  methods_failed INTEGER DEFAULT 0,
  primary_method VARCHAR(50),
  attestation_data JSONB DEFAULT '{}',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attestation_history_workload ON attestation_history(workload_id);
CREATE INDEX IF NOT EXISTS idx_attestation_history_created ON attestation_history(created_at DESC);

-- 4. Verify
DO $$
BEGIN
  RAISE NOTICE '✅ Attestation migration complete';
  RAISE NOTICE '   - trust_level now supports: cryptographic, very-high, high, medium, low, none';
  RAISE NOTICE '   - attestation_history table created';
  RAISE NOTICE '   - verified_at column ensured';
END $$;
