-- =============================================================================
-- Migration: Expand issuer + cloud_provider validation for all NHI scanner types
-- =============================================================================
-- Run against your workload_identity database:
--
--   docker compose exec postgres psql -U wip_user -d workload_identity -f migration.sql
--
-- Changes:
--   1. Expands validate_trust_domain() issuer regex to support:
--      vault://, github://, jenkins://, gitlab://, oidc://, https://, spiffe://, internal://
--   2. If cloud_provider has a CHECK constraint, expands it to include:
--      vault, github, jenkins, gitlab, internal
-- =============================================================================

-- Step 1: Expand issuer validation
CREATE OR REPLACE FUNCTION validate_trust_domain(p_trust_domain VARCHAR, p_issuer VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
  -- Validate trust domain format (must be domain-like)
  IF p_trust_domain IS NULL OR p_trust_domain = '' THEN
    RETURN FALSE;
  END IF;

  IF p_trust_domain !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$' THEN
    RETURN FALSE;
  END IF;

  -- Validate issuer format (all supported schemes)
  IF p_issuer IS NOT NULL AND p_issuer != '' THEN
    IF p_issuer !~ '^(k8s|docker|aws|gcp|azure|vault|github|jenkins|gitlab|oidc|https|spiffe|internal)://.+$' THEN
      RETURN FALSE;
    END IF;
  END IF;

  RETURN TRUE;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Step 2: Drop and recreate cloud_provider constraint if it exists
DO $$
DECLARE
  constraint_name TEXT;
BEGIN
  -- Find any CHECK constraint on cloud_provider
  SELECT con.conname INTO constraint_name
  FROM pg_constraint con
  JOIN pg_attribute att ON att.attrelid = con.conrelid
  WHERE con.conrelid = 'workloads'::regclass
    AND con.contype = 'c'
    AND pg_get_constraintdef(con.oid) ILIKE '%cloud_provider%';
  
  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE workloads DROP CONSTRAINT %I', constraint_name);
    RAISE NOTICE 'Dropped constraint: %', constraint_name;
    
    -- Recreate with expanded values
    ALTER TABLE workloads ADD CONSTRAINT check_cloud_provider 
      CHECK (cloud_provider IN (
        'aws', 'gcp', 'azure', 'docker', 'kubernetes',
        'vault', 'github', 'jenkins', 'gitlab', 'internal',
        'oracle', 'vmware', 'openstack', 'unknown'
      ));
    RAISE NOTICE 'Created expanded cloud_provider constraint';
  ELSE
    RAISE NOTICE 'No cloud_provider CHECK constraint found — skipping';
  END IF;
END $$;

-- Step 3: Verify
DO $$
BEGIN
  -- Issuer tests
  ASSERT validate_trust_domain('company.com', 'aws://us-east-1'),        'aws:// should pass';
  ASSERT validate_trust_domain('company.com', 'docker://hostname'),       'docker:// should pass';
  ASSERT validate_trust_domain('company.com', 'k8s://cluster'),           'k8s:// should pass';
  ASSERT validate_trust_domain('company.com', 'vault://vault-local'),     'vault:// should pass';
  ASSERT validate_trust_domain('company.com', 'github://my-org'),         'github:// should pass';
  ASSERT validate_trust_domain('company.com', 'jenkins://jenkins-local'), 'jenkins:// should pass';
  ASSERT validate_trust_domain('company.com', 'https://token.actions.githubusercontent.com'), 'https:// should pass';
  ASSERT validate_trust_domain('company.com', 'spiffe://company.com'),    'spiffe:// should pass';
  ASSERT validate_trust_domain('company.com', 'internal://token-service'),'internal:// should pass';
  ASSERT validate_trust_domain('company.com', 'oidc://keycloak'),         'oidc:// should pass';
  
  -- Negative tests
  ASSERT NOT validate_trust_domain('', 'aws://test'),         'empty domain should fail';
  ASSERT NOT validate_trust_domain('company.com', 'ftp://x'), 'ftp:// should fail';
  ASSERT NOT validate_trust_domain('UPPER.COM', 'aws://x'),   'uppercase domain should fail';
  
  RAISE NOTICE '✅ All validation tests passed!';
END $$;
