-- =============================================================================
-- Migration 005: Audit Log Encryption at Rest
-- =============================================================================
-- Adds column-level PGP encryption for sensitive audit detail blobs.
-- Query fields (policy_name, severity, created_at, etc.) stay plaintext for indexing.
-- Encryption key is provided at application layer via AUDIT_ENCRYPTION_KEY env var.
-- =============================================================================

-- Enable pgcrypto
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Add encrypted details columns
ALTER TABLE ext_authz_decisions ADD COLUMN IF NOT EXISTS details_encrypted BYTEA;
ALTER TABLE policy_violations ADD COLUMN IF NOT EXISTS details_encrypted BYTEA;

-- Helper functions for encrypt/decrypt
CREATE OR REPLACE FUNCTION encrypt_audit(plaintext TEXT, encryption_key TEXT)
RETURNS BYTEA AS $$
BEGIN
  IF encryption_key IS NULL OR encryption_key = '' THEN
    RETURN NULL;
  END IF;
  RETURN pgp_sym_encrypt(plaintext, encryption_key);
END;
$$ LANGUAGE plpgsql IMMUTABLE;

CREATE OR REPLACE FUNCTION decrypt_audit(ciphertext BYTEA, encryption_key TEXT)
RETURNS TEXT AS $$
BEGIN
  IF ciphertext IS NULL OR encryption_key IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN pgp_sym_decrypt(ciphertext, encryption_key);
EXCEPTION WHEN OTHERS THEN
  RETURN '[encrypted - wrong key]';
END;
$$ LANGUAGE plpgsql IMMUTABLE;
