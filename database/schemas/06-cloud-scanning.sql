-- =============================================================================
-- Migration 06: Cloud Scanning Indexes
-- =============================================================================
-- Supports the expanded scanner coverage (S3, RDS, DynamoDB, VPC, SG, KMS,
-- Secrets Manager, Cloud SQL, GCS, Firewall Rules, Azure Storage/SQL/NSG/KeyVault,
-- Entra ID). No new tables needed — all resource types are rows in the existing
-- workloads table with different type values and JSONB metadata.
--
-- These indexes accelerate:
--   1. Filtering workloads by type within a cloud provider (graph construction)
--   2. Filtering workloads by account + type (per-account inventory queries)
--   3. Graph queries that join on workload type for relationship building
-- =============================================================================

-- Index: workloads by type + cloud_provider (most common graph query pattern)
CREATE INDEX IF NOT EXISTS idx_workloads_type_provider
  ON workloads(type, cloud_provider);

-- Index: workloads by account_id + type (per-account inventory)
CREATE INDEX IF NOT EXISTS idx_workloads_account_type
  ON workloads(account_id, type);

-- Index: workloads by discovered_by (scanner-specific queries)
CREATE INDEX IF NOT EXISTS idx_workloads_discovered_by
  ON workloads(discovered_by)
  WHERE discovered_by IS NOT NULL;
