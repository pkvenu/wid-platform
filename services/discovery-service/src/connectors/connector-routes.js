// =============================================================================
// Connector Routes — CRUD + Test + Scan for cloud account connectors
// =============================================================================
// Mounts on /api/v1/connectors
// Each connector represents one customer cloud account connection.
// Credentials are stored in Secret Manager (or local encrypted), never in DB.
// =============================================================================

const { storeCredentials, getCredentials, deleteCredentials } = require('./credential-store');
const { clearGraphCache } = require('../graph/graph-routes');

// ── Input validation helpers ──────────────────────────────────────────────
const MAX_NAME_LENGTH = 100;
const MAX_DESCRIPTION_LENGTH = 500;
const VALID_MODES = ['discovery', 'enforcement'];
const NAME_PATTERN = /^[\w\s\-().,:]+$/; // alphanumeric, spaces, hyphens, parens, dots, commas, colons

function sanitizeErrorMessage(msg) {
  if (!msg || typeof msg !== 'string') return 'Unknown error';
  // Strip potential credential values from error messages
  return msg
    .replace(/(?:key|token|secret|password|credential)[=:\s]+\S+/gi, '[REDACTED]')
    .replace(/hvs\.\S+/g, '[REDACTED]')
    .replace(/AKIA[A-Z0-9]{16}/g, '[REDACTED]')
    .replace(/-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----/g, '[REDACTED]')
    .slice(0, 500);
}

function validateConnectorInput(name, description, mode) {
  const errors = [];
  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    errors.push('name is required');
  } else {
    if (name.length > MAX_NAME_LENGTH) {
      errors.push(`name must be ${MAX_NAME_LENGTH} characters or fewer`);
    }
    if (!NAME_PATTERN.test(name)) {
      errors.push('name contains invalid characters');
    }
  }
  if (description && description.length > MAX_DESCRIPTION_LENGTH) {
    errors.push(`description must be ${MAX_DESCRIPTION_LENGTH} characters or fewer`);
  }
  if (mode && !VALID_MODES.includes(mode)) {
    errors.push(`mode must be one of: ${VALID_MODES.join(', ')}`);
  }
  return errors;
}

// ── Simple in-memory rate limiter ──────────────────────────────────────────
const rateLimitBuckets = new Map();
function rateLimit(key, maxPerWindow, windowMs = 60000) {
  const now = Date.now();
  let bucket = rateLimitBuckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
    rateLimitBuckets.set(key, bucket);
  }
  bucket.count++;
  return bucket.count > maxPerWindow;
}

// Provider-specific credential field definitions
const PROVIDER_FIELDS = {
  aws: {
    required: ['roleArn', 'externalId'],
    optional: ['region', 'accountId'],
    configFields: ['region', 'accountId'],
  },
  gcp: {
    required: ['projectId'],
    optional: [],
    configFields: ['projectId', 'orgId'],
  },
  azure: {
    required: ['tenantId', 'subscriptionId'],
    optional: [],
    configFields: ['subscriptionId', 'tenantId'],
  },
  kubernetes: {
    required: ['kubeconfig'],
    optional: ['context', 'clusterName'],
    configFields: ['clusterName', 'context'],
  },
  docker: {
    required: [],
    optional: ['socketPath', 'host'],
    configFields: ['host'],
  },
  vault: {
    required: ['vaultAddr', 'vaultToken'],
    optional: [],
    configFields: ['vaultAddr'],
  },
};

/**
 * Mount connector routes on the Express app.
 * @param {import('express').Application} app
 * @param {import('pg').Client} dbClient
 * @param {object} deps - { scannerRegistry, ScannerConfig, runConnectorScan }
 */
function mountConnectorRoutes(app, dbClient, deps = {}) {
  const { runConnectorScan } = deps;

  // ─── Ensure connectors table exists (idempotent migration) ──────────
  (async () => {
    try {
      await dbClient.query(`
        CREATE TABLE IF NOT EXISTS connectors (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name TEXT NOT NULL,
          description TEXT DEFAULT '',
          provider TEXT NOT NULL CHECK (provider IN ('aws', 'gcp', 'azure', 'kubernetes', 'docker', 'vault')),
          status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'validating', 'active', 'error', 'disabled')),
          mode TEXT DEFAULT 'discovery' CHECK (mode IN ('discovery', 'enforcement')),
          config JSONB DEFAULT '{}',
          credential_ref TEXT,
          last_scan_at TIMESTAMPTZ,
          last_scan_status TEXT,
          last_scan_duration_ms INTEGER,
          workload_count INTEGER DEFAULT 0,
          error_message TEXT,
          error_at TIMESTAMPTZ,
          consecutive_errors INTEGER DEFAULT 0,
          gateway_env_name TEXT,
          gateway_connected BOOLEAN DEFAULT FALSE,
          gateway_last_heartbeat TIMESTAMPTZ,
          created_by TEXT DEFAULT 'system',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        ALTER TABLE workloads ADD COLUMN IF NOT EXISTS connector_id UUID;
        CREATE INDEX IF NOT EXISTS idx_connectors_provider ON connectors(provider);
        CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
        CREATE INDEX IF NOT EXISTS idx_workloads_connector ON workloads(connector_id);
      `);
      console.log('[connectors] Schema migration applied');
    } catch (err) {
      console.log(`[connectors] Schema migration skipped: ${err.message}`);
    }
  })();

  // ═════════════════════════════════════════════════════════════════════
  // GET /api/v1/connectors — List all connectors
  // ═════════════════════════════════════════════════════════════════════
  app.get('/api/v1/connectors', async (req, res) => {
    try {
      const { rows } = await dbClient.query(`
        SELECT c.id, c.name, c.description, c.provider, c.status, c.mode, c.config,
               c.last_scan_at, c.last_scan_status, c.last_scan_duration_ms,
               c.error_message, c.gateway_env_name, c.gateway_connected, c.gateway_last_heartbeat,
               c.created_by, c.created_at, c.updated_at,
               COALESCE(p.cnt, 0)::int AS workload_count
        FROM connectors c
        LEFT JOIN (
          SELECT cloud_provider, COUNT(*) AS cnt FROM workloads GROUP BY cloud_provider
        ) p ON p.cloud_provider = c.provider
        ORDER BY c.created_at DESC
      `);

      res.json({
        connectors: rows,
        total: rows.length,
        by_status: {
          active: rows.filter(r => r.status === 'active').length,
          pending: rows.filter(r => r.status === 'pending').length,
          error: rows.filter(r => r.status === 'error').length,
          disabled: rows.filter(r => r.status === 'disabled').length,
        },
      });
    } catch (err) {
      console.error('[connectors] List error:', err.message);
      res.status(500).json({ error: 'Failed to list connectors' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // GET /api/v1/connectors/providers — Available provider definitions
  // ═════════════════════════════════════════════════════════════════════
  app.get('/api/v1/connectors/providers', (req, res) => {
    const providers = [
      {
        id: 'aws',
        name: 'Amazon Web Services',
        icon: 'aws',
        description: 'Discover IAM users, roles, EC2 instances, Lambda functions, ECS tasks, S3 buckets, and more.',
        credentialFields: [
          { name: 'accessKeyId', label: 'Access Key ID', type: 'text', required: true, placeholder: 'AKIA...' },
          { name: 'secretAccessKey', label: 'Secret Access Key', type: 'password', required: true },
          { name: 'region', label: 'Default Region', type: 'text', required: false, placeholder: 'us-east-1', default: 'us-east-1' },
          { name: 'roleArn', label: 'Assume Role ARN (optional)', type: 'text', required: false, placeholder: 'arn:aws:iam::123456789012:role/WIDDiscoveryRole' },
          { name: 'externalId', label: 'External ID (optional)', type: 'text', required: false },
        ],
        configFields: [
          { name: 'region', label: 'Region', type: 'text', default: 'us-east-1' },
          { name: 'accountAlias', label: 'Account Alias', type: 'text' },
        ],
        setupOptions: [
          { method: 'cloudformation', label: 'CloudFormation (Recommended)', description: 'One-click: creates a read-only IAM role in your account' },
          { method: 'manual', label: 'Manual', description: 'Paste IAM access key credentials' },
        ],
      },
      {
        id: 'gcp',
        name: 'Google Cloud Platform',
        icon: 'gcp',
        description: 'Discover service accounts, Compute Engine instances, Cloud Run services, GKE workloads, and IAM bindings.',
        credentialFields: [
          { name: 'serviceAccountJson', label: 'Service Account Key (JSON)', type: 'textarea', required: true, placeholder: '{"type": "service_account", ...}' },
          { name: 'projectId', label: 'Project ID', type: 'text', required: false, placeholder: 'my-project-123' },
        ],
        configFields: [
          { name: 'projectId', label: 'Project ID', type: 'text' },
          { name: 'orgId', label: 'Organization ID (optional)', type: 'text' },
        ],
        setupOptions: [
          { method: 'gcloud', label: 'gcloud CLI (Recommended)', description: 'Run our setup script to create a service account with Viewer role' },
          { method: 'manual', label: 'Manual', description: 'Upload existing service account JSON key' },
        ],
      },
      {
        id: 'azure',
        name: 'Microsoft Azure',
        icon: 'azure',
        description: 'Discover VMs, App Services, AKS clusters, Entra ID applications, and service principals.',
        credentialFields: [
          { name: 'tenantId', label: 'Tenant ID', type: 'text', required: true },
          { name: 'clientId', label: 'Client ID (Application ID)', type: 'text', required: true },
          { name: 'clientSecret', label: 'Client Secret', type: 'password', required: true },
          { name: 'subscriptionId', label: 'Subscription ID', type: 'text', required: false },
        ],
        configFields: [
          { name: 'subscriptionId', label: 'Subscription ID', type: 'text' },
          { name: 'tenantId', label: 'Tenant ID', type: 'text' },
        ],
        setupOptions: [
          { method: 'azurecli', label: 'Azure CLI (Recommended)', description: 'Run our setup script to create a service principal with Reader role' },
          { method: 'manual', label: 'Manual', description: 'Paste service principal credentials' },
        ],
      },
      {
        id: 'kubernetes',
        name: 'Kubernetes',
        icon: 'kubernetes',
        description: 'Discover deployments, statefulsets, daemonsets, cronjobs, and service accounts across clusters.',
        credentialFields: [
          { name: 'kubeconfig', label: 'Kubeconfig', type: 'textarea', required: true, placeholder: 'apiVersion: v1\nkind: Config\n...' },
          { name: 'context', label: 'Context (optional)', type: 'text', required: false },
          { name: 'clusterName', label: 'Cluster Name', type: 'text', required: false },
        ],
        configFields: [
          { name: 'clusterName', label: 'Cluster Name', type: 'text' },
          { name: 'context', label: 'Kubeconfig Context', type: 'text' },
        ],
      },
      {
        id: 'vault',
        name: 'HashiCorp Vault',
        icon: 'vault',
        description: 'Discover Vault secrets engines, auth methods, and token policies.',
        credentialFields: [
          { name: 'vaultAddr', label: 'Vault Address', type: 'text', required: true, placeholder: 'https://vault.example.com:8200' },
          { name: 'vaultToken', label: 'Vault Token', type: 'password', required: true },
        ],
        configFields: [
          { name: 'vaultAddr', label: 'Vault Address', type: 'text' },
        ],
      },
    ];

    res.json({ providers });
  });

  // ═════════════════════════════════════════════════════════════════════
  // POST /api/v1/connectors — Create a new connector
  // ═════════════════════════════════════════════════════════════════════
  app.post('/api/v1/connectors', async (req, res) => {
    try {
      const { name, provider, description, config, credentials, mode } = req.body;

      // Validate input fields
      const inputErrors = validateConnectorInput(name, description, mode);
      if (inputErrors.length > 0) {
        return res.status(400).json({ error: inputErrors.join('; ') });
      }
      if (!provider) {
        return res.status(400).json({ error: 'provider is required' });
      }
      if (!PROVIDER_FIELDS[provider]) {
        return res.status(400).json({ error: `Unsupported provider: ${provider}. Supported: ${Object.keys(PROVIDER_FIELDS).join(', ')}` });
      }

      // Validate required credential fields
      const providerDef = PROVIDER_FIELDS[provider];
      if (credentials) {
        for (const field of providerDef.required) {
          if (!credentials[field]) {
            return res.status(400).json({ error: `Missing required credential field: ${field}` });
          }
        }
      }

      // Merge non-secret context fields from credentials into config
      // so they persist even if the credential store is unavailable
      const mergedConfig = { ...(config || {}) };
      if (credentials) {
        for (const field of (providerDef.configFields || [])) {
          if (credentials[field] && !mergedConfig[field]) {
            mergedConfig[field] = credentials[field];
          }
        }
      }

      // Insert connector (without credentials)
      const { rows } = await dbClient.query(`
        INSERT INTO connectors (name, description, provider, mode, config, status)
        VALUES ($1, $2, $3, $4, $5, 'pending')
        RETURNING *
      `, [name, description || '', provider, mode || 'discovery', JSON.stringify(mergedConfig)]);

      const connector = rows[0];

      // Store credentials in Secret Manager
      if (credentials) {
        try {
          const credRef = await storeCredentials(connector.id, provider, credentials);
          await dbClient.query(
            'UPDATE connectors SET credential_ref = $1 WHERE id = $2',
            [credRef, connector.id]
          );
          connector.credential_ref = credRef;
        } catch (credErr) {
          console.error('[connectors] Credential storage failed:', credErr.message);
          await dbClient.query(
            "UPDATE connectors SET status = 'error', error_message = $1, error_at = NOW() WHERE id = $2",
            [sanitizeErrorMessage(`Credential storage failed: ${credErr.message}`), connector.id]
          );
          return res.status(500).json({ error: 'Failed to store credentials securely' });
        }
      }

      console.log(`[connectors] Created connector: ${connector.id} (${provider}) "${name}"`);
      res.status(201).json({ connector });
    } catch (err) {
      console.error('[connectors] Create error:', err.message);
      res.status(500).json({ error: 'Failed to create connector' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // GET /api/v1/connectors/:id — Get connector details
  // ═════════════════════════════════════════════════════════════════════
  app.get('/api/v1/connectors/:id', async (req, res) => {
    try {
      const { rows } = await dbClient.query(
        `SELECT id, name, description, provider, status, mode, config,
                last_scan_at, last_scan_status, last_scan_duration_ms, workload_count,
                error_message, gateway_env_name, gateway_connected, gateway_last_heartbeat,
                created_by, created_at, updated_at
         FROM connectors WHERE id = $1`,
        [req.params.id]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'Connector not found' });
      }

      res.json({ connector: rows[0] });
    } catch (err) {
      console.error('[connectors] Get error:', err.message);
      res.status(500).json({ error: 'Failed to get connector' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // PUT /api/v1/connectors/:id — Update connector
  // ═════════════════════════════════════════════════════════════════════
  app.put('/api/v1/connectors/:id', async (req, res) => {
    try {
      const { name, description, config, credentials, mode, status } = req.body;
      const connectorId = req.params.id;

      // Check exists
      const existing = await dbClient.query('SELECT * FROM connectors WHERE id = $1', [connectorId]);
      if (existing.rows.length === 0) {
        return res.status(404).json({ error: 'Connector not found' });
      }

      // Build SET clause dynamically
      const updates = [];
      const values = [];
      let paramIdx = 1;

      if (name !== undefined) { updates.push(`name = $${paramIdx++}`); values.push(name); }
      if (description !== undefined) { updates.push(`description = $${paramIdx++}`); values.push(description); }
      if (config !== undefined) { updates.push(`config = $${paramIdx++}`); values.push(JSON.stringify(config)); }
      if (mode !== undefined) { updates.push(`mode = $${paramIdx++}`); values.push(mode); }
      if (status !== undefined) { updates.push(`status = $${paramIdx++}`); values.push(status); }

      if (updates.length > 0) {
        values.push(connectorId);
        await dbClient.query(
          `UPDATE connectors SET ${updates.join(', ')} WHERE id = $${paramIdx}`,
          values
        );
      }

      // Update credentials if provided
      if (credentials) {
        const provider = existing.rows[0].provider;
        await storeCredentials(connectorId, provider, credentials);
      }

      const { rows } = await dbClient.query(
        `SELECT id, name, description, provider, status, mode, config,
                last_scan_at, last_scan_status, workload_count,
                created_at, updated_at
         FROM connectors WHERE id = $1`,
        [connectorId]
      );

      res.json({ connector: rows[0] });
    } catch (err) {
      console.error('[connectors] Update error:', err.message);
      res.status(500).json({ error: 'Failed to update connector' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // DELETE /api/v1/connectors/:id — Remove connector + credentials
  // Query params:
  //   ?purge=true  → DELETE workloads discovered by this connector (removes from graph)
  //   (default)    → SET connector_id = NULL (workloads remain as unlinked/archived)
  // Always invalidates graph cache.
  // ═════════════════════════════════════════════════════════════════════
  app.delete('/api/v1/connectors/:id', async (req, res) => {
    try {
      const connectorId = req.params.id;
      const purge = req.query.purge === 'true';

      // Check exists
      const { rows } = await dbClient.query('SELECT id, name, provider FROM connectors WHERE id = $1', [connectorId]);
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Connector not found' });
      }

      // Count affected workloads
      const countResult = await dbClient.query('SELECT COUNT(*)::int AS cnt FROM workloads WHERE connector_id = $1', [connectorId]);
      const workloadsAffected = countResult.rows[0].cnt;

      if (purge) {
        // Delete workloads discovered by this connector (removes them from graph)
        await dbClient.query('DELETE FROM workloads WHERE connector_id = $1', [connectorId]);
        console.log(`[connectors] Purged ${workloadsAffected} workloads for connector ${connectorId}`);
      } else {
        // Unlink workloads (they remain in DB as archived/unlinked)
        await dbClient.query('UPDATE workloads SET connector_id = NULL WHERE connector_id = $1', [connectorId]);
      }

      // Delete credentials from Secret Manager
      await deleteCredentials(connectorId);

      // Delete connector record
      await dbClient.query('DELETE FROM connectors WHERE id = $1', [connectorId]);

      // Invalidate graph cache so the identity graph reflects the change
      clearGraphCache();

      console.log(`[connectors] Deleted connector: ${connectorId} (${rows[0].provider}) "${rows[0].name}" purge=${purge}`);
      res.json({ deleted: true, id: connectorId, workloads_affected: workloadsAffected, purged: purge });
    } catch (err) {
      console.error('[connectors] Delete error:', err.message);
      res.status(500).json({ error: 'Failed to delete connector' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // POST /api/v1/connectors/:id/test — Validate credentials
  // ═════════════════════════════════════════════════════════════════════
  app.post('/api/v1/connectors/:id/test', async (req, res) => {
    try {
      const connectorId = req.params.id;

      // Rate limit: 5 test calls per connector per minute
      if (rateLimit(`test:${connectorId}`, 5)) {
        return res.status(429).json({ error: 'Too many test requests. Try again in a minute.' });
      }

      const { rows } = await dbClient.query('SELECT * FROM connectors WHERE id = $1', [connectorId]);
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Connector not found' });
      }

      const connector = rows[0];
      await dbClient.query(
        "UPDATE connectors SET status = 'validating' WHERE id = $1",
        [connectorId]
      );

      // Retrieve stored credentials
      const credData = await getCredentials(connectorId);
      if (!credData || !credData.credentials) {
        await dbClient.query(
          "UPDATE connectors SET status = 'error', error_message = 'No credentials stored', error_at = NOW() WHERE id = $1",
          [connectorId]
        );
        return res.status(400).json({ valid: false, error: 'No credentials stored for this connector' });
      }

      // Test credentials by trying to create and validate a scanner instance
      const testResult = await testProviderCredentials(connector.provider, credData.credentials, connector.config);

      if (testResult.valid) {
        await dbClient.query(
          "UPDATE connectors SET status = 'active', error_message = NULL, consecutive_errors = 0 WHERE id = $1",
          [connectorId]
        );
        res.json({ valid: true, details: testResult.details });
      } else {
        await dbClient.query(
          "UPDATE connectors SET status = 'error', error_message = $1, error_at = NOW(), consecutive_errors = consecutive_errors + 1 WHERE id = $2",
          [testResult.error, connectorId]
        );
        res.json({ valid: false, error: testResult.error });
      }
    } catch (err) {
      console.error('[connectors] Test error:', err.message);
      res.status(500).json({ error: 'Credential test failed' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // POST /api/v1/connectors/:id/scan — Trigger discovery for connector
  // ═════════════════════════════════════════════════════════════════════
  app.post('/api/v1/connectors/:id/scan', async (req, res) => {
    try {
      const connectorId = req.params.id;

      // Rate limit: 1 scan per connector per 5 minutes
      if (rateLimit(`scan:${connectorId}`, 1, 300000)) {
        return res.status(429).json({ error: 'Scan already ran recently. Try again in a few minutes.' });
      }

      const { rows } = await dbClient.query('SELECT * FROM connectors WHERE id = $1', [connectorId]);
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Connector not found' });
      }

      const connector = rows[0];

      // Check not already scanning
      if (connector.last_scan_status === 'running') {
        return res.status(409).json({ error: 'Scan already in progress for this connector' });
      }

      // Mark scan as running
      await dbClient.query(
        "UPDATE connectors SET last_scan_status = 'running', last_scan_at = NOW() WHERE id = $1",
        [connectorId]
      );

      // Retrieve credentials (may be empty for providers using platform identity like GCP/Azure)
      const credData = await getCredentials(connectorId);
      const credentials = credData?.credentials || {};

      // For providers that require stored secrets (AWS roleArn, K8s kubeconfig), fail if missing
      const providerDef = PROVIDER_FIELDS[connector.provider];
      const needsSecrets = providerDef?.required?.some(f => !credentials[f]);
      // Check if config has the required fields (they may have been persisted there)
      const connConfig = typeof connector.config === 'string' ? JSON.parse(connector.config) : (connector.config || {});
      const hasConfigFallback = providerDef?.required?.every(f => credentials[f] || connConfig[f]);
      if (needsSecrets && !hasConfigFallback) {
        await dbClient.query(
          "UPDATE connectors SET last_scan_status = 'failed', error_message = 'No credentials stored' WHERE id = $1",
          [connectorId]
        );
        return res.status(400).json({ error: 'Required credentials not found for this connector' });
      }

      // Merge config fields into credentials so scanners have access to context fields
      for (const [k, v] of Object.entries(connConfig)) {
        if (!credentials[k]) credentials[k] = v;
      }

      // Run scan async — respond immediately
      res.json({
        status: 'scanning',
        connector_id: connectorId,
        message: `Discovery scan started for ${connector.name} (${connector.provider})`,
      });

      // Background scan
      const startTime = Date.now();
      try {
        const workloads = await runProviderScan(connector, credentials, dbClient, deps);
        const duration = Date.now() - startTime;

        // Use live DB count (includes workloads from all scan sources, not just this scan)
        let liveCount = workloads.length;
        try {
          const { rows: countRows } = await dbClient.query(
            'SELECT COUNT(*)::int AS cnt FROM workloads WHERE cloud_provider = $1',
            [connector.provider]
          );
          liveCount = countRows[0]?.cnt || workloads.length;
        } catch { /* fallback to scan count */ }

        await dbClient.query(
          `UPDATE connectors SET
            last_scan_status = 'completed',
            last_scan_duration_ms = $1,
            workload_count = $2,
            status = 'active',
            error_message = NULL,
            consecutive_errors = 0
           WHERE id = $3`,
          [duration, liveCount, connectorId]
        );

        console.log(`[connectors] Scan completed: ${connector.name} — ${workloads.length} workloads in ${duration}ms`);

        // Invalidate graph cache so next GET /graph rebuilds with new workloads
        if (workloads.length > 0) {
          clearGraphCache();
        }
      } catch (scanErr) {
        const duration = Date.now() - startTime;
        await dbClient.query(
          `UPDATE connectors SET
            last_scan_status = 'failed',
            last_scan_duration_ms = $1,
            error_message = $2,
            error_at = NOW(),
            consecutive_errors = consecutive_errors + 1
           WHERE id = $3`,
          [duration, sanitizeErrorMessage(scanErr.message), connectorId]
        );
        console.error(`[connectors] Scan failed for ${connector.name}: ${sanitizeErrorMessage(scanErr.message)}`);
      }
    } catch (err) {
      console.error('[connectors] Scan trigger error:', err.message);
      res.status(500).json({ error: 'Failed to trigger scan' });
    }
  });

  // ═════════════════════════════════════════════════════════════════════
  // POST /api/v1/connectors/purge — Delete ALL connectors + workloads (demo reset)
  // ═════════════════════════════════════════════════════════════════════
  app.post('/api/v1/connectors/purge', async (req, res) => {
    try {
      // Delete workloads linked to connectors
      const wRes = await dbClient.query('DELETE FROM workloads WHERE connector_id IS NOT NULL');
      // Delete all connectors
      const cRes = await dbClient.query('DELETE FROM connectors');
      // Clean up credential store entries
      const connectorIds = [];
      // Also delete workloads with no connector (orphans from scans)
      const oRes = await dbClient.query('DELETE FROM workloads');
      // Clear related tables
      await dbClient.query('DELETE FROM discovery_scans').catch(() => {});
      await dbClient.query('DELETE FROM targets').catch(() => {});

      console.log(`[connectors] PURGE: deleted ${cRes.rowCount} connectors, ${wRes.rowCount + oRes.rowCount} workloads`);

      res.json({
        purged: true,
        connectors_deleted: cRes.rowCount,
        workloads_deleted: wRes.rowCount + oRes.rowCount,
      });
    } catch (err) {
      console.error('[connectors] Purge error:', err.message);
      res.status(500).json({ error: 'Failed to purge: ' + err.message });
    }
  });

  console.log('[connectors] Routes mounted: /api/v1/connectors');
}

// =============================================================================
// Provider-specific credential testing
// =============================================================================

async function testProviderCredentials(provider, credentials, config = {}) {
  try {
    switch (provider) {
      case 'aws': {
        const { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } = require('@aws-sdk/client-sts');
        const region = credentials.region || config.region || 'us-east-1';

        // Build base client config (platform credentials from env, or SDK default chain)
        const clientConfig = { region };
        if (process.env.AWS_ACCESS_KEY_ID) {
          clientConfig.credentials = {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
          };
        }

        // Assume the customer's cross-account role
        if (!credentials.roleArn) {
          return { valid: false, error: 'Role ARN is required for AWS connector' };
        }

        const sts = new STSClient(clientConfig);
        const assumeParams = {
          RoleArn: credentials.roleArn,
          RoleSessionName: `wid-test-${Date.now()}`,
          DurationSeconds: 900,
        };
        if (credentials.externalId) assumeParams.ExternalId = credentials.externalId;

        const assumeResult = await sts.send(new AssumeRoleCommand(assumeParams));
        const assumed = assumeResult.Credentials;

        // Verify assumed role identity
        const assumedSts = new STSClient({
          region,
          credentials: {
            accessKeyId: assumed.AccessKeyId,
            secretAccessKey: assumed.SecretAccessKey,
            sessionToken: assumed.SessionToken,
          },
        });
        const identity = await assumedSts.send(new GetCallerIdentityCommand({}));
        return {
          valid: true,
          details: {
            account: identity.Account,
            arn: identity.Arn,
            userId: identity.UserId,
            assumedRole: credentials.roleArn,
          },
        };
      }

      case 'gcp': {
        // WID uses its own service account (ADC) to access the customer's project.
        // Test: verify we can list resources in their project.
        const projectId = credentials.projectId || config.projectId;
        if (!projectId) {
          return { valid: false, error: 'Project ID is required' };
        }

        try {
          const { google } = require('googleapis');
          const auth = new google.auth.GoogleAuth({
            scopes: ['https://www.googleapis.com/auth/cloud-platform'],
          });
          const run = google.run({ version: 'v2', auth });
          await run.projects.locations.services.list({
            parent: `projects/${projectId}/locations/-`,
            pageSize: 1,
          });
        } catch (gcpErr) {
          const msg = sanitizeErrorMessage(gcpErr.message);
          if (msg.includes('PERMISSION_DENIED') || msg.includes('403')) {
            return { valid: false, error: `WID does not have access to project ${projectId}. Grant roles/viewer and roles/iam.securityReviewer to wid-dev-run@wid-platform.iam.gserviceaccount.com` };
          }
          return { valid: false, error: `GCP access check failed: ${msg}` };
        }

        return {
          valid: true,
          details: {
            projectId,
            accessMethod: 'service-account-impersonation',
          },
        };
      }

      case 'azure': {
        // WID uses its own Azure AD multi-tenant app to access customer subscriptions.
        // Test: verify WID's app can authenticate against the customer's tenant.
        if (!credentials.tenantId || !credentials.subscriptionId) {
          return { valid: false, error: 'Tenant ID and Subscription ID are required' };
        }

        // Use platform credentials from env
        const clientId = process.env.AZURE_CLIENT_ID;
        const clientSecret = process.env.AZURE_CLIENT_SECRET;
        if (!clientId || !clientSecret) {
          // No Azure platform credentials configured — accept the connector for now
          return {
            valid: true,
            details: {
              tenantId: credentials.tenantId,
              subscriptionId: credentials.subscriptionId,
              note: 'Azure platform credentials not yet configured. Connector saved — scanning will work once AZURE_CLIENT_ID/AZURE_CLIENT_SECRET are set.',
            },
          };
        }

        const tokenUrl = `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`;
        const params = new URLSearchParams({
          grant_type: 'client_credentials',
          client_id: clientId,
          client_secret: clientSecret,
          scope: 'https://management.azure.com/.default',
        });
        const tokenResp = await fetch(tokenUrl, { method: 'POST', body: params });
        if (!tokenResp.ok) {
          return { valid: false, error: 'WID app does not have access to this Azure tenant. Ensure WID\'s enterprise application is registered and consented in your tenant.' };
        }
        return {
          valid: true,
          details: {
            tenantId: credentials.tenantId,
            subscriptionId: credentials.subscriptionId,
            accessMethod: 'multi-tenant-app',
          },
        };
      }

      case 'kubernetes': {
        // Basic validation — check kubeconfig is valid YAML-like structure
        const kc = credentials.kubeconfig || '';
        if (!kc.includes('apiVersion') || !kc.includes('clusters')) {
          return { valid: false, error: 'Invalid kubeconfig format' };
        }
        return { valid: true, details: { hasKubeconfig: true } };
      }

      case 'vault': {
        const vaultAddr = credentials.vaultAddr;
        const resp = await fetch(`${vaultAddr}/v1/sys/health`, {
          headers: { 'X-Vault-Token': credentials.vaultToken },
        });
        if (!resp.ok) {
          return { valid: false, error: `Vault health check failed: HTTP ${resp.status}` };
        }
        const health = await resp.json();
        return { valid: true, details: { initialized: health.initialized, sealed: health.sealed, version: health.version } };
      }

      default:
        return { valid: false, error: `Unsupported provider: ${provider}` };
    }
  } catch (err) {
    return { valid: false, error: sanitizeErrorMessage(err.message) };
  }
}

// =============================================================================
// Provider-specific scan execution — creates scanner instance from credentials
// =============================================================================

async function runProviderScan(connector, credentials, dbClient, deps) {
  const { saveWorkload } = deps;
  const provider = connector.provider;
  const config = connector.config || {};
  const allWorkloads = [];

  // Build scanner config from connector credentials
  switch (provider) {
    case 'aws': {
      // WID uses role assumption — no customer access keys stored.
      // Platform credentials come from env (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)
      // or from the GCP service account's workload identity federation.
      const scanConfig = {
        enabled: true,
        region: credentials.region || config.region || 'us-east-1',
        trustDomain: 'company.com',
        // Platform credentials from environment (used to call STS:AssumeRole)
        credentials: process.env.AWS_ACCESS_KEY_ID ? {
          accessKeyId: process.env.AWS_ACCESS_KEY_ID,
          secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
        } : null,
        // Customer's cross-account role (required)
        roleArn: credentials.roleArn,
        externalId: credentials.externalId,
      };

      // Run the main AWS scanner + sub-scanners
      const scannerNames = ['aws', 'aws-storage', 'aws-network', 'aws-security', 'iam'];
      for (const scannerName of scannerNames) {
        try {
          const scannerDef = deps.scannerRegistry?.getScanner(scannerName);
          if (!scannerDef) continue;

          const instance = new scannerDef.class(scanConfig);
          if (typeof instance.validate === 'function') {
            const valid = await instance.validate();
            if (!valid) continue;
          }

          const workloads = await instance.discover();
          for (const w of workloads) {
            w.connector_id = connector.id;
            if (saveWorkload) await saveWorkload(w);
            allWorkloads.push(w);
          }
        } catch (scanErr) {
          console.error(`[connectors] Scanner ${scannerName} error: ${scanErr.message}`);
        }
      }
      break;
    }

    case 'gcp': {
      // WID uses its own service account identity (Application Default Credentials).
      // Customer grants WID's SA read-only roles on their project — no keys stored.
      // Backward compat: if credentials have serviceAccountJson (old format), extract project_id and use it.
      let gcpProjectId = credentials.projectId || config.projectId || config.project;
      let gcpExplicitCreds = null;

      if (credentials.serviceAccountJson) {
        try {
          const saKey = typeof credentials.serviceAccountJson === 'string'
            ? JSON.parse(credentials.serviceAccountJson)
            : credentials.serviceAccountJson;
          if (!gcpProjectId && saKey.project_id) gcpProjectId = saKey.project_id;
          gcpExplicitCreds = saKey;
        } catch { /* ignore parse errors */ }
      }

      if (!gcpProjectId) {
        console.error('[connectors] GCP scan: no projectId found in credentials or config');
        break;
      }

      const scanConfig = {
        enabled: true,
        project: gcpProjectId,
        trustDomain: 'company.com',
        // Use explicit SA key credentials if available (backward compat), otherwise ADC
        ...(gcpExplicitCreds ? { credentials: gcpExplicitCreds } : {}),
      };

      try {
        const scannerDef = deps.scannerRegistry?.getScanner('gcp');
        if (scannerDef) {
          const instance = new scannerDef.class(scanConfig);
          const workloads = await instance.discover();
          for (const w of workloads) {
            w.connector_id = connector.id;
            if (saveWorkload) await saveWorkload(w);
            allWorkloads.push(w);
          }
        }
      } catch (scanErr) {
        console.error(`[connectors] GCP scanner error: ${scanErr.message}`);
      }
      break;
    }

    case 'azure': {
      // WID uses its own multi-tenant Azure AD app identity.
      // Customer consents to WID's app and assigns Reader + Security Reader roles.
      // Platform credentials come from env (AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_TENANT_ID).
      const scanConfig = {
        enabled: true,
        subscriptionId: credentials.subscriptionId || config.subscriptionId,
        tenantId: credentials.tenantId,
        trustDomain: 'company.com',
        credentials: process.env.AZURE_CLIENT_ID ? {
          clientId: process.env.AZURE_CLIENT_ID,
          clientSecret: process.env.AZURE_CLIENT_SECRET,
          tenantId: credentials.tenantId,
        } : null,
      };

      for (const scannerName of ['azure', 'azure-entra']) {
        try {
          const scannerDef = deps.scannerRegistry?.getScanner(scannerName);
          if (!scannerDef) continue;

          const instance = new scannerDef.class(scanConfig);
          const workloads = await instance.discover();
          for (const w of workloads) {
            w.connector_id = connector.id;
            if (saveWorkload) await saveWorkload(w);
            allWorkloads.push(w);
          }
        } catch (scanErr) {
          console.error(`[connectors] Scanner ${scannerName} error: ${scanErr.message}`);
        }
      }
      break;
    }

    case 'kubernetes': {
      try {
        const scannerDef = deps.scannerRegistry?.getScanner('kubernetes');
        if (scannerDef) {
          const instance = new scannerDef.class();
          // Override kubeconfig from connector credentials
          if (credentials.kubeconfig) {
            instance.kubeconfig = credentials.kubeconfig;
          }
          const workloads = await instance.discover();
          for (const w of workloads) {
            w.connector_id = connector.id;
            if (saveWorkload) await saveWorkload(w);
            allWorkloads.push(w);
          }
        }
      } catch (scanErr) {
        console.error(`[connectors] K8s scanner error: ${scanErr.message}`);
      }
      break;
    }

    case 'vault': {
      try {
        const scannerDef = deps.scannerRegistry?.getScanner('vault');
        if (scannerDef) {
          const instance = new scannerDef.class({
            enabled: true,
            vaultAddr: credentials.vaultAddr,
            vaultToken: credentials.vaultToken,
          });
          const workloads = await instance.discover();
          for (const w of workloads) {
            w.connector_id = connector.id;
            if (saveWorkload) await saveWorkload(w);
            allWorkloads.push(w);
          }
        }
      } catch (scanErr) {
        console.error(`[connectors] Vault scanner error: ${scanErr.message}`);
      }
      break;
    }

    default:
      throw new Error(`Unsupported provider for scanning: ${provider}`);
  }

  return allWorkloads;
}

module.exports = { mountConnectorRoutes, runProviderScan };
