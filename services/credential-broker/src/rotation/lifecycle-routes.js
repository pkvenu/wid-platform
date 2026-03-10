// =============================================================================
// Lifecycle Routes — Secret rotation, revocation, history, and migration API
// =============================================================================

function mountLifecycleRoutes(app, dbClient, providerManager, scheduler) {

  // ── POST /v1/credentials/:id/rotate — Trigger rotation ──────────────
  app.post('/v1/credentials/:id/rotate', async (req, res) => {
    try {
      const credentialPath = decodeURIComponent(req.params.id);
      const { provider, new_value, workload_id } = req.body || {};

      // Schedule the rotation
      const rotation = await scheduler.scheduleRotation(credentialPath, 'manual', {
        provider,
        workloadId: workload_id,
      });

      // If new_value provided, execute immediately
      if (new_value) {
        try {
          const result = await scheduler.executeRotation(rotation.id, new_value);
          return res.json({
            message: `Credential "${credentialPath}" rotated successfully`,
            rotation_id: rotation.id,
            status: 'completed',
            old_version: result.oldVersion,
            new_version: result.newVersion,
          });
        } catch (execErr) {
          return res.status(500).json({
            error: `Rotation failed: ${execErr.message}`,
            rotation_id: rotation.id,
            status: 'failed',
          });
        }
      }

      // Otherwise return pending rotation for async execution
      res.status(202).json({
        message: `Rotation scheduled for "${credentialPath}"`,
        rotation_id: rotation.id,
        status: 'pending',
        execute_url: `/v1/credentials/rotations/${rotation.id}/execute`,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /v1/credentials/rotations/:id/execute — Execute pending ────
  app.post('/v1/credentials/rotations/:id/execute', async (req, res) => {
    try {
      const { new_value } = req.body || {};
      const result = await scheduler.executeRotation(parseInt(req.params.id), new_value);
      res.json({
        message: 'Rotation executed',
        ...result,
      });
    } catch (err) {
      res.status(err.message.includes('not found') ? 404 : 500).json({ error: err.message });
    }
  });

  // ── GET /v1/credentials/:id/history — Rotation history ──────────────
  app.get('/v1/credentials/:id/history', async (req, res) => {
    try {
      const credentialPath = decodeURIComponent(req.params.id);
      const limit = parseInt(req.query.limit) || 20;
      const history = await scheduler.getHistory(credentialPath, limit);
      res.json({
        credential: credentialPath,
        rotations: history,
        total: history.length,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /v1/credentials/:id/revoke — Revoke credential ────────────
  app.post('/v1/credentials/:id/revoke', async (req, res) => {
    try {
      const credentialPath = decodeURIComponent(req.params.id);
      const { provider, version } = req.body || {};
      const result = await scheduler.revokeCredential(credentialPath, provider, version);

      // Clear from cache
      const cache = require('../utils/cache');
      cache.flush();

      res.json({
        message: `Credential "${credentialPath}" revoked`,
        ...result,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /v1/credentials/stale — List stale credentials ──────────────
  app.get('/v1/credentials/stale', async (req, res) => {
    try {
      const days = parseInt(req.query.days) || 90;
      const stale = await scheduler.getStaleCredentials(days);
      res.json({
        threshold_days: days,
        stale_credentials: stale,
        total: stale.length,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /v1/credentials/migrate — Cross-provider migration ────────
  app.post('/v1/credentials/migrate', async (req, res) => {
    try {
      const { from_provider, to_provider, credential_path, target_path } = req.body || {};

      if (!from_provider || !to_provider || !credential_path) {
        return res.status(400).json({
          error: 'from_provider, to_provider, and credential_path are required',
        });
      }

      const result = await scheduler.migrateCredential(
        from_provider, to_provider, credential_path,
        { targetPath: target_path }
      );

      res.json({
        message: `Credential migrated from ${from_provider} to ${to_provider}`,
        ...result,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /v1/credentials/rotations — List all rotations ──────────────
  app.get('/v1/credentials/rotations', async (req, res) => {
    try {
      const status = req.query.status;
      let query = 'SELECT * FROM credential_rotations';
      const params = [];

      if (status) {
        params.push(status);
        query += ` WHERE status = $${params.length}`;
      }

      query += ' ORDER BY created_at DESC LIMIT 100';

      const { rows } = await dbClient.query(query, params);
      res.json({
        rotations: rows,
        total: rows.length,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /v1/credentials/rotations/:id — Single rotation status ──────
  app.get('/v1/credentials/rotations/:id', async (req, res) => {
    try {
      const rotation = await scheduler.getRotation(parseInt(req.params.id));
      if (!rotation) return res.status(404).json({ error: 'Rotation not found' });
      res.json(rotation);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /v1/credentials/providers — List providers with capabilities ─
  app.get('/v1/credentials/providers', (req, res) => {
    const metadata = providerManager.getProvidersMetadata();
    const enriched = metadata.map(p => {
      const provider = providerManager.getProvider(p.key);
      return {
        ...p,
        capabilities: {
          rotation: provider?.supportsRotation() || false,
          revocation: provider?.supportsRevocation() || false,
          dynamic_secrets: provider?.supportsDynamicSecrets() || false,
        },
      };
    });
    res.json({ providers: enriched });
  });

  // ── POST /v1/credentials/dynamic — Generate dynamic secret ──────────
  app.post('/v1/credentials/dynamic', async (req, res) => {
    try {
      const { engine, role, provider } = req.body || {};
      if (!engine || !role) {
        return res.status(400).json({ error: 'engine and role are required' });
      }

      const providerKey = provider || 'hashicorp-vault';
      const p = providerManager.getProvider(providerKey);
      if (!p?.supportsDynamicSecrets()) {
        return res.status(400).json({ error: `Provider "${providerKey}" does not support dynamic secrets` });
      }

      const result = await p.getDynamicSecret(engine, role);
      res.json({
        message: 'Dynamic secret generated',
        ...result,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}

module.exports = { mountLifecycleRoutes };
