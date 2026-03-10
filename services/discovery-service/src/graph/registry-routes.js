// =============================================================================
// Registry Routes — CRUD API for provider_registry table
// =============================================================================
// Allows adding, updating, and disabling provider/domain entries without
// redeployment. Changes take effect on next auto-reload (60s) or immediately
// via POST /api/v1/registry/reload.
// =============================================================================

const { ProviderRegistry } = require('./provider-registry');

function mountRegistryRoutes(app, dbClient) {

  // ── GET /api/v1/registry — List all entries ──
  app.get('/api/v1/registry', async (req, res) => {
    try {
      const { type, category, enabled } = req.query;
      let query = 'SELECT * FROM provider_registry WHERE 1=1';
      const params = [];

      if (type) {
        params.push(type);
        query += ` AND registry_type = $${params.length}`;
      }
      if (category) {
        params.push(category);
        query += ` AND category = $${params.length}`;
      }
      if (enabled !== undefined) {
        params.push(enabled === 'true');
        query += ` AND enabled = $${params.length}`;
      }

      query += ' ORDER BY sort_order, registry_type, id';
      const { rows } = await dbClient.query(query, params);

      // Include stats
      const registry = ProviderRegistry.getInstance();
      res.json({
        entries: rows,
        total: rows.length,
        stats: registry.getStats(),
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── GET /api/v1/registry/stats — Registry stats ──
  app.get('/api/v1/registry/stats', (req, res) => {
    const registry = ProviderRegistry.getInstance();
    res.json(registry.getStats());
  });

  // ── GET /api/v1/registry/:id — Single entry ──
  app.get('/api/v1/registry/:id', async (req, res) => {
    try {
      const { rows } = await dbClient.query(
        'SELECT * FROM provider_registry WHERE id = $1', [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(rows[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/v1/registry — Create new entry ──
  app.post('/api/v1/registry', async (req, res) => {
    try {
      const { id, registry_type, label, category, credential_keys,
              ai_config, domain_patterns, domain_type,
              image_patterns, signal_patterns, sort_order } = req.body;

      if (!id || !registry_type || !label || !category) {
        return res.status(400).json({ error: 'id, registry_type, label, and category are required' });
      }

      // Validate regex patterns to prevent ReDoS
      for (const pat of (signal_patterns || [])) {
        if (pat.length > 500) {
          return res.status(400).json({ error: `Pattern too long (${pat.length} chars, max 500)` });
        }
        try { new RegExp(pat, 'i'); } catch (e) {
          return res.status(400).json({ error: `Invalid regex "${pat}": ${e.message}` });
        }
      }

      const { rows } = await dbClient.query(`
        INSERT INTO provider_registry (id, registry_type, label, category, credential_keys, ai_config, domain_patterns, domain_type, image_patterns, signal_patterns, sort_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING *
      `, [
        id, registry_type, label, category,
        credential_keys || [],
        ai_config ? JSON.stringify(ai_config) : null,
        domain_patterns || [], domain_type || null,
        image_patterns || [], signal_patterns || [],
        sort_order || 100,
      ]);

      res.status(201).json(rows[0]);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: `Entry "${req.body.id}" already exists` });
      }
      res.status(500).json({ error: err.message });
    }
  });

  // ── PUT /api/v1/registry/:id — Update entry ──
  app.put('/api/v1/registry/:id', async (req, res) => {
    try {
      const { label, category, credential_keys, ai_config,
              domain_patterns, domain_type, image_patterns,
              signal_patterns, enabled, sort_order } = req.body;

      // Validate regex patterns
      for (const pat of (signal_patterns || [])) {
        if (pat.length > 500) {
          return res.status(400).json({ error: `Pattern too long (${pat.length} chars, max 500)` });
        }
        try { new RegExp(pat, 'i'); } catch (e) {
          return res.status(400).json({ error: `Invalid regex "${pat}": ${e.message}` });
        }
      }

      const sets = [];
      const params = [req.params.id];
      let idx = 2;

      if (label !== undefined) { sets.push(`label = $${idx++}`); params.push(label); }
      if (category !== undefined) { sets.push(`category = $${idx++}`); params.push(category); }
      if (credential_keys !== undefined) { sets.push(`credential_keys = $${idx++}`); params.push(credential_keys); }
      if (ai_config !== undefined) { sets.push(`ai_config = $${idx++}`); params.push(JSON.stringify(ai_config)); }
      if (domain_patterns !== undefined) { sets.push(`domain_patterns = $${idx++}`); params.push(domain_patterns); }
      if (domain_type !== undefined) { sets.push(`domain_type = $${idx++}`); params.push(domain_type); }
      if (image_patterns !== undefined) { sets.push(`image_patterns = $${idx++}`); params.push(image_patterns); }
      if (signal_patterns !== undefined) { sets.push(`signal_patterns = $${idx++}`); params.push(signal_patterns); }
      if (enabled !== undefined) { sets.push(`enabled = $${idx++}`); params.push(enabled); }
      if (sort_order !== undefined) { sets.push(`sort_order = $${idx++}`); params.push(sort_order); }

      if (!sets.length) return res.status(400).json({ error: 'No fields to update' });

      sets.push('updated_at = NOW()');

      const { rows } = await dbClient.query(
        `UPDATE provider_registry SET ${sets.join(', ')} WHERE id = $1 RETURNING *`,
        params
      );

      if (!rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(rows[0]);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── DELETE /api/v1/registry/:id — Soft-disable (set enabled=false) ──
  app.delete('/api/v1/registry/:id', async (req, res) => {
    try {
      const { rows } = await dbClient.query(
        'UPDATE provider_registry SET enabled = FALSE, updated_at = NOW() WHERE id = $1 RETURNING id, label, enabled',
        [req.params.id]
      );
      if (!rows.length) return res.status(404).json({ error: 'Not found' });
      res.json({ message: `Provider "${req.params.id}" disabled`, ...rows[0] });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ── POST /api/v1/registry/reload — Force cache refresh ──
  app.post('/api/v1/registry/reload', async (req, res) => {
    try {
      const registry = ProviderRegistry.getInstance();
      await registry.reload();
      res.json({ message: 'Registry reloaded', stats: registry.getStats() });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}

module.exports = { mountRegistryRoutes };
