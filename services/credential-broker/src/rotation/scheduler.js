// =============================================================================
// Rotation Scheduler — Evaluate, schedule, and execute credential rotations
// =============================================================================
// Periodically checks credential_usage + credential_rotations for stale
// credentials. Dispatches rotation to the appropriate provider.
// Tracks all rotation events in the credential_rotations table.
// =============================================================================

class RotationScheduler {
  constructor(dbClient, providerManager, config = {}) {
    this.db = dbClient;
    this.providers = providerManager;
    this.defaultMaxAgeDays = config.defaultMaxAgeDays || 90;
    this.evaluationInterval = config.evaluationInterval || 3600000; // 1 hour
    this._timer = null;
    // Per-secret rotation policies loaded from DB at startup
    this._policies = new Map(); // credential_path -> { max_age_days, auto_rotate, provider, notify_before_days }
  }

  // ── Start / Stop ──────────────────────────────────────────────────────

  start() {
    console.log(`[RotationScheduler] Started (eval every ${this.evaluationInterval / 1000}s, max age ${this.defaultMaxAgeDays}d)`);
    // Load policies then run initial evaluation after 30s
    setTimeout(async () => {
      try {
        await this.loadPolicies();
        await this.evaluateAll();
      } catch (e) {
        console.warn('[RotationScheduler] Initial startup failed:', e.message);
      }
    }, 30000);
    this._timer = setInterval(async () => {
      try {
        await this.loadPolicies();
        await this.evaluateAll();
      } catch (e) {
        console.warn('[RotationScheduler] Periodic evaluation failed:', e.message);
      }
    }, this.evaluationInterval);
  }

  stop() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
  }

  // ── Evaluate all credentials for staleness ────────────────────────────

  async evaluateAll() {
    if (!this.db) return { evaluated: 0, scheduled: 0 };

    // Find credentials that haven't been rotated in > maxAgeDays
    // Uses credential_usage to find actively-used credentials and their last rotation
    try {
      const { rows } = await this.db.query(`
        SELECT DISTINCT target_api,
               MIN(accessed_at) as first_seen,
               MAX(accessed_at) as last_seen,
               COUNT(*) as access_count
        FROM credential_usage
        WHERE result = 'allowed'
        GROUP BY target_api
      `);

      // Check each against existing rotations
      let scheduled = 0;
      for (const cred of rows) {
        const stale = await this.isStale(cred.target_api);
        if (stale) {
          // Only schedule if not already pending
          const existing = await this.db.query(
            `SELECT id FROM credential_rotations
             WHERE credential_path = $1 AND status IN ('pending', 'in_progress')
             LIMIT 1`,
            [cred.target_api]
          );
          if (existing.rows.length === 0) {
            await this.scheduleRotation(cred.target_api, 'schedule');
            scheduled++;
          }
        }
      }

      if (scheduled > 0) {
        console.log(`[RotationScheduler] Evaluated ${rows.length} credentials, scheduled ${scheduled} rotations`);
      }
      return { evaluated: rows.length, scheduled };
    } catch (e) {
      console.warn('[RotationScheduler] Evaluation error:', e.message);
      return { evaluated: 0, scheduled: 0 };
    }
  }

  // ── Check if a credential is stale ────────────────────────────────────

  async isStale(credentialPath) {
    if (!this.db) return false;
    const maxAge = this.getMaxAgeDays(credentialPath);

    try {
      const { rows } = await this.db.query(
        `SELECT executed_at FROM credential_rotations
         WHERE credential_path = $1 AND status = 'completed'
         ORDER BY executed_at DESC LIMIT 1`,
        [credentialPath]
      );

      if (rows.length === 0) {
        // Never rotated — check first usage
        const { rows: usage } = await this.db.query(
          `SELECT MIN(accessed_at) as first_seen FROM credential_usage
           WHERE target_api = $1 AND result = 'allowed'`,
          [credentialPath]
        );
        if (!usage[0]?.first_seen) return false;
        const ageDays = (Date.now() - new Date(usage[0].first_seen).getTime()) / 86400000;
        return ageDays > maxAge;
      }

      const lastRotation = new Date(rows[0].executed_at);
      const ageDays = (Date.now() - lastRotation.getTime()) / 86400000;
      return ageDays > maxAge;
    } catch {
      return false;
    }
  }

  // ── Schedule a rotation ───────────────────────────────────────────────

  async scheduleRotation(credentialPath, triggeredBy = 'manual', opts = {}) {
    if (!this.db) throw new Error('Database not connected');

    const provider = opts.provider || this._detectProvider(credentialPath);
    const scheduledAt = opts.scheduledAt || new Date();

    const { rows } = await this.db.query(`
      INSERT INTO credential_rotations
        (credential_path, provider, workload_id, status, triggered_by, scheduled_at)
      VALUES ($1, $2, $3, 'pending', $4, $5)
      RETURNING *
    `, [credentialPath, provider, opts.workloadId || null, triggeredBy, scheduledAt]);

    console.log(`[RotationScheduler] Scheduled rotation #${rows[0].id}: ${credentialPath} (${provider})`);
    return rows[0];
  }

  // ── Execute a rotation ────────────────────────────────────────────────

  async executeRotation(rotationId, newValue) {
    if (!this.db) throw new Error('Database not connected');

    // Load rotation record
    const { rows } = await this.db.query(
      'SELECT * FROM credential_rotations WHERE id = $1', [rotationId]
    );
    if (!rows.length) throw new Error(`Rotation #${rotationId} not found`);
    const rotation = rows[0];

    if (rotation.status !== 'pending') {
      throw new Error(`Rotation #${rotationId} is ${rotation.status}, expected pending`);
    }

    // Mark in-progress
    await this.db.query(
      `UPDATE credential_rotations SET status = 'in_progress', executed_at = NOW() WHERE id = $1`,
      [rotationId]
    );

    try {
      const providerKey = rotation.provider;
      const result = await this.providers.rotateSecret(providerKey, rotation.credential_path, newValue);

      // Mark completed
      await this.db.query(
        `UPDATE credential_rotations
         SET status = 'completed', old_version = $2, new_version = $3
         WHERE id = $1`,
        [rotationId, result.oldVersion || null, result.newVersion || null]
      );

      console.log(`[RotationScheduler] Rotation #${rotationId} completed: ${rotation.credential_path}`);
      return { id: rotationId, status: 'completed', ...result };
    } catch (error) {
      // Mark failed
      await this.db.query(
        `UPDATE credential_rotations SET status = 'failed', error_message = $2 WHERE id = $1`,
        [rotationId, error.message]
      );
      console.error(`[RotationScheduler] Rotation #${rotationId} failed:`, error.message);
      throw error;
    }
  }

  // ── Revoke a credential ───────────────────────────────────────────────

  async revokeCredential(credentialPath, provider, version) {
    const providerKey = provider || this._detectProvider(credentialPath);
    const result = await this.providers.revokeSecret(providerKey, credentialPath, version);

    // Log the revocation
    if (this.db) {
      await this.db.query(`
        INSERT INTO credential_rotations
          (credential_path, provider, status, triggered_by, executed_at)
        VALUES ($1, $2, 'completed', 'revoke', NOW())
      `, [credentialPath, providerKey]).catch(() => {});
    }

    return result;
  }

  // ── Query rotation history ────────────────────────────────────────────

  async getHistory(credentialPath, limit = 20) {
    if (!this.db) return [];
    const { rows } = await this.db.query(
      `SELECT * FROM credential_rotations
       WHERE credential_path = $1
       ORDER BY created_at DESC LIMIT $2`,
      [credentialPath, limit]
    );
    return rows;
  }

  async getRotation(rotationId) {
    if (!this.db) return null;
    const { rows } = await this.db.query(
      'SELECT * FROM credential_rotations WHERE id = $1', [rotationId]
    );
    return rows[0] || null;
  }

  async listPending() {
    if (!this.db) return [];
    const { rows } = await this.db.query(
      `SELECT * FROM credential_rotations
       WHERE status IN ('pending', 'in_progress')
       ORDER BY scheduled_at ASC`
    );
    return rows;
  }

  // ── Stale credentials query ───────────────────────────────────────────

  async getStaleCredentials(maxAgeDays) {
    if (!this.db) return [];
    const days = maxAgeDays || this.defaultMaxAgeDays;

    const { rows } = await this.db.query(`
      SELECT cu.target_api as credential_path,
             MIN(cu.accessed_at) as first_seen,
             MAX(cu.accessed_at) as last_used,
             COUNT(*) as total_accesses,
             cr.executed_at as last_rotated,
             COALESCE(
               EXTRACT(EPOCH FROM (NOW() - cr.executed_at)) / 86400,
               EXTRACT(EPOCH FROM (NOW() - MIN(cu.accessed_at))) / 86400
             ) as age_days
      FROM credential_usage cu
      LEFT JOIN LATERAL (
        SELECT executed_at FROM credential_rotations
        WHERE credential_path = cu.target_api AND status = 'completed'
        ORDER BY executed_at DESC LIMIT 1
      ) cr ON true
      WHERE cu.result = 'allowed'
      GROUP BY cu.target_api, cr.executed_at
      HAVING COALESCE(
        EXTRACT(EPOCH FROM (NOW() - cr.executed_at)) / 86400,
        EXTRACT(EPOCH FROM (NOW() - MIN(cu.accessed_at))) / 86400
      ) > $1
      ORDER BY age_days DESC
    `, [days]);

    return rows;
  }

  // ── Cross-provider migration ──────────────────────────────────────────

  async migrateCredential(fromProvider, toProvider, credentialPath, opts = {}) {
    // Read from source
    const sourceProvider = this.providers.getProvider(fromProvider);
    if (!sourceProvider?.enabled) throw new Error(`Source provider "${fromProvider}" not available`);

    const value = await sourceProvider.getSecret(credentialPath);
    if (!value) throw new Error(`Secret "${credentialPath}" not found in ${fromProvider}`);

    // Write to destination
    const targetPath = opts.targetPath || credentialPath;
    const result = await this.providers.putSecret(toProvider, targetPath, value);

    // Log migration
    if (this.db) {
      await this.db.query(`
        INSERT INTO credential_rotations
          (credential_path, provider, status, triggered_by, old_version, new_version, executed_at)
        VALUES ($1, $2, 'completed', 'migration', $3, $4, NOW())
      `, [targetPath, toProvider, `${fromProvider}:${credentialPath}`, result.version]).catch(() => {});
    }

    console.log(`[RotationScheduler] Migrated ${credentialPath}: ${fromProvider} → ${toProvider}`);
    return {
      source: { provider: fromProvider, path: credentialPath },
      destination: { provider: toProvider, path: targetPath, version: result.version },
    };
  }

  // ── Rotation Policies ────────────────────────────────────────────────

  async loadPolicies() {
    if (!this.db) return;
    try {
      const { rows } = await this.db.query(
        'SELECT * FROM rotation_policies WHERE enabled = true'
      );
      this._policies.clear();
      for (const row of rows) {
        this._policies.set(row.credential_path, {
          id: row.id,
          max_age_days: row.max_age_days,
          auto_rotate: row.auto_rotate,
          provider: row.provider,
          notify_before_days: row.notify_before_days,
          created_at: row.created_at,
        });
      }
      if (rows.length > 0) {
        console.log(`[RotationScheduler] Loaded ${rows.length} rotation policies`);
      }
    } catch (e) {
      // Table may not exist yet — that is fine
      if (!e.message.includes('does not exist')) {
        console.warn('[RotationScheduler] Failed to load policies:', e.message);
      }
    }
  }

  getPolicyForPath(credentialPath) {
    // Exact match first, then prefix match
    if (this._policies.has(credentialPath)) return this._policies.get(credentialPath);
    for (const [pattern, policy] of this._policies) {
      if (pattern.endsWith('*') && credentialPath.startsWith(pattern.slice(0, -1))) {
        return policy;
      }
    }
    return null;
  }

  getMaxAgeDays(credentialPath) {
    const policy = this.getPolicyForPath(credentialPath);
    return policy?.max_age_days || this.defaultMaxAgeDays;
  }

  async setPolicy(credentialPath, opts = {}) {
    if (!this.db) throw new Error('Database not connected');
    const maxAgeDays = opts.max_age_days || this.defaultMaxAgeDays;
    const autoRotate = opts.auto_rotate !== undefined ? opts.auto_rotate : true;
    const provider = opts.provider || this._detectProvider(credentialPath);
    const notifyBeforeDays = opts.notify_before_days || 7;

    const { rows } = await this.db.query(`
      INSERT INTO rotation_policies
        (credential_path, provider, max_age_days, auto_rotate, notify_before_days)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (credential_path) DO UPDATE SET
        provider = EXCLUDED.provider,
        max_age_days = EXCLUDED.max_age_days,
        auto_rotate = EXCLUDED.auto_rotate,
        notify_before_days = EXCLUDED.notify_before_days,
        updated_at = NOW()
      RETURNING *
    `, [credentialPath, provider, maxAgeDays, autoRotate, notifyBeforeDays]);

    // Update in-memory cache
    const row = rows[0];
    this._policies.set(credentialPath, {
      id: row.id,
      max_age_days: row.max_age_days,
      auto_rotate: row.auto_rotate,
      provider: row.provider,
      notify_before_days: row.notify_before_days,
      created_at: row.created_at,
    });

    console.log(`[RotationScheduler] Policy set: ${credentialPath} (${maxAgeDays}d, auto=${autoRotate})`);
    return row;
  }

  async deletePolicy(credentialPath) {
    if (!this.db) throw new Error('Database not connected');
    await this.db.query('DELETE FROM rotation_policies WHERE credential_path = $1', [credentialPath]);
    this._policies.delete(credentialPath);
  }

  async listPolicies() {
    if (!this.db) return [];
    const { rows } = await this.db.query('SELECT * FROM rotation_policies ORDER BY credential_path');
    return rows;
  }

  // ── Rotation status summary ─────────────────────────────────────────

  async getRotationStatus() {
    if (!this.db) return { policies: [], pending: [], recent: [] };

    const [policies, pending, recent] = await Promise.all([
      this.listPolicies(),
      this.listPending(),
      this.db.query(`
        SELECT credential_path, provider, status, old_version, new_version,
               triggered_by, executed_at, created_at
        FROM credential_rotations
        WHERE executed_at > NOW() - INTERVAL '30 days'
        ORDER BY executed_at DESC LIMIT 50
      `).then(r => r.rows).catch(() => []),
    ]);

    return { policies, pending, recent };
  }

  // ── Helpers ───────────────────────────────────────────────────────────

  _detectProvider(credentialPath) {
    // Guess provider from path conventions
    if (credentialPath.startsWith('credentials/') || credentialPath.startsWith('secret/')) {
      return 'hashicorp-vault';
    }
    if (credentialPath.startsWith('arn:aws:')) return 'aws-secrets-manager';
    if (credentialPath.startsWith('projects/')) return 'gcp-secret-manager';
    // Default to first available provider
    const first = this.providers.getProviderForPath(credentialPath);
    return first?.key || 'hashicorp-vault';
  }
}

module.exports = { RotationScheduler };
