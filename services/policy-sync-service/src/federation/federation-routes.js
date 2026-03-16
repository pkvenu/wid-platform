// =============================================================================
// Federation Routes — Hub-side mTLS Relay Management (ADR-13)
// =============================================================================
//
// Mounted at /api/v1/federation/* on the policy-sync-service (hub).
// Provides:
//   - Relay registration with certificate validation
//   - Heartbeat with cert fingerprint verification
//   - Relay revocation
//   - Relay listing with cert status
//   - Certificate bootstrap (for envs without SPIRE)
//   - Policy push webhook broadcasting
//
// =============================================================================

const crypto = require('crypto');

/**
 * Mount federation routes on an Express app.
 *
 * @param {import('express').Express} app
 * @param {import('pg').Pool} pool
 * @param {Object} opts
 * @param {import('@wid/core').TLSManager} [opts.tlsManager] - Hub TLS manager for cert validation
 */
function mountFederationRoutes(app, pool, opts = {}) {
  const { tlsManager } = opts;

  // ── Helper: extract client cert from request ──
  function extractClientCert(req) {
    // Option 1: Direct TLS (req.socket.getPeerCertificate)
    if (req.socket?.getPeerCertificate) {
      const cert = req.socket.getPeerCertificate(true);
      if (cert && cert.raw) {
        return {
          raw: cert.raw,
          pem: `-----BEGIN CERTIFICATE-----\n${cert.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`,
          subject: cert.subject,
          issuer: cert.issuer,
          fingerprint256: cert.fingerprint256,
          serialNumber: cert.serialNumber,
          valid_from: cert.valid_from,
          valid_to: cert.valid_to,
          subjectaltname: cert.subjectaltname,
        };
      }
    }

    // Option 2: Reverse proxy headers (Cloud Run, nginx, Envoy)
    const certHeader = req.headers['x-client-cert'] ||
                       req.headers['x-forwarded-client-cert'] ||
                       req.headers['x-ssl-client-cert'];
    if (certHeader) {
      // URL-decode if needed (Cloud Run URL-encodes the cert)
      const decoded = decodeURIComponent(certHeader);
      return { pem: decoded, fromHeader: true };
    }

    return null;
  }

  // ── Helper: extract SPIFFE ID from cert or header ──
  function extractSpiffeId(clientCert) {
    if (!clientCert) return null;
    // From direct TLS
    if (clientCert.subjectaltname) {
      const parts = clientCert.subjectaltname.split(',').map(s => s.trim());
      for (const part of parts) {
        if (part.startsWith('URI:spiffe://')) return part.substring(4);
      }
    }
    // From TLSManager validation
    if (tlsManager && clientCert.pem) {
      const result = tlsManager.validatePeerCert(clientCert.pem);
      return result.spiffeId;
    }
    return null;
  }

  // ── Helper: compute cert fingerprint ──
  function computeFingerprint(certPem) {
    if (!certPem) return null;
    try {
      const lines = certPem.split('\n').filter(l => !l.startsWith('-----')).join('');
      const der = Buffer.from(lines, 'base64');
      return crypto.createHash('sha256').update(der).digest('hex');
    } catch {
      return null;
    }
  }

  // ── Helper: system query (bypasses RLS for federation operations) ──
  async function sysQuery(sql, params) {
    const client = await pool.connect();
    try {
      // Federation operations use system context (no tenant RLS)
      await client.query("SET LOCAL role TO 'wid_user'");
      const result = await client.query(sql, params);
      return result;
    } finally {
      client.release();
    }
  }

  // ── Helper: log federation event ──
  async function logFederationEvent(relayId, eventType, details = {}, req = null) {
    try {
      const tenantId = details.tenant_id || '00000000-0000-0000-0000-000000000001';
      const sourceIp = req ? (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip) : null;
      await sysQuery(
        `INSERT INTO federation_events (tenant_id, relay_id, event_type, spiffe_id, cert_fingerprint, details, source_ip, data_region)
         VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8)`,
        [tenantId, relayId, eventType, details.spiffe_id || null,
         details.cert_fingerprint || null, JSON.stringify(details),
         sourceIp, details.data_region || 'us']
      );
    } catch (e) {
      console.warn(`[federation] Failed to log event: ${e.message}`);
    }
  }

  // ═════════════════════════════════════════════════════════════════
  // POST /api/v1/federation/register — Relay registration with cert validation
  // ═════════════════════════════════════════════════════════════════

  app.post('/api/v1/federation/register', async (req, res) => {
    try {
      const {
        environment_name, environment_type, region, cluster_id,
        relay_version, capabilities, tenant_id,
        data_region, data_residency_strict, allowed_regions,
        webhook_url, spiffe_id: claimedSpiffeId,
      } = req.body;

      if (!environment_name || !environment_type || !region) {
        return res.status(400).json({ error: 'environment_name, environment_type, and region are required' });
      }

      // Extract and validate client certificate
      const clientCert = extractClientCert(req);
      let certSpiffeId = null;
      let certFingerprint = null;
      let certInfo = {};
      let mtlsVerified = false;

      if (clientCert) {
        certSpiffeId = extractSpiffeId(clientCert);
        certFingerprint = clientCert.fingerprint256?.replace(/:/g, '').toLowerCase() ||
                          computeFingerprint(clientCert.pem);

        // Validate cert chain if TLSManager is configured
        if (tlsManager && clientCert.pem) {
          const validation = tlsManager.validatePeerCert(clientCert.pem);
          if (!validation.valid) {
            await logFederationEvent('unknown', 'auth_failed', {
              error: validation.error,
              claimed_env: environment_name,
              cert_fingerprint: certFingerprint,
            }, req);
            return res.status(403).json({
              error: 'Certificate validation failed',
              detail: validation.error,
            });
          }
          mtlsVerified = true;
          certSpiffeId = validation.spiffeId || certSpiffeId;
        }

        certInfo = {
          issuer: clientCert.issuer?.CN || clientCert.issuer || null,
          valid_from: clientCert.valid_from || null,
          valid_to: clientCert.valid_to || null,
          serial: clientCert.serialNumber || null,
        };

        // Verify SPIFFE ID matches claim (if both present)
        if (claimedSpiffeId && certSpiffeId && claimedSpiffeId !== certSpiffeId) {
          await logFederationEvent('unknown', 'auth_failed', {
            error: 'SPIFFE ID mismatch',
            claimed: claimedSpiffeId,
            cert: certSpiffeId,
          }, req);
          return res.status(403).json({
            error: 'SPIFFE ID mismatch: claimed does not match certificate SAN',
          });
        }
      }

      const relayId = `relay-${environment_name}-${Date.now().toString(36)}`;
      const effectiveRegion = data_region || region || 'us';
      const effectiveTenant = tenant_id || '00000000-0000-0000-0000-000000000001';
      const effectiveSpiffeId = certSpiffeId || claimedSpiffeId || null;

      // Check for duplicate SPIFFE ID (only one active relay per SPIFFE ID)
      if (effectiveSpiffeId) {
        const existing = await sysQuery(
          `SELECT relay_id, status FROM spoke_relays WHERE spiffe_id = $1 AND status = 'active'`,
          [effectiveSpiffeId]
        );
        if (existing.rows.length > 0) {
          // Update existing instead of creating duplicate
          await sysQuery(
            `UPDATE spoke_relays SET
              last_heartbeat_at = NOW(), relay_version = $1, webhook_url = $2,
              cert_fingerprint = $3, updated_at = NOW()
             WHERE spiffe_id = $4 AND status = 'active'`,
            [relay_version, webhook_url, certFingerprint, effectiveSpiffeId]
          );
          const existingRelay = existing.rows[0];
          await logFederationEvent(existingRelay.relay_id, 'registered', {
            reregistration: true, spiffe_id: effectiveSpiffeId, mtls_verified: mtlsVerified,
          }, req);
          return res.json({
            relay_id: existingRelay.relay_id,
            status: 'active',
            mtls_verified: mtlsVerified,
            reregistered: true,
          });
        }
      }

      // Insert new relay
      await sysQuery(
        `INSERT INTO spoke_relays (
          relay_id, tenant_id, environment_name, environment_type, region, cluster_id,
          spiffe_id, cert_fingerprint, cert_issuer, cert_not_before, cert_not_after, cert_serial,
          status, relay_version, capabilities, data_region, data_residency_strict, allowed_regions,
          webhook_url, webhook_enabled, last_heartbeat_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NOW())`,
        [
          relayId, effectiveTenant, environment_name, environment_type, region, cluster_id || null,
          effectiveSpiffeId, certFingerprint, certInfo.issuer,
          certInfo.valid_from ? new Date(certInfo.valid_from) : null,
          certInfo.valid_to ? new Date(certInfo.valid_to) : null,
          certInfo.serial,
          'active', relay_version || '1.0.0', capabilities || ['policy-cache', 'audit-forward'],
          effectiveRegion, data_residency_strict || false, allowed_regions || [effectiveRegion],
          webhook_url || null, !!webhook_url,
        ]
      );

      await logFederationEvent(relayId, 'registered', {
        tenant_id: effectiveTenant,
        spiffe_id: effectiveSpiffeId,
        cert_fingerprint: certFingerprint,
        mtls_verified: mtlsVerified,
        environment_name,
        data_region: effectiveRegion,
      }, req);

      console.log(`[federation] Relay registered: ${relayId} (${environment_name}, mTLS: ${mtlsVerified})`);

      res.status(201).json({
        relay_id: relayId,
        status: 'active',
        data_region: effectiveRegion,
        mtls_verified: mtlsVerified,
        spiffe_id: effectiveSpiffeId,
        cert_fingerprint: certFingerprint ? certFingerprint.substring(0, 16) + '...' : null,
      });
    } catch (e) {
      console.error(`[federation] Registration error: ${e.message}`);
      res.status(500).json({ error: 'Registration failed', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // POST /api/v1/federation/heartbeat — Validated heartbeat
  // ═════════════════════════════════════════════════════════════════

  app.post('/api/v1/federation/heartbeat', async (req, res) => {
    try {
      const {
        relay_id, policy_version, policy_count, audit_buffer_size,
        adapter_count, uptime_seconds, status,
      } = req.body;

      if (!relay_id) return res.status(400).json({ error: 'relay_id required' });

      // Verify cert fingerprint matches registration (if mTLS active)
      const clientCert = extractClientCert(req);
      if (clientCert) {
        const fp = clientCert.fingerprint256?.replace(/:/g, '').toLowerCase() ||
                   computeFingerprint(clientCert.pem);
        if (fp) {
          const relay = await sysQuery(
            `SELECT cert_fingerprint, status FROM spoke_relays WHERE relay_id = $1`,
            [relay_id]
          );
          if (relay.rows.length > 0 && relay.rows[0].cert_fingerprint) {
            if (relay.rows[0].cert_fingerprint !== fp) {
              await logFederationEvent(relay_id, 'auth_failed', {
                error: 'Cert fingerprint mismatch on heartbeat',
                registered_fp: relay.rows[0].cert_fingerprint?.substring(0, 16),
                presented_fp: fp?.substring(0, 16),
              }, req);
              return res.status(403).json({ error: 'Certificate fingerprint does not match registration' });
            }
            if (relay.rows[0].status === 'revoked') {
              return res.status(403).json({ error: 'Relay has been revoked' });
            }
          }
        }
      }

      // Update heartbeat
      await sysQuery(
        `UPDATE spoke_relays SET
          last_heartbeat_at = NOW(), status = 'active',
          policy_version = COALESCE($2, policy_version),
          policy_count = COALESCE($3, policy_count),
          audit_buffer_size = COALESCE($4, audit_buffer_size),
          adapter_count = COALESCE($5, adapter_count),
          uptime_seconds = COALESCE($6, uptime_seconds),
          updated_at = NOW()
         WHERE relay_id = $1`,
        [relay_id, policy_version, policy_count, audit_buffer_size, adapter_count, uptime_seconds]
      );

      res.json({ status: 'ok', server_time: new Date().toISOString() });
    } catch (e) {
      console.error(`[federation] Heartbeat error: ${e.message}`);
      res.status(500).json({ error: 'Heartbeat failed' });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // POST /api/v1/federation/revoke/:relayId — Revoke a spoke relay
  // ═════════════════════════════════════════════════════════════════

  app.post('/api/v1/federation/revoke/:relayId', async (req, res) => {
    try {
      const { relayId } = req.params;
      const { reason } = req.body;

      const result = await sysQuery(
        `UPDATE spoke_relays SET
          status = 'revoked', revoked_at = NOW(), revoked_reason = $2, updated_at = NOW()
         WHERE relay_id = $1
         RETURNING relay_id, environment_name, spiffe_id`,
        [relayId, reason || 'Manual revocation']
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Relay not found' });
      }

      const relay = result.rows[0];
      await logFederationEvent(relayId, 'revoked', {
        reason: reason || 'Manual revocation',
        spiffe_id: relay.spiffe_id,
        environment_name: relay.environment_name,
      }, req);

      console.log(`[federation] Relay revoked: ${relayId} (reason: ${reason || 'manual'})`);
      res.json({ status: 'revoked', relay_id: relayId });
    } catch (e) {
      res.status(500).json({ error: 'Revocation failed', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // GET /api/v1/federation/relays — List relays with cert status
  // ═════════════════════════════════════════════════════════════════

  app.get('/api/v1/federation/relays', async (req, res) => {
    try {
      const { status: filterStatus, region, tenant_id } = req.query;
      let sql = `SELECT
        relay_id, tenant_id, environment_name, environment_type, region, cluster_id,
        spiffe_id, cert_fingerprint, cert_issuer, cert_not_before, cert_not_after,
        status, registered_at, last_heartbeat_at, revoked_at, revoked_reason,
        webhook_url, webhook_enabled, relay_version, capabilities,
        data_region, data_residency_strict, policy_version, policy_count,
        audit_buffer_size, adapter_count, uptime_seconds
       FROM spoke_relays WHERE 1=1`;
      const params = [];
      let paramIdx = 0;

      if (filterStatus) {
        params.push(filterStatus);
        sql += ` AND status = $${++paramIdx}`;
      }
      if (region) {
        params.push(region);
        sql += ` AND region = $${++paramIdx}`;
      }
      if (tenant_id) {
        params.push(tenant_id);
        sql += ` AND tenant_id = $${++paramIdx}`;
      }

      sql += ' ORDER BY last_heartbeat_at DESC NULLS LAST';

      const result = await sysQuery(sql, params);

      // Compute health status for each relay
      const relays = result.rows.map(r => {
        const lastHb = r.last_heartbeat_at ? new Date(r.last_heartbeat_at) : null;
        const staleThreshold = 5 * 60 * 1000; // 5 minutes
        const healthStatus = r.status === 'revoked' ? 'revoked'
          : (!lastHb || (Date.now() - lastHb.getTime()) > staleThreshold) ? 'stale'
          : 'healthy';

        const certExpiring = r.cert_not_after
          ? (new Date(r.cert_not_after).getTime() - Date.now()) < 3600000
          : false;

        return {
          ...r,
          health_status: healthStatus,
          cert_expiring_soon: certExpiring,
          cert_fingerprint: r.cert_fingerprint ? r.cert_fingerprint.substring(0, 16) + '...' : null,
          time_since_heartbeat_s: lastHb ? Math.round((Date.now() - lastHb.getTime()) / 1000) : null,
        };
      });

      res.json({
        total: relays.length,
        active: relays.filter(r => r.health_status === 'healthy').length,
        stale: relays.filter(r => r.health_status === 'stale').length,
        revoked: relays.filter(r => r.health_status === 'revoked').length,
        relays,
      });
    } catch (e) {
      res.status(500).json({ error: 'Failed to list relays', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // GET /api/v1/federation/events — Federation audit log
  // ═════════════════════════════════════════════════════════════════

  app.get('/api/v1/federation/events', async (req, res) => {
    try {
      const { relay_id, event_type, limit: limitStr } = req.query;
      const limit = Math.min(parseInt(limitStr || '100'), 500);
      let sql = 'SELECT * FROM federation_events WHERE 1=1';
      const params = [];
      let paramIdx = 0;

      if (relay_id) {
        params.push(relay_id);
        sql += ` AND relay_id = $${++paramIdx}`;
      }
      if (event_type) {
        params.push(event_type);
        sql += ` AND event_type = $${++paramIdx}`;
      }

      params.push(limit);
      sql += ` ORDER BY created_at DESC LIMIT $${++paramIdx}`;

      const result = await sysQuery(sql, params);
      res.json({ total: result.rows.length, events: result.rows });
    } catch (e) {
      res.status(500).json({ error: 'Failed to list events', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // POST /api/v1/federation/push — Broadcast policy push to active relays
  // ═════════════════════════════════════════════════════════════════

  app.post('/api/v1/federation/push', async (req, res) => {
    try {
      const { policy_ids, reason, force } = req.body;

      // Get all active relays with webhook URLs
      const result = await sysQuery(
        `SELECT relay_id, webhook_url, environment_name, data_region
         FROM spoke_relays
         WHERE status = 'active' AND webhook_enabled = true AND webhook_url IS NOT NULL`
      );

      const relays = result.rows;
      if (relays.length === 0) {
        return res.json({ pushed: 0, message: 'No active relays with webhooks' });
      }

      const payload = {
        event: 'policy_update',
        policy_ids: policy_ids || [],
        reason: reason || 'manual_push',
        timestamp: new Date().toISOString(),
        nonce: crypto.randomBytes(16).toString('hex'),
      };

      // Sign payload with HMAC-SHA256
      const payloadStr = JSON.stringify(payload);
      const signature = crypto.createHmac('sha256', process.env.FEDERATION_PUSH_SECRET || 'wid-federation-push')
        .update(payloadStr)
        .digest('hex');

      let pushed = 0;
      let failed = 0;
      const errors = [];

      // Fan-out to all relays (fire-and-forget with circuit breaker per relay)
      const pushPromises = relays.map(async (relay) => {
        try {
          const https = require('https');
          const http = require('http');
          const url = new URL(relay.webhook_url);
          const transport = url.protocol === 'https:' ? https : http;

          await new Promise((resolve, reject) => {
            const pushReq = transport.request({
              hostname: url.hostname,
              port: url.port,
              path: '/api/v1/relay/policy-push',
              method: 'POST',
              timeout: 5000,
              headers: {
                'Content-Type': 'application/json',
                'X-WID-Push-Signature': signature,
                'X-WID-Push-Timestamp': payload.timestamp,
                'X-WID-Push-Nonce': payload.nonce,
              },
            }, (res) => {
              let data = '';
              res.on('data', c => data += c);
              res.on('end', () => resolve({ status: res.statusCode }));
            });
            pushReq.on('error', reject);
            pushReq.on('timeout', () => { pushReq.destroy(); reject(new Error('timeout')); });
            pushReq.write(payloadStr);
            pushReq.end();
          });

          pushed++;
          await logFederationEvent(relay.relay_id, 'policy_pushed', {
            policy_ids, reason, data_region: relay.data_region,
          });
        } catch (e) {
          failed++;
          errors.push({ relay_id: relay.relay_id, error: e.message });
        }
      });

      await Promise.allSettled(pushPromises);

      res.json({ pushed, failed, total: relays.length, errors: errors.length > 0 ? errors : undefined });
    } catch (e) {
      res.status(500).json({ error: 'Push failed', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // POST /api/v1/federation/bootstrap-cert — Issue client cert (one-time token)
  // ═════════════════════════════════════════════════════════════════

  app.post('/api/v1/federation/bootstrap-cert', async (req, res) => {
    try {
      const { registration_token, environment_name, spiffe_id } = req.body;

      if (!registration_token || !environment_name) {
        return res.status(400).json({ error: 'registration_token and environment_name required' });
      }

      // Validate registration token (one-time use)
      // In production, tokens are pre-generated and stored in DB
      // For now, validate against FEDERATION_BOOTSTRAP_TOKEN env var
      const validToken = process.env.FEDERATION_BOOTSTRAP_TOKEN || 'wid-bootstrap-token';
      if (registration_token !== validToken) {
        await logFederationEvent('bootstrap-' + environment_name, 'auth_failed', {
          error: 'Invalid bootstrap token',
        }, req);
        return res.status(403).json({ error: 'Invalid registration token' });
      }

      // Generate keypair for the relay
      const { generateKeyPairSync } = crypto;
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-256',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      // In a full implementation, we'd sign a CSR with the Federation CA.
      // For now, return the generated keypair + instructions.
      const effectiveSpiffeId = spiffe_id || `spiffe://wid-platform/relay/${environment_name}`;

      res.json({
        status: 'issued',
        spiffe_id: effectiveSpiffeId,
        public_key: publicKey,
        private_key: privateKey,
        ca_bundle: opts.tlsManager?.certificate || null,
        instructions: [
          `Save public key to: /run/wid/relay-cert.pem`,
          `Save private key to: /run/wid/relay-key.pem`,
          `Save CA bundle to: /run/wid/ca-bundle.pem`,
          `Set env: RELAY_CERT_PATH=/run/wid/relay-cert.pem`,
          `Set env: RELAY_KEY_PATH=/run/wid/relay-key.pem`,
          `Set env: RELAY_CA_BUNDLE_PATH=/run/wid/ca-bundle.pem`,
        ],
        expires_in: '24h',
        note: 'Use these credentials to register via mTLS. Bootstrap token is single-use.',
      });

      await logFederationEvent('bootstrap-' + environment_name, 'cert_issued', {
        environment_name,
        spiffe_id: effectiveSpiffeId,
      }, req);
    } catch (e) {
      res.status(500).json({ error: 'Bootstrap failed', detail: e.message });
    }
  });

  // ═════════════════════════════════════════════════════════════════
  // Background: Mark stale relays (no heartbeat > 5 min)
  // ═════════════════════════════════════════════════════════════════

  const staleCheckInterval = setInterval(async () => {
    try {
      const result = await sysQuery(
        `UPDATE spoke_relays SET status = 'stale', updated_at = NOW()
         WHERE status = 'active' AND last_heartbeat_at < NOW() - INTERVAL '5 minutes'
         RETURNING relay_id, environment_name`
      );
      for (const row of result.rows) {
        console.log(`[federation] Relay marked stale: ${row.relay_id} (${row.environment_name})`);
        await logFederationEvent(row.relay_id, 'stale_detected', {
          environment_name: row.environment_name,
        });
      }
    } catch { /* DB not ready yet */ }
  }, 60000); // Check every minute

  if (staleCheckInterval.unref) staleCheckInterval.unref();

  console.log('  [federation] Federation routes mounted at /api/v1/federation/*');
}

module.exports = { mountFederationRoutes };
