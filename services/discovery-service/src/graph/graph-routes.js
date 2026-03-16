// =============================================================================
// Graph Routes — Identity Graph API
// =============================================================================
// Mount on the discovery service Express app:
//   const { mountGraphRoutes } = require('./graph/graph-routes');
//   mountGraphRoutes(app, dbClient);
//
// Endpoints:
//   GET  /api/v1/graph           → Full identity graph + attack paths
//   GET  /api/v1/graph/paths     → Attack paths only
//   GET  /api/v1/graph/timeline  → Unified timeline (graph + policies + events)
//   POST /api/v1/graph/scan      → Trigger relationship scan
// =============================================================================

const RelationshipScanner = require('./relationship-scanner');
const { calculateSecurityScore, determineTrustLevel, applyFindingPenalties } = require('../utils/security-scorer');
const { detectCategory } = require('./categorizer');
const { RemediationRenderer } = require('./remediation-renderer');
const { RemediationExecutor } = require('./remediation-executor');

// Tenant-scoped in-memory cache (rebuilt on each scan)
const graphCaches = new Map(); // tenantId → { data, scanTime }

function getGraphCache(tenantId) {
  const entry = graphCaches.get(tenantId || '_system');
  if (!entry) return { data: null, scanTime: null };
  return { data: entry.data, scanTime: entry.scanTime };
}

function setGraphCache(tenantId, data, scanTime) {
  graphCaches.set(tenantId || '_system', { data, scanTime });
}

// ── Cold-start: load last graph from DB so first GET /graph is not empty ──
// At startup there is no req context, so we use pool.query directly (system-level)
async function warmGraphCache(pool) {
  try {
    const row = await pool.query("SELECT graph_data, generated_at FROM identity_graph WHERE id = 'latest' LIMIT 1");
    if (row.rows.length > 0 && row.rows[0].graph_data) {
      const data = typeof row.rows[0].graph_data === 'string'
        ? JSON.parse(row.rows[0].graph_data) : row.rows[0].graph_data;
      const age = Date.now() - new Date(row.rows[0].generated_at).getTime();
      if (age < 30 * 60 * 1000) { // 30-minute TTL
        setGraphCache('_system', data, row.rows[0].generated_at);
        console.log(`[graph] Cache warm: ${data.nodes?.length || 0} nodes, ${data.relationships?.length || 0} edges (age ${Math.round(age/1000)}s)`);
      }
    }
  } catch (e) { /* identity_graph table may not exist yet */ }
}

function mountGraphRoutes(app, pool) {
  // DB helper: use tenant-scoped req.db when available, fall back to pool
  const db = (req) => req.db || { query: (text, params) => pool.query(text, params) };

  warmGraphCache(pool).catch(() => {});

  // Seed remediation intents from CONTROL_CATALOG (idempotent) — system-level, use pool
  seedRemediationIntents(pool).catch(e =>
    console.log(`  [seed] Remediation seed skipped: ${e.message}`)
  );

  // Seed finding type metadata (idempotent)
  seedFindingTypeMetadata(pool).catch(e =>
    console.log(`  [seed] Finding type metadata seed skipped: ${e.message}`)
  );

  // Seed provider registry from defaults + initialize singleton (idempotent)
  seedProviderRegistry(pool).catch(e =>
    console.log(`  [seed] Provider registry seed skipped: ${e.message}`)
  );

  // ── GET /api/v1/graph — Full identity graph ──
  app.get('/api/v1/graph', async (req, res) => {
    try {
      const tenantId = req.tenantId || '_system';
      const { data: cachedGraph, scanTime } = getGraphCache(tenantId);
      let graphResult;
      if (cachedGraph) {
        graphResult = { ...cachedGraph, cached: true, last_scan: scanTime };
      } else {
        graphResult = await buildGraph(pool);
      }

      // Enrich attack paths with remediation status from deployed policies
      try {
        const polRes = await db(req).query(
          `SELECT p.id, p.template_id, p.enforcement_mode, p.enabled, p.name,
                  p.client_workload_id, p.attack_path_id,
                  p.last_evaluated, p.evaluation_count,
                  (SELECT COUNT(*) FROM policy_violations v WHERE v.policy_id = p.id AND v.status = 'open') as open_violations
           FROM policies p WHERE p.template_id IS NOT NULL AND p.enabled = true`
        );
        const deployedPolicies = polRes.rows;

        // Load finding → template mappings
        let findingMap = {};
        try {
          const frmRes = await db(req).query('SELECT finding_type, template_id FROM finding_remediation_map');
          for (const row of frmRes.rows) {
            if (!findingMap[row.finding_type]) findingMap[row.finding_type] = [];
            findingMap[row.finding_type].push(row.template_id);
          }
        } catch (e) { /* table might not exist */ }

        // Build workload name → DB UUID map for scoped policy matching
        const workloadNameToId = {};
        if (graphResult.nodes) {
          for (const n of graphResult.nodes) {
            if (n.workload_id) workloadNameToId[(n.label || '').toLowerCase()] = n.workload_id;
          }
        }

        // Annotate each attack path
        if (graphResult.attack_paths) {
          for (const ap of graphResult.attack_paths) {
            const ft = ap.finding_type;
            if (!ft) continue;
            const relevantTemplateIds = findingMap[ft] || [];
            const matchedPolicies = deployedPolicies.filter(p => {
              if (!relevantTemplateIds.includes(p.template_id)) return false;
              // Skip globally-scoped policies — they enforce on the gateway but
              // shouldn't clutter the graph (e.g. compliance pack deploys)
              if (!p.client_workload_id && !p.attack_path_id) return false;
              // Scoped to a specific attack path — must match this path's id
              if (p.attack_path_id && p.attack_path_id !== ap.id) return false;
              // Scoped to a specific workload — must match this path's workload
              if (p.client_workload_id) {
                const apWorkloadId = workloadNameToId[(ap.workload || '').toLowerCase()];
                if (!apWorkloadId || p.client_workload_id !== apWorkloadId) return false;
              }
              return true;
            });

            if (matchedPolicies.length > 0) {
              const enforcing = matchedPolicies.filter(p => p.enforcement_mode === 'enforce');
              const auditing = matchedPolicies.filter(p => p.enforcement_mode === 'audit');
              ap.remediation = {
                status: enforcing.length > 0 ? 'enforced' : 'audit',
                policies: matchedPolicies.map(p => ({
                  id: p.id, name: p.name, mode: p.enforcement_mode,
                  open_violations: parseInt(p.open_violations) || 0,
                  last_evaluated: p.last_evaluated,
                })),
                enforcing_count: enforcing.length,
                audit_count: auditing.length,
                total_open_violations: matchedPolicies.reduce((s, p) => s + (parseInt(p.open_violations) || 0), 0),
              };
            }

            // Enrich with scored controls if missing (cached graph won't have them)
            if (!ap.ranked_controls || ap.ranked_controls.length === 0) {
              const allNodes = graphResult.nodes || [];
              const allRels = graphResult.relationships || [];
              ap.ranked_controls = await scoreControlsAsync(ap, allNodes, allRels, pool);
              if (!ap.credential_chain || ap.credential_chain.length === 0) {
                ap.credential_chain = computeCredentialChain(ap, allNodes, allRels);
              }
            }
          }

          // Update summary with remediation stats
          const remediatedPaths = graphResult.attack_paths.filter(ap => ap.remediation);
          const enforcedPaths = graphResult.attack_paths.filter(ap => ap.remediation?.status === 'enforced');
          graphResult.summary = {
            ...graphResult.summary,
            remediated_paths: remediatedPaths.length,
            enforced_paths: enforcedPaths.length,
            unmitigated_paths: graphResult.attack_paths.length - remediatedPaths.length,
          };
        }
      } catch (e) {
        console.error('Attack path enrichment error:', e.message);
        // Non-fatal — return graph without enrichment
      }

      res.json(graphResult);
    } catch (error) {
      console.error('Graph error:', error);
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/paths — Attack paths only ──
  app.get('/api/v1/graph/paths', async (req, res) => {
    try {
      const tenantId = req.tenantId || '_system';
      const { data: cachedGraph, scanTime } = getGraphCache(tenantId);
      if (cachedGraph) {
        return res.json({
          attack_paths: cachedGraph.attack_paths,
          summary: cachedGraph.summary,
          last_scan: scanTime,
        });
      }
      const graph = await buildGraph(pool);
      res.json({ attack_paths: graph.attack_paths, summary: graph.summary });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/timeline — Unified story timeline ──
  // Merges: graph relationships + OPA policies + auth events + attestation events
  app.get('/api/v1/graph/timeline', async (req, res) => {
    try {
      const { workload_id, limit = 50 } = req.query;
      const timeline = [];

      // 1. Attestation events
      try {
        const attestQ = workload_id
          ? `SELECT id, spiffe_id AS workload_id, name, trust_level, verification_method,
                    attestation_data, last_attestation AS timestamp, 'attestation' AS event_type
             FROM workloads WHERE id = $1 AND last_attestation IS NOT NULL`
          : `SELECT id, spiffe_id AS workload_id, name, trust_level, verification_method,
                    attestation_data, last_attestation AS timestamp, 'attestation' AS event_type
             FROM workloads WHERE last_attestation IS NOT NULL
             ORDER BY last_attestation DESC LIMIT $1`;
        const params = workload_id ? [workload_id] : [Math.min(limit, 100)];
        const attestRes = await db(req).query(attestQ, params);
        for (const row of attestRes.rows) {
          timeline.push({
            type: 'attestation',
            timestamp: row.timestamp,
            workload_id: row.workload_id,
            workload_name: row.name,
            summary: `${row.name} attested at trust level: ${row.trust_level}`,
            detail: {
              trust_level: row.trust_level,
              method: row.verification_method,
              data: row.attestation_data,
            },
            severity: row.trust_level === 'cryptographic' ? 'info' : row.trust_level === 'none' ? 'critical' : 'low',
            icon: 'shield',
          });
        }
      } catch (e) { /* table might not exist yet */ }

      // 2. Authorization events (from audit log if available)
      try {
        const authQ = workload_id
          ? `SELECT * FROM authorization_events WHERE workload_id = $1 ORDER BY timestamp DESC LIMIT $2`
          : `SELECT * FROM authorization_events ORDER BY timestamp DESC LIMIT $1`;
        const authParams = workload_id ? [workload_id, limit] : [Math.min(limit, 100)];
        const authRes = await db(req).query(authQ, authParams);
        for (const row of authRes.rows) {
          // Check if this event violates any policy
          const isViolation = row.decision === 'deny' || row.policy_violated;
          timeline.push({
            type: 'authorization',
            timestamp: row.timestamp,
            workload_id: row.workload_id,
            workload_name: row.workload_name || row.source_identity,
            summary: `${row.source_identity || 'Unknown'} → ${row.target_resource || row.action}: ${row.decision}`,
            detail: {
              source: row.source_identity,
              target: row.target_resource,
              action: row.action,
              decision: row.decision,
              policy: row.policy_name,
              reason: row.reason,
            },
            severity: isViolation ? 'high' : 'info',
            icon: isViolation ? 'alert-triangle' : 'check-circle',
            violation: isViolation,
          });
        }
      } catch (e) { /* table might not exist yet */ }

      // 3. Policy evaluations
      try {
        const polQ = workload_id
          ? `SELECT * FROM policy_evaluations WHERE workload_id = $1 ORDER BY evaluated_at DESC LIMIT $2`
          : `SELECT * FROM policy_evaluations ORDER BY evaluated_at DESC LIMIT $1`;
        const polParams = workload_id ? [workload_id, limit] : [Math.min(limit, 100)];
        const polRes = await db(req).query(polQ, polParams);
        for (const row of polRes.rows) {
          timeline.push({
            type: 'policy',
            timestamp: row.evaluated_at,
            workload_id: row.workload_id,
            workload_name: row.workload_name,
            summary: `Policy "${row.policy_name}": ${row.result}`,
            detail: {
              policy_name: row.policy_name,
              result: row.result,
              violations: row.violations,
            },
            severity: row.result === 'fail' ? 'high' : 'info',
            icon: row.result === 'fail' ? 'x-circle' : 'check',
          });
        }
      } catch (e) { /* table might not exist yet */ }

      // 4. Graph findings (attack paths as events)
      const { data: timelineGraphCache } = getGraphCache(req.tenantId || '_system');
      if (timelineGraphCache) {
        for (const ap of timelineGraphCache.attack_paths) {
          timeline.push({
            type: 'graph_finding',
            timestamp: timelineGraphCache.generated_at,
            summary: ap.title,
            detail: {
              description: ap.description,
              blast_radius: ap.blast_radius,
              entry_points: ap.entry_points,
              sensitive_targets: ap.sensitive_targets,
            },
            severity: ap.severity,
            icon: 'git-branch',
          });
        }
      }

      // Sort by timestamp descending
      timeline.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));

      res.json({
        total: timeline.length,
        timeline: timeline.slice(0, Math.min(limit, 200)),
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/scan — Trigger relationship scan ──
  app.post('/api/v1/graph/scan', async (req, res) => {
    try {
      const graph = await buildGraph(pool);

      // ── AUDIT LOG: Persist each finding/attack path for compliance timeline ──
      if (graph.attack_paths && pool) {
        for (const ap of graph.attack_paths) {
          try {
            await db(req).query(`
              INSERT INTO audit_events (event_type, actor, workload_name, detail)
              VALUES ($1, $2, $3, $4)
            `, [
              'FINDING',
              'graph-scanner',
              ap.workload || ap.source || 'unknown',
              JSON.stringify({
                finding_type: ap.finding_type || ap.type,
                severity: ap.severity,
                message: ap.message || ap.description,
                blast_radius: ap.blast_radius,
                entry_points: ap.entry_points,
                owasp_mapping: ap.owasp || ap.nhi_mapping,
              }),
            ]);
          } catch {} // Non-fatal — don't break scan for audit log failures
        }
        console.log(`  📋 Audit: ${graph.attack_paths.length} findings logged`);
      }

      // ── AUDIT LOG: Discovery event (what was found this scan) ──
      try {
        await db(req).query(`
          INSERT INTO audit_events (event_type, actor, detail)
          VALUES ($1, $2, $3)
        `, [
          'DISCOVERY',
          'graph-scanner',
          JSON.stringify({
            total_nodes: graph.nodes?.length || 0,
            total_relationships: graph.relationships?.length || 0,
            total_attack_paths: graph.attack_paths?.length || 0,
            summary: graph.summary,
          }),
        ]);
      } catch {}

      const controlCount = graph.attack_paths?.reduce((s, p) => s + (p.ranked_controls?.length || 0), 0) || 0;
      res.json({ message: 'Graph scan complete', ...graph.summary, total_controls_scored: controlCount });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/controls/:finding_type — Get scored controls for a finding ──
  app.get('/api/v1/graph/controls/:finding_type', async (req, res) => {
    try {
      const findingType = req.params.finding_type;
      const workload = req.query.workload || '';

      // Build mock attack path for scoring
      const mockPath = { finding_type: findingType, workload };
      const { data: controlGraphCache } = getGraphCache(req.tenantId || '_system');
      const nodes = controlGraphCache?.nodes || [];
      const rels = controlGraphCache?.relationships || [];

      const controls = await scoreControlsAsync(mockPath, nodes, rels, pool);
      res.json({
        finding_type: findingType,
        workload,
        controls,
        count: controls.length,
        recommended: controls[0] || null,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/remediation/:nodeId — Rendered remediation for a node ──
  app.get('/api/v1/graph/remediation/:nodeId', async (req, res) => {
    try {
      const nodeId = req.params.nodeId;
      const { finding_type } = req.query;

      const { data: remGraphCache } = getGraphCache(req.tenantId || '_system');
      if (!remGraphCache) {
        return res.status(404).json({ error: 'Graph not loaded. Trigger a scan first.' });
      }

      // Find the node (match by id, workload_id, or label)
      const node = remGraphCache.nodes.find(n =>
        n.id === nodeId ||
        n.workload_id === nodeId ||
        (n.label || '').toLowerCase() === nodeId.toLowerCase()
      );
      if (!node) {
        return res.status(404).json({ error: `Node not found: ${nodeId}` });
      }

      // Find attack paths for this node
      let attackPaths = (remGraphCache.attack_paths || []).filter(ap => {
        const wl = (ap.workload || '').toLowerCase();
        const nl = (node.label || '').toLowerCase();
        return wl === nl || (ap.entry_points || []).some(ep => ep.toLowerCase() === nl);
      });

      // Optional: filter by specific finding type
      if (finding_type) {
        attackPaths = attackPaths.filter(ap => ap.finding_type === finding_type);
      }

      if (attackPaths.length === 0) {
        return res.json({ node_id: nodeId, node_label: node.label, remediations: [], note: 'No attack paths for this node' });
      }

      const renderer = new RemediationRenderer(pool);
      const context = renderer.buildContext(node, attackPaths, remGraphCache.nodes, remGraphCache.relationships);
      const remediations = await renderer.render(context);

      res.json({
        node_id: nodeId,
        node_label: node.label,
        cloud_provider: context.cloud_provider,
        finding_types: context.finding_types,
        blast_radius: context.blast_radius,
        remediations,
        total: remediations.length,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/reset — Clear graph cache for fresh demo ──
  app.post('/api/v1/graph/reset', async (req, res) => {
    const tenantId = req.tenantId || '_system';
    graphCaches.delete(tenantId);
    res.json({ message: 'Graph cache cleared. Next GET /graph will rebuild from DB.' });
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // CRUD — Remediation Intents + Templates
  // DB is single source of truth. Replaces need for CONTROL_CATALOG code changes.
  // ═══════════════════════════════════════════════════════════════════════════

  // ── GET /api/v1/graph/remediation-intents — List with filters ──
  app.get('/api/v1/graph/remediation-intents', async (req, res) => {
    try {
      const { finding_type, action_type, enabled, limit = 200, offset = 0 } = req.query;
      const conditions = [];
      const params = [];
      let pi = 1;

      if (finding_type) { conditions.push(`$${pi} = ANY(finding_types)`); params.push(finding_type); pi++; }
      if (action_type) { conditions.push(`action_type = $${pi}`); params.push(action_type); pi++; }
      if (enabled !== undefined) { conditions.push(`enabled = $${pi}`); params.push(enabled === 'true'); pi++; }

      const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const countRes = await db(req).query(`SELECT COUNT(*) FROM remediation_intents ${where}`, params);
      const total = parseInt(countRes.rows[0].count);

      params.push(parseInt(limit)); pi++;
      params.push(parseInt(offset)); pi++;
      const result = await db(req).query(
        `SELECT ri.*, (SELECT COUNT(*) FROM remediation_templates rt WHERE rt.intent_id = ri.id) AS template_count
         FROM remediation_intents ri ${where}
         ORDER BY ri.updated_at DESC
         LIMIT $${pi - 2} OFFSET $${pi - 1}`, params
      );

      res.json({ intents: result.rows, total });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/remediation-intents/:id — Single intent + templates ──
  app.get('/api/v1/graph/remediation-intents/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const intentRes = await db(req).query('SELECT * FROM remediation_intents WHERE id = $1', [id]);
      if (intentRes.rows.length === 0) return res.status(404).json({ error: `Intent not found: ${id}` });

      const tmplRes = await db(req).query(
        'SELECT * FROM remediation_templates WHERE intent_id = $1 ORDER BY priority ASC, created_at ASC', [id]
      );

      res.json({ ...intentRes.rows[0], templates: tmplRes.rows });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/remediation-intents — Create new intent ──
  app.post('/api/v1/graph/remediation-intents', async (req, res) => {
    try {
      const {
        id, name, description, goal, action_type, remediation_type, finding_types,
        scope, resource_types, path_break, feasibility, operational, risk_reduction,
        rollback_strategy, template_id,
      } = req.body;

      if (!id || !name || !description || !action_type || !remediation_type) {
        return res.status(400).json({ error: 'Required: id, name, description, action_type, remediation_type' });
      }
      if (!finding_types || !Array.isArray(finding_types) || finding_types.length === 0) {
        return res.status(400).json({ error: 'finding_types must be a non-empty array' });
      }
      if (!path_break || !feasibility || !operational) {
        return res.status(400).json({ error: 'Required: path_break, feasibility, operational' });
      }

      const result = await db(req).query(`
        INSERT INTO remediation_intents (
          id, control_id, name, description, goal, action_type, remediation_type,
          finding_types, scope, resource_types, path_break, feasibility, operational,
          risk_reduction, rollback_strategy, template_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING *
      `, [
        id, id.toUpperCase().replace(/-/g, '.'), name, description,
        goal || description, action_type, remediation_type,
        finding_types, scope || 'resource', resource_types || [],
        JSON.stringify(path_break), JSON.stringify(feasibility), JSON.stringify(operational),
        JSON.stringify(risk_reduction || {}), rollback_strategy || null, template_id || null,
      ]);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: `Intent already exists: ${req.body.id}` });
      res.status(500).json({ error: error.message });
    }
  });

  // ── PUT /api/v1/graph/remediation-intents/:id — Update intent ──
  app.put('/api/v1/graph/remediation-intents/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const {
        name, description, goal, action_type, remediation_type, finding_types,
        scope, resource_types, path_break, feasibility, operational, risk_reduction,
        rollback_strategy, template_id, enabled,
      } = req.body;

      const result = await db(req).query(`
        UPDATE remediation_intents SET
          name = COALESCE($2, name),
          description = COALESCE($3, description),
          goal = COALESCE($4, goal),
          action_type = COALESCE($5, action_type),
          remediation_type = COALESCE($6, remediation_type),
          finding_types = COALESCE($7, finding_types),
          scope = COALESCE($8, scope),
          resource_types = COALESCE($9, resource_types),
          path_break = COALESCE($10, path_break),
          feasibility = COALESCE($11, feasibility),
          operational = COALESCE($12, operational),
          risk_reduction = COALESCE($13, risk_reduction),
          rollback_strategy = COALESCE($14, rollback_strategy),
          template_id = COALESCE($15, template_id),
          enabled = COALESCE($16, enabled),
          updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `, [
        id, name || null, description || null, goal || null,
        action_type || null, remediation_type || null,
        finding_types || null, scope || null, resource_types || null,
        path_break ? JSON.stringify(path_break) : null,
        feasibility ? JSON.stringify(feasibility) : null,
        operational ? JSON.stringify(operational) : null,
        risk_reduction ? JSON.stringify(risk_reduction) : null,
        rollback_strategy !== undefined ? rollback_strategy : null,
        template_id !== undefined ? template_id : null,
        enabled !== undefined ? enabled : null,
      ]);

      if (result.rows.length === 0) return res.status(404).json({ error: `Intent not found: ${id}` });
      res.json(result.rows[0]);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── DELETE /api/v1/graph/remediation-intents/:id — Delete intent (cascades templates) ──
  app.delete('/api/v1/graph/remediation-intents/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const result = await db(req).query('DELETE FROM remediation_intents WHERE id = $1 RETURNING id', [id]);
      if (result.rows.length === 0) return res.status(404).json({ error: `Intent not found: ${id}` });
      res.json({ deleted: id });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/remediation-intents/:id/templates — Add template to intent ──
  app.post('/api/v1/graph/remediation-intents/:id/templates', async (req, res) => {
    try {
      const intentId = req.params.id;
      const { provider, channel, template_body, title, resource_type, variables, validate_template, rollback_template, priority } = req.body;

      if (!provider || !channel || !template_body) {
        return res.status(400).json({ error: 'Required: provider, channel, template_body' });
      }

      // Verify intent exists
      const intentCheck = await db(req).query('SELECT id FROM remediation_intents WHERE id = $1', [intentId]);
      if (intentCheck.rows.length === 0) return res.status(404).json({ error: `Intent not found: ${intentId}` });

      const result = await db(req).query(`
        INSERT INTO remediation_templates (
          intent_id, provider, channel, title, template_body,
          resource_type, variables, validate_template, rollback_template, priority
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (intent_id, provider, COALESCE(resource_type,''), channel)
        DO UPDATE SET title = EXCLUDED.title, template_body = EXCLUDED.template_body,
                      variables = EXCLUDED.variables, validate_template = EXCLUDED.validate_template,
                      rollback_template = EXCLUDED.rollback_template, priority = EXCLUDED.priority
        RETURNING *
      `, [
        intentId, provider, channel, title || null, template_body,
        resource_type || null, JSON.stringify(variables || []),
        validate_template || null, rollback_template || null, priority || 100,
      ]);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── DELETE /api/v1/graph/remediation-templates/:templateId — Delete a template ──
  app.delete('/api/v1/graph/remediation-templates/:templateId', async (req, res) => {
    try {
      const { templateId } = req.params;
      const result = await db(req).query('DELETE FROM remediation_templates WHERE id = $1 RETURNING id', [parseInt(templateId)]);
      if (result.rows.length === 0) return res.status(404).json({ error: `Template not found: ${templateId}` });
      res.json({ deleted: parseInt(templateId) });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ==========================================================================
  // REMEDIATION EXECUTIONS — Execute, approve, rollback remediation actions
  // ==========================================================================

  const executor = new RemediationExecutor(pool);

  // ── POST /api/v1/graph/remediation/:nodeId/execute — Request execution ──
  app.post('/api/v1/graph/remediation/:nodeId/execute', async (req, res) => {
    try {
      const { nodeId } = req.params;
      const { control_id, channel, auto_approve, enforcement_mode, requested_by } = req.body || {};

      if (!control_id || !channel) {
        return res.status(400).json({ error: 'control_id and channel are required' });
      }

      // Get rendered commands from renderer if not provided
      let commands = req.body.commands || null;
      let rollbackCommands = req.body.rollback_commands || null;

      if (!commands) {
        // Auto-render from intent templates
        const { data: execGraphCache } = getGraphCache(req.tenantId || '_system');
        const graph = execGraphCache || await buildGraph(pool);
        const node = graph.nodes.find(n => n.id === nodeId);
        if (!node) return res.status(404).json({ error: `Node not found: ${nodeId}` });

        const renderer = new RemediationRenderer(pool);
        const attackPaths = (graph.attack_paths || []).filter(ap =>
          ap.workload_id === nodeId || ap.source_id === nodeId
        );
        const context = renderer.buildContext(node, attackPaths, graph.nodes, graph.relationships);
        const remediations = await renderer.render(context);

        const matched = remediations.find(r => r.control_id === control_id || r.intent_id === control_id);
        if (matched?.channels?.[channel]) {
          commands = matched.channels[channel].commands;
          rollbackCommands = matched.channels[channel].rollback_commands;
        }
      }

      const result = await executor.requestExecution(control_id, nodeId, channel, {
        requestedBy: requested_by || 'ui',
        autoApprove: auto_approve === true,
        commands,
        rollbackCommands,
        context: { enforcement_mode: enforcement_mode || 'audit' },
      });

      res.status(result.status === 'pending' ? 202 : 200).json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/remediation-executions/:id/approve — Approve and execute ──
  app.post('/api/v1/graph/remediation-executions/:id/approve', async (req, res) => {
    try {
      const { approved_by, enforcement_mode } = req.body || {};
      const result = await executor.approveAndExecute(
        parseInt(req.params.id),
        approved_by || 'admin',
        { enforcement_mode: enforcement_mode || 'audit' }
      );
      res.json(result);
    } catch (error) {
      const status = error.message.includes('not found') ? 404
        : error.message.includes('expected pending') ? 409 : 500;
      res.status(status).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/remediation-executions/:id/rollback — Rollback ──
  app.post('/api/v1/graph/remediation-executions/:id/rollback', async (req, res) => {
    try {
      const result = await executor.rollback(parseInt(req.params.id));
      res.json(result);
    } catch (error) {
      const status = error.message.includes('not found') ? 404
        : error.message.includes('Cannot rollback') ? 409 : 500;
      res.status(status).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/remediation-executions/:id — Single execution status ──
  app.get('/api/v1/graph/remediation-executions/:id', async (req, res) => {
    try {
      const execution = await executor.getExecution(parseInt(req.params.id));
      if (!execution) return res.status(404).json({ error: 'Execution not found' });
      res.json(execution);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/remediation-executions — List all executions ──
  app.get('/api/v1/graph/remediation-executions', async (req, res) => {
    try {
      const { node_id, status, control_id } = req.query;
      const executions = await executor.listExecutions({
        nodeId: node_id,
        status,
        controlId: control_id,
      });
      res.json({ executions, total: executions.length });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── GET /api/v1/graph/finding-types — All known finding types with labels + descriptions ──
  app.get('/api/v1/graph/finding-types', async (req, res) => {
    try {
      // Fetch from finding_type_metadata table (DB source of truth)
      let dbTypes = [];
      try {
        const result = await db(req).query(`
          SELECT ftm.finding_type AS id, ftm.label, ftm.description, ftm.severity, ftm.category, ftm.enabled,
                 (SELECT COUNT(*) FROM remediation_intents ri WHERE ftm.finding_type = ANY(ri.finding_types) AND ri.enabled = true) AS control_count
          FROM finding_type_metadata ftm
          WHERE ftm.enabled = true
          ORDER BY ftm.label ASC
        `);
        dbTypes = result.rows;
      } catch {
        // Table may not exist yet — fall through to catalog-derived types
      }

      if (dbTypes.length > 0) {
        return res.json({ finding_types: dbTypes, source: 'db' });
      }

      // Fallback: derive from remediation_intents finding_types arrays
      const fallbackRes = await db(req).query(`
        SELECT ft AS id, COUNT(*) AS control_count
        FROM (SELECT DISTINCT unnest(finding_types) AS ft FROM remediation_intents WHERE enabled = true) sub
        GROUP BY ft ORDER BY ft
      `);

      const findingTypes = fallbackRes.rows.map(row => ({
        id: row.id,
        label: FINDING_TYPE_DEFAULTS[row.id]?.label || row.id.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
        description: FINDING_TYPE_DEFAULTS[row.id]?.description || '',
        severity: FINDING_TYPE_DEFAULTS[row.id]?.severity || 'high',
        control_count: parseInt(row.control_count),
      }));

      res.json({ finding_types: findingTypes, source: 'derived' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── POST /api/v1/graph/finding-types — Create/update finding type metadata ──
  app.post('/api/v1/graph/finding-types', async (req, res) => {
    try {
      const { finding_type, label, description, severity, category } = req.body;
      if (!finding_type || !label || !description) {
        return res.status(400).json({ error: 'Required: finding_type, label, description' });
      }

      const result = await db(req).query(`
        INSERT INTO finding_type_metadata (finding_type, label, description, severity, category)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (finding_type) DO UPDATE SET
          label = EXCLUDED.label, description = EXCLUDED.description,
          severity = COALESCE(EXCLUDED.severity, finding_type_metadata.severity),
          category = COALESCE(EXCLUDED.category, finding_type_metadata.category)
        RETURNING *
      `, [finding_type, label, description, severity || 'high', category || null]);

      res.status(201).json(result.rows[0]);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  // ── MCP Fingerprint Query Endpoints ──

  // GET /api/v1/mcp/fingerprints — Fingerprint history with drift filter
  app.get('/api/v1/mcp/fingerprints', async (req, res) => {
    try {
      const { workload, server, drift_only, since, limit: rawLimit } = req.query;
      let q = 'SELECT * FROM mcp_fingerprints WHERE 1=1';
      const p = []; let i = 1;

      if (workload) { q += ` AND LOWER(workload_name) LIKE $${i}`; p.push(`%${workload.toLowerCase()}%`); i++; }
      if (server) { q += ` AND LOWER(server_name) LIKE $${i}`; p.push(`%${server.toLowerCase()}%`); i++; }
      if (drift_only === 'true') { q += ' AND drift_detected = TRUE'; }
      if (since) { q += ` AND created_at > $${i}`; p.push(since); i++; }

      q += ` ORDER BY created_at DESC LIMIT $${i}`;
      p.push(Math.min(parseInt(rawLimit) || 100, 500));

      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, fingerprints: r.rows });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ total: 0, fingerprints: [], note: 'mcp_fingerprints table not yet created' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/mcp/fingerprints/:workloadName/drift — Drift events for a specific server
  app.get('/api/v1/mcp/fingerprints/:workloadName/drift', async (req, res) => {
    try {
      const r = await db(req).query(
        `SELECT * FROM mcp_fingerprints
         WHERE workload_name = $1 AND drift_detected = TRUE
         ORDER BY created_at DESC LIMIT 50`,
        [req.params.workloadName]
      );
      res.json({ workload: req.params.workloadName, total: r.rows.length, drift_events: r.rows });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ workload: req.params.workloadName, total: 0, drift_events: [], note: 'mcp_fingerprints table not yet created' });
      }
      res.status(500).json({ error: e.message });
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// CONTROL SCORING ENGINE
// Given an attack path, compute and rank candidate controls by:
//   Path Break Strength (40%) — how effectively the control breaks the path
//   Feasibility (hard gate)   — are preconditions met?
//   Blast Radius (20% inv)    — how many workloads affected (fewer = higher)
//   Operational Cost (20% inv)— implementation effort (lower = higher)
//   Confidence (20%)          — evidence completeness, false positive risk
// ═══════════════════════════════════════════════════════════════════════════

// Control catalog: maps finding types to candidate controls with scoring metadata
const CONTROL_CATALOG = {
  'static-external-credential': [
    {
      id: 'migrate-to-vault',
      name: 'Migrate to Secret Manager',
      description: 'Move credential from env var to secret manager (GCP Secret Manager, AWS Secrets Manager, HashiCorp Vault)',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['vault-available'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'secret-in-env-plaintext',
      remediation_guide: {
        aws: {
          title: 'Move secret to AWS Secrets Manager',
          steps: [
            'aws secretsmanager create-secret --name <SECRET_NAME> --secret-string "<VALUE>"',
            'aws secretsmanager get-secret-value --secret-id <SECRET_NAME> --query SecretString --output text',
          ],
          terraform: 'resource "aws_secretsmanager_secret" "this" {\n  name = "<SECRET_NAME>"\n}\nresource "aws_secretsmanager_secret_version" "this" {\n  secret_id     = aws_secretsmanager_secret.this.id\n  secret_string = "<VALUE>"\n}',
        },
        gcp: {
          title: 'Move secret to GCP Secret Manager',
          steps: [
            'echo -n "<VALUE>" | gcloud secrets create <SECRET_NAME> --data-file=-',
            'gcloud secrets versions access latest --secret=<SECRET_NAME>',
          ],
        },
      },
    },
    {
      id: 'jit-token-rotation',
      name: 'Replace with JIT Gateway Token',
      description: 'Route API access through WID Edge Gateway with short-lived JIT tokens (5min TTL, auto-rotated)',
      action_type: 'replace',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['edge-gateway-deployed', 'spire-available'], effort: 'days', automated: true },
      operational: { implementation: 5, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'jit-credential-required',
    },
    {
      id: 'add-expiry-rotation',
      name: 'Add Expiry + Rotation Policy',
      description: 'Set credential expiry (90d) and enable automatic rotation schedule via cloud provider settings',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.4 },
      feasibility: { preconditions: ['api-supports-rotation'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 2, expertise: 'low' },
      template_id: 'long-lived-api-key',
    },
    {
      id: 'scope-reduction',
      name: 'Reduce Credential Scope',
      description: 'Limit credential permissions to minimum required (e.g., charges:write → charges:create only)',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: ['api-supports-scoping'], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: null,
      remediation_guide: {
        aws: {
          title: 'Scope down IAM policy to least privilege',
          steps: [
            'aws iam generate-service-last-accessed-details --arn <ROLE_ARN>',
            'aws accessanalyzer generate-policy --start-policy-generation --cloud-trail-details ...',
          ],
        },
        gcp: {
          title: 'Scope down IAM roles using recommender',
          steps: [
            'gcloud recommender recommendations list --project=<PROJECT> --recommender=google.iam.policy.Recommender --location=global',
          ],
        },
      },
    },
  ],
  'toxic-combo': [
    {
      id: 'identity-separation',
      name: 'Separate into Dedicated Identities',
      description: 'Split workload into 2 agents — one for financial (Stripe), one for CRM (Salesforce) — each with dedicated credentials',
      action_type: 'architecture',
      remediation_type: 'code_change',
      path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['can-split-workload'], effort: 'weeks', automated: false },
      operational: { implementation: 8, ongoing_toil: 2, expertise: 'high' },
      template_id: 'toxic-combo-financial-crm',
      remediation_guide: {
        aws: {
          title: 'Create separate IAM roles per function',
          steps: [
            'aws iam create-role --role-name <WORKLOAD>-financial --assume-role-policy-document file://trust.json',
            'aws iam create-role --role-name <WORKLOAD>-crm --assume-role-policy-document file://trust.json',
            'aws iam attach-role-policy --role-name <WORKLOAD>-financial --policy-arn <FINANCIAL_POLICY>',
            'aws iam attach-role-policy --role-name <WORKLOAD>-crm --policy-arn <CRM_POLICY>',
          ],
        },
        gcp: {
          title: 'Create separate service accounts per function',
          steps: [
            'gcloud iam service-accounts create <WORKLOAD>-financial --display-name="Financial SA"',
            'gcloud iam service-accounts create <WORKLOAD>-crm --display-name="CRM SA"',
          ],
        },
      },
    },
    {
      id: 'scope-ceiling',
      name: 'Agent Scope Ceiling',
      description: 'Enforce maximum scope per workload identity — prevent any single identity from holding financial + CRM access',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'agent-scope-ceiling',
    },
    {
      id: 'jit-with-approval',
      name: 'JIT Access with Human Approval',
      description: 'Replace static credentials with JIT tokens that require human approval for cross-domain access',
      action_type: 'replace',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.95 },
      feasibility: { preconditions: ['edge-gateway-deployed', 'approval-workflow'], effort: 'days', automated: true },
      operational: { implementation: 5, ongoing_toil: 3, expertise: 'medium' },
      template_id: 'jit-credential-required',
    },
  ],
  'mcp-static-credentials': [
    {
      id: 'mcp-oauth',
      name: 'Migrate to OAuth 2.1',
      description: 'Replace static MCP server credentials with OAuth 2.1 client credentials flow',
      action_type: 'replace',
      remediation_type: 'code_change',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['mcp-server-supports-oauth'], effort: 'days', automated: true },
      operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'mcp-oauth-required',
      remediation_guide: {
        aws: { title: 'Configure OAuth 2.1 for MCP server', steps: ['Update MCP server config to use OAuth 2.1 client credentials flow', 'Rotate and delete static API keys after migration'] },
        gcp: { title: 'Configure OAuth 2.1 for MCP server', steps: ['Update MCP server config to use OAuth 2.1 client credentials flow', 'Rotate and delete static API keys after migration'] },
      },
    },
    {
      id: 'mcp-static-ban',
      name: 'Ban Static Credentials',
      description: 'Enforce policy that denies any MCP server connection using static credentials',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'mcp-static-credential-ban',
    },
  ],
  'mcp-tool-poisoning': [
    {
      id: 'mcp-disconnect-poisoned',
      name: 'Disconnect Poisoned MCP Server',
      description: 'Immediately disconnect the MCP server with tool poisoning indicators. Audit all previous tool invocations and replace with a verified alternative.',
      action_type: 'contain',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'mcp-poisoning-containment',
    },
    {
      id: 'mcp-tool-description-audit',
      name: 'Enforce Tool Description Scanning',
      description: 'Deploy WID policy that scans all MCP tool descriptions for prompt injection, hidden instructions, and exfiltration patterns before allowing tool invocation.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['edge-gateway-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'mcp-tool-poisoning-scan',
    },
  ],
  'mcp-unverified-server': [
    {
      id: 'mcp-pin-verified-version',
      name: 'Pin to Verified MCP Package',
      description: 'Replace unverified MCP server with a verified package from the known-good registry. Pin to a specific version hash for supply chain integrity.',
      action_type: 'replace',
      remediation_type: 'code_change',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'mcp-integrity-verification',
    },
    {
      id: 'mcp-integrity-policy',
      name: 'Enforce Server Integrity Check',
      description: 'Deploy policy that denies connections to MCP servers not present in the known-good registry. Requires capability fingerprint verification.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'mcp-server-integrity-required',
    },
  ],
  'mcp-outdated-version': [
    {
      id: 'mcp-update-version',
      name: 'Update MCP Server Version',
      description: 'Update the MCP server package to the minimum recommended version or later. Outdated versions may have known security vulnerabilities.',
      action_type: 'remediate',
      remediation_type: 'code_change',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 1, expertise: 'low' },
      template_id: 'mcp-version-update',
    },
    {
      id: 'mcp-version-policy',
      name: 'Enforce Minimum Version Policy',
      description: 'Deploy policy that blocks connections to MCP servers running below the minimum recommended version.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'mcp-minimum-version-required',
    },
  ],
  'a2a-no-auth': [
    {
      id: 'a2a-require-auth',
      name: 'Require Authentication',
      description: 'Enforce WID token authentication for all A2A agent-to-agent task delegations',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'a2a-authentication-required',
    },
    {
      id: 'a2a-delegator',
      name: 'Require Human Delegator',
      description: 'AI agents can only accept tasks with a verified human delegator in the token chain',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['delegation-chain-available'], effort: 'days', automated: true },
      operational: { implementation: 4, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'agent-must-have-delegator',
    },
  ],
  'a2a-unsigned-card': [
    {
      id: 'require-signed-card',
      name: 'Require Signed Agent Cards',
      description: 'All A2A Agent Cards must be signed with JWS for authenticity verification',
      action_type: 'harden',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: ['jws-signing-available'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'a2a-agent-card-signing',
    },
  ],
  'shared-sa': [
    {
      id: 'dedicated-sa',
      name: 'Assign Dedicated Service Account',
      description: 'Replace shared service account with per-workload dedicated SAs with least-privilege roles',
      action_type: 'architecture',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 5, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'shared-service-account-deny',
      remediation_guide: {
        aws: { title: 'Create per-workload IAM roles', steps: ['aws iam create-role --role-name <WORKLOAD>-sa --assume-role-policy-document file://trust.json', 'aws iam attach-role-policy --role-name <WORKLOAD>-sa --policy-arn <LEAST_PRIV_POLICY>'] },
        gcp: { title: 'Create per-workload service accounts', steps: ['gcloud iam service-accounts create <WORKLOAD>-sa --display-name="<WORKLOAD> Dedicated SA"', 'gcloud projects add-iam-policy-binding <PROJECT> --member=serviceAccount:<SA_EMAIL> --role=<LEAST_PRIV_ROLE>'] },
      },
    },
    {
      id: 'workload-identity-federation',
      name: 'Migrate to Workload Identity Federation',
      description: 'Use GCP Workload Identity Federation to eliminate service account keys entirely',
      action_type: 'replace',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['gcp-project-access'], effort: 'days', automated: true },
      operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'env-credential-isolation',
      remediation_guide: {
        gcp: { title: 'Configure Workload Identity Federation', steps: ['gcloud iam workload-identity-pools create <POOL> --location=global', 'gcloud iam workload-identity-pools providers create-oidc <PROVIDER> --location=global --workload-identity-pool=<POOL> --issuer-uri=<SPIRE_OIDC_ISSUER>', 'gcloud iam service-accounts add-iam-policy-binding <SA_EMAIL> --role=roles/iam.workloadIdentityUser --member="principalSet://iam.googleapis.com/projects/<NUM>/locations/global/workloadIdentityPools/<POOL>/attribute.spiffe_id/<SPIFFE_ID>"'] },
        aws: { title: 'Configure IRSA (IAM Roles for Service Accounts)', steps: ['aws iam create-open-id-connect-provider --url <SPIRE_OIDC_URL> --client-id-list sts.amazonaws.com', 'aws iam create-role --role-name <WORKLOAD>-federated --assume-role-policy-document file://trust-oidc.json'] },
      },
    },
  ],
  'key-leak': [
    {
      id: 'rotate-leaked-key',
      name: 'Rotate Leaked Credential',
      description: 'Immediately rotate the compromised key and revoke old credentials',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'credential-rotation-overdue',
      remediation_guide: {
        aws: { title: 'Rotate compromised access key immediately', steps: ['aws iam create-access-key --user-name <USER>', 'aws iam update-access-key --access-key-id <OLD_KEY_ID> --status Inactive --user-name <USER>', 'aws iam delete-access-key --access-key-id <OLD_KEY_ID> --user-name <USER>'] },
        gcp: { title: 'Rotate compromised service account key', steps: ['gcloud iam service-accounts keys create /tmp/new-key.json --iam-account=<SA_EMAIL>', 'gcloud iam service-accounts keys delete <OLD_KEY_ID> --iam-account=<SA_EMAIL> --quiet'] },
      },
    },
    {
      id: 'ban-user-managed-keys',
      name: 'Ban User-Managed Keys',
      description: 'Enforce policy that no user-managed service account keys are allowed — use Workload Identity instead',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'user-managed-key-prohibition',
    },
  ],
  'over-privileged': [
    {
      id: 'remove-wildcards',
      name: 'Remove Wildcard Permissions',
      description: 'Replace wildcard (*) IAM bindings with specific, least-privilege roles',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 5, ongoing_toil: 2, expertise: 'medium' },
      template_id: 'no-wildcard-permissions',
      remediation_guide: {
        aws: { title: 'Replace wildcard permissions with specific actions', steps: ['aws iam generate-service-last-accessed-details --arn <ROLE_ARN>', 'aws accessanalyzer generate-policy --start-policy-generation --cloud-trail-details ...'] },
        gcp: { title: 'Replace broad roles with fine-grained roles', steps: ['gcloud recommender recommendations list --project=<PROJECT> --recommender=google.iam.policy.Recommender --location=global'] },
      },
    },
    {
      id: 'crypto-attest-for-admin',
      name: 'Require Cryptographic Attestation for Admin',
      description: 'Admin-level access requires cryptographic workload attestation (SPIRE mTLS)',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'admin-requires-crypto',
    },
  ],
  'public-internal-pivot': [
    {
      id: 'network-segmentation',
      name: 'Enforce Network Segmentation',
      description: 'Block public-facing services from reaching internal services directly — require gateway intermediary',
      action_type: 'architecture',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: true },
      operational: { implementation: 5, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'internal-service-isolation',
      remediation_guide: {
        aws: { title: 'Add network segmentation between public and internal', steps: ['aws ec2 create-security-group --group-name internal-only --description "No public ingress" --vpc-id <VPC_ID>', 'aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --groups <SG_ID>'] },
        gcp: { title: 'Create firewall rules for internal-only access', steps: ['gcloud compute firewall-rules create deny-public-to-internal --network=<VPC> --action=DENY --direction=INGRESS --source-ranges=0.0.0.0/0 --target-tags=internal'] },
      },
    },
    {
      id: 'zero-trust-identity',
      name: 'Zero Trust Identity Verification',
      description: 'Every internal service call requires WID token verification — no implicit trust based on network',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'low' },
      template_id: 'weak-trust-in-prod',
    },
  ],
  'privilege-escalation': [
    {
      id: 'restrict-pass-role',
      name: 'Restrict iam:PassRole',
      description: 'Limit iam:PassRole to specific target roles via resource condition — prevent passing to admin roles',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'restrict-iam-pass-role',
      remediation_guide: {
        aws: { title: 'Add resource condition to restrict iam:PassRole', steps: ['aws iam put-role-policy --role-name <ROLE> --policy-name RestrictPassRole --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::<ACCOUNT>:role/<ALLOWED_ROLE>"}]}\''], terraform: 'resource "aws_iam_role_policy" "restrict_pass_role" {\n  name = "RestrictPassRole"\n  role = "<ROLE>"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "arn:aws:iam::<ACCOUNT>:role/<ALLOWED_ROLE>" }]\n  })\n}' },
      },
    },
    {
      id: 'add-permission-boundary',
      name: 'Apply Permission Boundary',
      description: 'Attach a permission boundary to the role to cap maximum permissions regardless of attached policies',
      action_type: 'policy',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'permission-boundary-required',
      remediation_guide: {
        aws: { title: 'Apply permission boundary', steps: ['aws iam put-role-permissions-boundary --role-name <ROLE> --permissions-boundary arn:aws:iam::<ACCOUNT>:policy/<BOUNDARY>'], terraform: 'resource "aws_iam_role" "this" {\n  name                 = "<ROLE>"\n  permissions_boundary = "arn:aws:iam::<ACCOUNT>:policy/<BOUNDARY>"\n}' },
      },
    },
  ],
  'cross-account-trust': [
    {
      id: 'require-external-id',
      name: 'Require ExternalId in Trust Policy',
      description: 'Add sts:ExternalId condition to prevent confused deputy attacks on cross-account AssumeRole',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'cross-account-external-id',
      remediation_guide: {
        aws: { title: 'Add ExternalId condition to trust policy', steps: ['aws iam update-assume-role-policy --role-name <ROLE> --policy-document file://trust-with-external-id.json'], terraform: 'data "aws_iam_policy_document" "trust" {\n  statement {\n    actions = ["sts:AssumeRole"]\n    principals { type = "AWS"; identifiers = ["arn:aws:iam::<ACCOUNT>:root"] }\n    condition { test = "StringEquals"; variable = "sts:ExternalId"; values = ["<EXTERNAL_ID>"] }\n  }\n}' },
      },
    },
    {
      id: 'restrict-trust-policy',
      name: 'Restrict Trust Policy Principals',
      description: 'Replace wildcard (*) with specific account ARNs in the role trust policy',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'restrict-trust-principal',
      remediation_guide: {
        aws: { title: 'Replace wildcard trust with specific account ARNs', steps: ['aws iam update-assume-role-policy --role-name <ROLE> --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<ACCOUNT>:root"},"Action":"sts:AssumeRole"}]}\''] },
      },
    },
  ],
  'unbounded-admin': [
    {
      id: 'apply-permission-boundary',
      name: 'Apply Permission Boundary',
      description: 'Attach a permission boundary policy to cap the maximum permissions this admin identity can exercise',
      action_type: 'policy',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'permission-boundary-required',
      remediation_guide: {
        aws: {
          title: 'Apply permission boundary to IAM role',
          steps: [
            'aws iam put-role-permissions-boundary --role-name <ROLE_NAME> --permissions-boundary arn:aws:iam::<ACCOUNT>:policy/<BOUNDARY_POLICY>',
          ],
          terraform: 'resource "aws_iam_role" "this" {\n  name                 = "<ROLE_NAME>"\n  permissions_boundary = "arn:aws:iam::<ACCOUNT>:policy/<BOUNDARY_POLICY>"\n}',
        },
        gcp: {
          title: 'Apply IAM Conditions to limit scope',
          steps: [
            'gcloud projects add-iam-policy-binding <PROJECT> --member=serviceAccount:<SA_EMAIL> --role=roles/editor --condition=expression="request.time < timestamp(\\\"2026-04-01T00:00:00Z\\\")",title=temp-access',
          ],
        },
      },
    },
    {
      id: 'break-glass-only',
      name: 'Convert to Break-Glass Only',
      description: 'Remove admin access from daily-use role; create separate break-glass role with MFA + time-limited sessions',
      action_type: 'architecture',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 5, ongoing_toil: 2, expertise: 'high' },
      template_id: 'admin-requires-crypto',
      remediation_guide: {
        aws: {
          title: 'Create break-glass role with MFA requirement',
          steps: [
            'aws iam create-role --role-name BreakGlass-Admin --assume-role-policy-document file://trust-policy-mfa.json',
            'aws iam attach-role-policy --role-name BreakGlass-Admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
            'aws iam detach-role-policy --role-name <CURRENT_ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess',
          ],
        },
      },
    },
  ],
  'public-data-exposure': [
    {
      id: 'block-public-access',
      name: 'Enable Public Access Block',
      description: 'Enable S3 Block Public Access (all 4 settings) or GCS Public Access Prevention to prevent any public exposure',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'resource', edges_severed: 1, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'public-bucket-deny',
      remediation_guide: {
        aws: { title: 'Block public access on S3', steps: ['aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'], terraform: 'resource "aws_s3_bucket_public_access_block" "block" {\n  bucket                  = "<BUCKET>"\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}' },
        gcp: { title: 'Enable public access prevention on GCS', steps: ['gcloud storage buckets update gs://<BUCKET> --public-access-prevention=enforced'] },
      },
    },
    {
      id: 'encrypt-data-at-rest',
      name: 'Enable Server-Side Encryption',
      description: 'Enable SSE-KMS encryption with customer-managed key for data at rest',
      action_type: 'harden',
      remediation_type: 'infra',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: ['kms-key-available'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'encryption-at-rest-required',
      remediation_guide: {
        aws: { title: 'Enable SSE-KMS encryption on S3', steps: ['aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<KMS_KEY>"}}]}\''] },
        gcp: { title: 'Enable CMEK on GCS', steps: ['gcloud storage buckets update gs://<BUCKET> --default-encryption-key=projects/<PROJECT>/locations/<LOC>/keyRings/<RING>/cryptoKeys/<KEY>'] },
      },
    },
  ],
  'public-database': [
    {
      id: 'disable-public-access',
      name: 'Disable Public Accessibility',
      description: 'Set PubliclyAccessible=false on RDS/Cloud SQL — restrict access to VPC/private network only',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'public-database-deny',
      remediation_guide: {
        aws: { title: 'Disable public access on RDS', steps: ['aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible --apply-immediately'] },
        gcp: { title: 'Disable public IP on Cloud SQL', steps: ['gcloud sql instances patch <INSTANCE> --no-assign-ip'] },
      },
    },
    {
      id: 'require-iam-auth',
      name: 'Enable IAM Database Authentication',
      description: 'Replace password auth with IAM database authentication for short-lived token-based access',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['iam-auth-supported'], effort: 'days', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'db-iam-auth-required',
      remediation_guide: {
        aws: { title: 'Enable IAM authentication on RDS', steps: ['aws rds modify-db-instance --db-instance-identifier <DB_ID> --enable-iam-database-authentication --apply-immediately'] },
        gcp: { title: 'Enable IAM authentication on Cloud SQL', steps: ['gcloud sql instances patch <INSTANCE> --database-flags=cloudsql.iam_authentication=on'] },
      },
    },
  ],
  'unencrypted-data-store': [
    {
      id: 'enable-encryption',
      name: 'Enable Encryption at Rest',
      description: 'Enable server-side encryption with KMS customer-managed key for data at rest',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: ['kms-key-available'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'encryption-at-rest-required',
      remediation_guide: {
        aws: { title: 'Enable SSE-KMS encryption', steps: ['aws s3api put-bucket-encryption --bucket <BUCKET> --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<KMS_KEY_ARN>"}}]}\''] },
        gcp: { title: 'Enable CMEK encryption on GCS', steps: ['gcloud storage buckets update gs://<BUCKET> --default-encryption-key=projects/<PROJECT>/locations/<LOCATION>/keyRings/<RING>/cryptoKeys/<KEY>'] },
      },
    },
    {
      id: 'enable-backup-pitr',
      name: 'Enable Backup & Point-in-Time Recovery',
      description: 'Enable automated backups and PITR to protect against data loss and ransomware',
      action_type: 'harden',
      remediation_type: 'infra',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.4 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'backup-pitr-required',
      remediation_guide: {
        aws: { title: 'Enable automated backups and PITR', steps: ['aws rds modify-db-instance --db-instance-identifier <DB_ID> --backup-retention-period 7 --apply-immediately'] },
        gcp: { title: 'Enable automated backups on Cloud SQL', steps: ['gcloud sql instances patch <INSTANCE> --backup-start-time=02:00 --enable-point-in-time-recovery'] },
      },
    },
  ],
  'overly-permissive-sg': [
    {
      id: 'restrict-sg-ingress',
      name: 'Restrict Security Group Ingress',
      description: 'Replace 0.0.0.0/0 ingress rules with specific CIDR ranges or security group references',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'restrict-sg-public-ingress',
      remediation_guide: {
        aws: { title: 'Restrict security group to specific CIDRs', steps: ['aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 0-65535 --cidr 0.0.0.0/0', 'aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port <PORT> --cidr <ALLOWED_CIDR>'] },
        gcp: { title: 'Restrict firewall rules', steps: ['gcloud compute firewall-rules update <RULE> --source-ranges=<ALLOWED_CIDR>'] },
      },
    },
    {
      id: 'use-private-subnets',
      name: 'Move Workloads to Private Subnets',
      description: 'Move workloads behind NAT gateway in private subnets — use ALB/NLB for internet access',
      action_type: 'architecture',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['vpc-available'], effort: 'days', automated: false },
      operational: { implementation: 5, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'private-subnet-required',
      remediation_guide: {
        aws: { title: 'Move to private subnet with NAT gateway', steps: ['aws ec2 create-nat-gateway --subnet-id <PUBLIC_SUBNET> --allocation-id <EIP_ALLOC>', 'aws ec2 create-route --route-table-id <PRIVATE_RT> --destination-cidr-block 0.0.0.0/0 --nat-gateway-id <NAT_GW_ID>'] },
      },
    },
  ],
  'unrotated-kms-key': [
    {
      id: 'enable-key-rotation',
      name: 'Enable Automatic Key Rotation',
      description: 'Enable annual automatic rotation for customer-managed KMS keys',
      action_type: 'harden',
      remediation_type: 'infra',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'kms-rotation-required',
      remediation_guide: {
        aws: { title: 'Enable automatic KMS key rotation', steps: ['aws kms enable-key-rotation --key-id <KEY_ID>'] },
        gcp: { title: 'Set rotation period on CMEK key', steps: ['gcloud kms keys update <KEY> --keyring=<RING> --location=<LOC> --rotation-period=365d --next-rotation-time=$(date -d "+365 days" +%Y-%m-%dT%H:%M:%SZ)'] },
      },
    },
  ],
  'stale-secret': [
    {
      id: 'enable-secret-rotation',
      name: 'Enable Automatic Secret Rotation',
      description: 'Configure automatic rotation via Lambda/Cloud Function with 90-day maximum rotation period',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: ['rotation-lambda-available'], effort: 'days', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'secret-rotation-required',
      remediation_guide: {
        aws: { title: 'Configure automatic rotation with Lambda', steps: ['aws secretsmanager rotate-secret --secret-id <SECRET_ID> --rotation-lambda-arn <LAMBDA_ARN> --rotation-rules AutomaticallyAfterDays=90'] },
        gcp: { title: 'Configure automatic rotation', steps: ['gcloud secrets update <SECRET> --next-rotation-time=$(date -d "+90 days" +%Y-%m-%dT%H:%M:%SZ) --rotation-period=7776000s'] },
      },
    },
    {
      id: 'rotate-now',
      name: 'Rotate Secret Immediately',
      description: 'Perform immediate manual rotation of the stale secret and update all consumers',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'credential-rotation-overdue',
      remediation_guide: {
        aws: { title: 'Rotate secret immediately', steps: ['aws secretsmanager rotate-secret --secret-id <SECRET_ID>'] },
        gcp: { title: 'Create new secret version', steps: ['echo -n "<NEW_VALUE>" | gcloud secrets versions add <SECRET> --data-file=-', 'gcloud secrets versions disable <OLD_VERSION> --secret=<SECRET>'] },
      },
    },
  ],
  'internet-to-data': [
    {
      id: 'break-internet-path',
      name: 'Break Internet-to-Data Path',
      description: 'Remove public exposure on entry point, move to private subnet, or add WAF/API gateway as intermediary',
      action_type: 'architecture',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 5, ongoing_toil: 1, expertise: 'high' },
      template_id: 'internal-service-isolation',
      remediation_guide: {
        aws: { title: 'Break internet-to-data path', steps: ['aws ec2 modify-instance-attribute --instance-id <ID> --no-source-dest-check', 'aws wafv2 create-web-acl --name <NAME> --scope REGIONAL --default-action Block={}'] },
        gcp: { title: 'Add Cloud Armor + IAP for internal protection', steps: ['gcloud compute security-policies create <POLICY>', 'gcloud compute backend-services update <BACKEND> --security-policy=<POLICY>'] },
      },
    },
    {
      id: 'least-privilege-data-access',
      name: 'Enforce Least-Privilege Data Access',
      description: 'Restrict IAM policies to specific resources — no wildcard (*) on data store access',
      action_type: 'harden',
      remediation_type: 'iac',
      path_break: { edge_position: 'resource', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 4, ongoing_toil: 2, expertise: 'medium' },
      template_id: 'no-wildcard-permissions',
      remediation_guide: {
        aws: { title: 'Restrict data access to specific resources', steps: ['aws iam put-role-policy --role-name <ROLE> --policy-name LeastPrivData --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::<BUCKET>/<PREFIX>/*"}]}\''] },
        gcp: { title: 'Restrict data access with IAM conditions', steps: ['gcloud storage buckets add-iam-policy-binding gs://<BUCKET> --member=serviceAccount:<SA> --role=roles/storage.objectViewer --condition=expression="resource.name.startsWith(\\"projects/_/buckets/<BUCKET>/objects/<PREFIX>\\")",title=restrict-prefix'] },
      },
    },
  ],

  // ═══════════════════════════════════════════════════════════════════
  // Classification-based finding types — Enforcement Ladder
  // ═══════════════════════════════════════════════════════════════════

  'zombie-workload': [
    {
      id: 'notify-owner-zombie',
      name: 'Notify Owner — Request Justification',
      description: 'Alert the registered owner or team and request a justification for keeping the workload alive. Auto-escalate if no response within 14 days.',
      action_type: 'notify',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.3 },
      feasibility: { preconditions: [], effort: 'minutes', automated: true },
      operational: { implementation: 1, ongoing_toil: 1, expertise: 'low' },
      template_id: 'stale-credential-lifecycle',
    },
    {
      id: 'quarantine-zombie-access',
      name: 'Quarantine — Revoke Active Credentials',
      description: 'Revoke all active credentials and API keys attached to this dormant workload. Block outbound access via policy.',
      action_type: 'contain',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 2, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'inactivity-timeout-30',
      remediation_guide: {
        aws: {
          title: 'Deactivate all access keys and delete login profile',
          steps: [
            'aws iam list-access-keys --user-name <USER> --query "AccessKeyMetadata[].AccessKeyId" --output text | xargs -I{} aws iam update-access-key --access-key-id {} --status Inactive --user-name <USER>',
            'aws iam delete-login-profile --user-name <USER>',
          ],
          terraform: 'resource "aws_iam_access_key" "revoke" {\n  user   = "<USER>"\n  status = "Inactive"\n}',
        },
        gcp: {
          title: 'Disable service account and revoke keys',
          steps: [
            'gcloud iam service-accounts disable <SA_EMAIL>',
            'gcloud iam service-accounts keys list --iam-account=<SA_EMAIL> --format="value(name)" | xargs -I{} gcloud iam service-accounts keys delete {} --iam-account=<SA_EMAIL> --quiet',
          ],
        },
      },
    },
    {
      id: 'schedule-decommission',
      name: 'Schedule Decommission — 30-Day Grace',
      description: 'Create decommission ticket with 30-day grace period. If unclaimed, delete workload and all associated resources.',
      action_type: 'decommission',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'max-credential-age',
      remediation_guide: {
        aws: {
          title: 'Delete the IAM role after grace period',
          steps: [
            'aws iam list-attached-role-policies --role-name <ROLE> --query "AttachedPolicies[].PolicyArn" --output text | xargs -I{} aws iam detach-role-policy --role-name <ROLE> --policy-arn {}',
            'aws iam delete-role --role-name <ROLE>',
          ],
        },
        gcp: {
          title: 'Delete the service account after grace period',
          steps: [
            'gcloud iam service-accounts delete <SA_EMAIL> --quiet',
          ],
        },
      },
    },
  ],

  'rogue-workload': [
    {
      id: 'contain-rogue-access',
      name: 'Contain — Restrict Network + Credential Scope',
      description: 'Immediately apply restrictive policy: deny outbound to sensitive APIs, limit IAM permissions to read-only, add monitoring.',
      action_type: 'contain',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: null,
      remediation_guide: {
        aws: {
          title: 'Attach deny-all inline policy to contain the role',
          steps: [
            'aws iam put-role-policy --role-name <ROLE> --policy-name DenyAll-Containment --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}\'',
          ],
          terraform: 'resource "aws_iam_role_policy" "deny_all" {\n  name   = "DenyAll-Containment"\n  role   = "<ROLE>"\n  policy = jsonencode({\n    Version = "2012-10-17"\n    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]\n  })\n}',
        },
        gcp: {
          title: 'Revoke all roles from the service account',
          steps: [
            'gcloud projects get-iam-policy <PROJECT> --format=json | jq -r ".bindings[] | select(.members[] | contains(\\"<SA_EMAIL>\\")) | .role" | xargs -I{} gcloud projects remove-iam-policy-binding <PROJECT> --member=serviceAccount:<SA_EMAIL> --role={}',
            'gcloud iam service-accounts disable <SA_EMAIL>',
          ],
        },
      },
    },
    {
      id: 'require-attestation-rogue',
      name: 'Require Attestation Before Access',
      description: 'Force workload through cryptographic attestation before allowing any API calls. Block until identity is verified.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.95 },
      feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true },
      operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'require-cryptographic-attestation',
    },
    {
      id: 'escalate-to-security',
      name: 'Escalate — Security Incident',
      description: 'Create a security incident ticket and notify the security team. Include cross-account trust analysis and blast radius.',
      action_type: 'escalate',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'minutes', automated: true },
      operational: { implementation: 1, ongoing_toil: 2, expertise: 'low' },
      template_id: null,
    },
  ],

  'unused-iam-role': [
    {
      id: 'tag-for-review',
      name: 'Tag for Review — Notify Team',
      description: 'Add review-required tag and notify the owning team. Request confirmation that the role is still needed within 14 days.',
      action_type: 'notify',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.2 },
      feasibility: { preconditions: [], effort: 'minutes', automated: true },
      operational: { implementation: 1, ongoing_toil: 1, expertise: 'low' },
      template_id: 'stale-credential-lifecycle',
      remediation_guide: {
        aws: {
          title: 'Tag the role for review',
          steps: [
            'aws iam tag-role --role-name <ROLE> --tags Key=review-required,Value=true Key=review-deadline,Value=$(date -d "+14 days" +%Y-%m-%d)',
          ],
        },
        gcp: {
          title: 'Add review label to service account',
          steps: [
            'gcloud iam service-accounts update <SA_EMAIL> --description="REVIEW REQUIRED - unused since <DATE>"',
          ],
        },
      },
    },
    {
      id: 'detach-permissions',
      name: 'Detach Policies — Keep Role for Audit',
      description: 'Remove all attached and inline policies from the role (zero permissions). Keep the role entity for audit trail.',
      action_type: 'contain',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'inactivity-timeout-30',
      remediation_guide: {
        aws: {
          title: 'Detach all policies from the role',
          steps: [
            'aws iam list-attached-role-policies --role-name <ROLE> --query "AttachedPolicies[].PolicyArn" --output text | xargs -I{} aws iam detach-role-policy --role-name <ROLE> --policy-arn {}',
            'aws iam list-role-policies --role-name <ROLE> --query "PolicyNames[]" --output text | xargs -I{} aws iam delete-role-policy --role-name <ROLE> --policy-name {}',
          ],
        },
        gcp: {
          title: 'Remove all IAM bindings for the service account',
          steps: [
            'gcloud projects get-iam-policy <PROJECT> --format=json | jq -r ".bindings[] | select(.members[] | contains(\\"<SA_EMAIL>\\")) | .role" | xargs -I{} gcloud projects remove-iam-policy-binding <PROJECT> --member=serviceAccount:<SA_EMAIL> --role={}',
          ],
        },
      },
    },
    {
      id: 'schedule-role-deletion',
      name: 'Delete Identity',
      description: 'Delete the unused IAM role/group/user after review. Remove all associated resources.',
      action_type: 'decommission',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'max-credential-age',
      remediation_guide: {
        aws: {
          title: 'Delete the IAM role',
          steps: [
            'aws iam delete-role --role-name <ROLE>',
          ],
        },
        gcp: {
          title: 'Delete the service account',
          steps: [
            'gcloud iam service-accounts delete <SA_EMAIL> --quiet',
          ],
        },
      },
    },
  ],

  'public-exposure-untagged': [
    {
      id: 'require-approval-tag',
      name: 'Require Security Approval Tag',
      description: 'Enforce that all publicly accessible resources must have an approved-public tag from the security team before remaining public.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'public-resource-approval-required',
      remediation_guide: {
        aws: {
          title: 'Add approved-public tag to the resource',
          steps: [
            'aws s3api put-bucket-tagging --bucket <BUCKET> --tagging TagSet=[{Key=approved-public,Value=true},{Key=approved-by,Value=<YOUR_TEAM>}]',
          ],
        },
        gcp: {
          title: 'Add approved-public label',
          steps: [
            'gcloud storage buckets update gs://<BUCKET> --update-labels=approved-public=true,approved-by=<YOUR_TEAM>',
          ],
        },
      },
    },
    {
      id: 'restrict-public-access',
      name: 'Restrict Public Access',
      description: 'Enable S3 Block Public Access, disable RDS PubliclyAccessible flag, or restrict Security Group to internal CIDRs.',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'restrict-public-access',
      remediation_guide: {
        aws: {
          title: 'Block public access on S3 / restrict RDS / lock Security Groups',
          steps: [
            'aws s3api put-public-access-block --bucket <BUCKET> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true',
            'aws rds modify-db-instance --db-instance-identifier <DB_ID> --no-publicly-accessible --apply-immediately',
            'aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 0-65535 --cidr 0.0.0.0/0',
          ],
          terraform: 'resource "aws_s3_bucket_public_access_block" "block" {\n  bucket                  = "<BUCKET>"\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}',
        },
        gcp: {
          title: 'Enable public access prevention on GCS / restrict Cloud SQL',
          steps: [
            'gcloud storage buckets update gs://<BUCKET> --public-access-prevention=enforced',
            'gcloud sql instances patch <INSTANCE> --no-assign-ip',
          ],
        },
      },
    },
  ],

  'orphaned-asset': [
    {
      id: 'assign-owner-orphan',
      name: 'Assign Owner — Infrastructure Triage',
      description: 'Auto-assign to the infrastructure/platform team for triage. Request owner identification within 7 days.',
      action_type: 'notify',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.2 },
      feasibility: { preconditions: [], effort: 'minutes', automated: true },
      operational: { implementation: 1, ongoing_toil: 1, expertise: 'low' },
      template_id: null,
    },
    {
      id: 'quarantine-orphan',
      name: 'Quarantine — Isolate Resource',
      description: 'Move to quarantine VPC/subnet or apply deny-all network policy. Prevent any external or internal access.',
      action_type: 'contain',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' },
      template_id: null,
      remediation_guide: {
        aws: {
          title: 'Disable the orphaned identity',
          steps: [
            'aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER>',
            'aws iam put-role-policy --role-name <ROLE> --policy-name DenyAll --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}\'',
          ],
        },
        gcp: {
          title: 'Disable the orphaned service account',
          steps: [
            'gcloud iam service-accounts disable <SA_EMAIL>',
          ],
        },
      },
    },
    {
      id: 'schedule-cleanup-orphan',
      name: 'Schedule Cleanup — 60-Day Grace',
      description: 'Decommission after 60-day unclaimed period. Archive metadata before deletion for audit.',
      action_type: 'decommission',
      remediation_type: 'iac',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: [], effort: 'days', automated: false },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: null,
      remediation_guide: {
        aws: {
          title: 'Delete the orphaned identity',
          steps: [
            'aws iam delete-role --role-name <ROLE>',
            'aws iam delete-user --user-name <USER>',
          ],
        },
        gcp: {
          title: 'Delete the orphaned service account',
          steps: [
            'gcloud iam service-accounts delete <SA_EMAIL> --quiet',
          ],
        },
      },
    },
  ],

  'account-outside-org': [
    {
      id: 'validate-account',
      name: 'Validate Account Ownership',
      description: 'Verify that the external account belongs to the organization. Cross-reference with AWS Organizations or manual inventory.',
      action_type: 'investigate',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 2, expertise: 'medium' },
      template_id: null,
    },
    {
      id: 'require-external-id-account',
      name: 'Mandate ExternalId on Cross-Account Trust',
      description: 'Require ExternalId condition on all AssumeRole trust policies for cross-account access. Prevents confused deputy attacks.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'cross-account-trust-policy',
    },
  ],

  // ── Cloud AI Service Finding Types ──

  'unregistered-ai-endpoint': [
    {
      id: 'register-ai-endpoint',
      name: 'Register AI Endpoint in Governance',
      description: 'Register this AI endpoint in the organization AI registry with owner, data classification, and usage policy.',
      action_type: 'governance',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.6 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'ai-endpoint-registration',
    },
    {
      id: 'restrict-ai-endpoint-access',
      name: 'Restrict Endpoint to VPC',
      description: 'Move AI endpoint from public to VPC-only access using Private Service Connect or VPC peering.',
      action_type: 'harden',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: ['vpc-available'], effort: 'days', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'ai-vpc-only',
      remediation_guide: {
        gcp: {
          title: 'Move Vertex AI endpoint to VPC',
          steps: [
            'gcloud ai endpoints update <ENDPOINT_ID> --region=<REGION> --network=projects/<PROJECT>/global/networks/<VPC>',
            'Verify private connectivity: gcloud ai endpoints describe <ENDPOINT_ID> --region=<REGION>',
          ],
        },
      },
    },
  ],

  'shadow-ai-usage': [
    {
      id: 'register-shadow-ai',
      name: 'Register Shadow AI Usage',
      description: 'This workload is calling AI APIs without governance approval. Register the usage and apply rate limiting.',
      action_type: 'governance',
      remediation_type: 'process',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'shadow-ai-detection',
    },
    {
      id: 'route-through-llm-gateway',
      name: 'Route Through LLM Gateway',
      description: 'Channel all AI API calls through a centralized LLM gateway (e.g., LiteLLM) for cost tracking, rate limiting, and audit logging.',
      action_type: 'architecture',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['llm-gateway-available'], effort: 'days', automated: true },
      operational: { implementation: 4, ongoing_toil: 1, expertise: 'medium' },
      template_id: 'llm-gateway-enforcement',
    },
  ],

  'ai-permission-without-workload': [
    {
      id: 'audit-ai-permission',
      name: 'Audit AI Permission Grant',
      description: 'This identity has AI platform permissions but no registered AI workload. Investigate and either revoke the permission or register the workload.',
      action_type: 'investigate',
      remediation_type: 'process',
      path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'ai-permission-audit',
    },
    {
      id: 'revoke-ai-permission',
      name: 'Revoke Unused AI Permission',
      description: 'Remove AI platform permissions from this identity as no AI workload is using them. Follows least-privilege principle.',
      action_type: 'remediate',
      remediation_type: 'iac',
      path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: ['no-active-ai-workload'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'ai-permission-revoke',
      remediation_guide: {
        gcp: {
          title: 'Revoke AI Platform roles from service account',
          steps: [
            'gcloud projects remove-iam-policy-binding <PROJECT> --member=serviceAccount:<SA_EMAIL> --role=roles/aiplatform.user',
          ],
        },
        aws: {
          title: 'Revoke Bedrock/SageMaker permissions',
          steps: [
            'aws iam detach-role-policy --role-name <ROLE> --policy-arn <POLICY_ARN>',
          ],
        },
      },
    },
  ],

  'public-ai-endpoint': [
    {
      id: 'restrict-public-ai',
      name: 'Remove Public Access from AI Endpoint',
      description: 'AI inference endpoint is publicly accessible. Restrict to VPC-only access to prevent unauthorized model invocation.',
      action_type: 'remediate',
      remediation_type: 'infra',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 },
      feasibility: { preconditions: ['vpc-available'], effort: 'hours', automated: true },
      operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
      template_id: 'public-ai-endpoint-lockdown',
    },
    {
      id: 'add-ai-auth',
      name: 'Enforce Authentication on AI Endpoint',
      description: 'Require IAM authentication or API key for all requests to this AI inference endpoint.',
      action_type: 'harden',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
      template_id: 'ai-endpoint-auth',
    },
  ],
  'mcp-capability-drift': [
    {
      id: 'mcp-drift-investigate',
      name: 'Investigate Capability Change',
      description: 'MCP server capabilities changed since last scan. Investigate whether the change was authorized and review all tool invocations since the change.',
      action_type: 'investigate',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.5 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 2, expertise: 'medium' },
      template_id: null,
    },
    {
      id: 'mcp-drift-pin-version',
      name: 'Pin MCP Server Version',
      description: 'Pin the MCP server to a specific known-good version to prevent unauthorized capability changes.',
      action_type: 'harden',
      remediation_type: 'code_change',
      path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.7 },
      feasibility: { preconditions: [], effort: 'hours', automated: true },
      operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' },
      template_id: 'mcp-integrity-verification',
    },
  ],
  'a2a-invalid-signature': [
    {
      id: 'a2a-investigate-invalid-sig',
      name: 'Investigate Tampered Card',
      description: 'Agent Card cryptographic signature is invalid — the card content may have been tampered with. Audit the agent and its deployment.',
      action_type: 'investigate',
      remediation_type: 'process',
      path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.8 },
      feasibility: { preconditions: [], effort: 'hours', automated: false },
      operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' },
      template_id: null,
    },
    {
      id: 'a2a-block-invalid-sig',
      name: 'Block Invalid Signatures',
      description: 'Deploy policy to deny task delegation to A2A agents with invalid or missing signatures.',
      action_type: 'policy',
      remediation_type: 'policy',
      path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 },
      feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true },
      operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' },
      template_id: 'a2a-agent-card-signing',
    },
  ],
};

function scoreControls(attackPath, allNodes, allRels) {
  const findingType = attackPath.finding_type || attackPath.type;
  let candidates = [...(CONTROL_CATALOG[findingType] || [])];

  // Fallback: when no catalog entry exists, derive controls from node properties
  if (candidates.length === 0) {
    // Look up the actual workload node to get trust_level and credentials
    const wName = (attackPath.workload || '').toLowerCase();
    const wNode = wName ? allNodes.find(n =>
      (n.label || '').toLowerCase() === wName &&
      ['workload', 'a2a-agent', 'mcp-server', 'container', 'cloud-run', 'cloud-run-service'].includes(n.type)
    ) : null;
    const nodeTrust = wNode?.trust || attackPath.trust_level || 'none';
    if (['none', 'low'].includes(nodeTrust)) {
      candidates.push({
        id: `fallback-attest-${findingType || 'unknown'}`,
        name: 'Require Cryptographic Attestation',
        description: `Upgrade trust from "${nodeTrust}" via SPIRE workload attestation`,
        action_type: 'policy',
        path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 },
        feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true },
        operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' },
        template_id: 'prod-attestation-required',
      });
    }
    const creds = attackPath.credentials || attackPath.env_keys || wNode?.metadata?.credentials || [];
    if (creds.length > 0) {
      candidates.push({
        id: `fallback-jit-${findingType || 'unknown'}`,
        name: 'Replace Static Credentials with JIT Tokens',
        description: `Replace ${creds.length} static credential(s) with short-lived SPIFFE-bound JIT tokens`,
        action_type: 'replace',
        path_break: { edge_position: 'credential', edges_severed: creds.length, crown_jewel_proximity: 0.8 },
        feasibility: { preconditions: ['edge-gateway-deployed'], effort: 'hours', automated: true },
        operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' },
        template_id: 'jit-credential-required',
      });
    }
    if (candidates.length === 0) return [];
  }

  // Compute blast radius from graph topology
  const workloadName = (attackPath.workload || '').toLowerCase();
  const connectedNodeIds = new Set();
  const affectedWorkloads = [];

  // Guard: .includes('') matches every node — use exact/prefix match only when name is present
  if (workloadName) {
    for (const n of allNodes) {
      const nl = (n.label || '').toLowerCase();
      if (nl === workloadName || nl.startsWith(workloadName + '-') || nl.startsWith(workloadName + ' ')) {
        connectedNodeIds.add(n.id);
      }
    }
  } else if (attackPath.nodes?.length) {
    // Fallback: seed BFS from the attack path node list (shared-sa, key-leak etc.)
    for (const nid of attackPath.nodes.slice(0, 10)) connectedNodeIds.add(nid);
  } else if (attackPath.entry_points?.length) {
    for (const ep of attackPath.entry_points) {
      const n = allNodes.find(x => (x.label || '').toLowerCase() === ep.toLowerCase());
      if (n) connectedNodeIds.add(n.id);
    }
  }
  // BFS to find all reachable from affected workload
  const queue = [...connectedNodeIds];
  const visited = new Set(queue);
  while (queue.length > 0) {
    const current = queue.shift();
    for (const r of allRels) {
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      if (s === current && !visited.has(t)) { visited.add(t); queue.push(t); connectedNodeIds.add(t); }
      if (t === current && !visited.has(s)) { visited.add(s); queue.push(s); connectedNodeIds.add(s); }
    }
  }
  // Find workload names in blast zone
  for (const nid of connectedNodeIds) {
    const n = allNodes.find(nd => nd.id === nid);
    if (n && (n.type === 'workload' || n.type === 'a2a-agent' || n.type === 'mcp-server')) {
      affectedWorkloads.push(n.label || n.id);
    }
  }

  const blastRadius = connectedNodeIds.size;
  const crownJewelNearby = allNodes.some(n =>
    connectedNodeIds.has(n.id) && (n.type === 'external-resource' || n.workload_type === 'external-resource')
  );

  // Score each control
  const scored = candidates.map(ctrl => {
    // 1. Path Break Strength (0-100, weight 40%)
    const edgePositionScore = ctrl.path_break.edge_position === 'entry' ? 100
      : ctrl.path_break.edge_position === 'credential' ? 70 : 40;
    const edgesSevered = Math.min(ctrl.path_break.edges_severed * 35, 100);
    const crownJewel = ctrl.path_break.crown_jewel_proximity * (crownJewelNearby ? 100 : 50);
    const pathBreakScore = (edgePositionScore * 0.4 + edgesSevered * 0.3 + crownJewel * 0.3);

    // 2. Feasibility (0 or 1 — hard gate)
    // For demo: assume most preconditions are met except complex ones
    const hardPreconditions = ['can-split-workload', 'delegation-chain-available', 'approval-workflow'];
    const feasible = !ctrl.feasibility.preconditions.some(p => hardPreconditions.includes(p));
    const feasibilityScore = feasible ? 1.0 : 0.3; // Not fully blocked, just heavily penalized

    // 3. Blast Radius (0-100 INVERSE, weight 20%)
    // Fewer workloads affected = higher score
    const maxBlast = Math.max(blastRadius, 1);
    const controlBlastEstimate = ctrl.path_break.edges_severed > 1 ? maxBlast : Math.ceil(maxBlast * 0.5);
    const blastScore = Math.max(0, 100 - (controlBlastEstimate * 8)); // 8 points per workload

    // 4. Operational Cost (0-100 INVERSE, weight 20%)
    const effortMap = { 1: 95, 2: 80, 3: 65, 4: 50, 5: 35, 8: 15 };
    const toilMap = { 0: 100, 1: 75, 2: 50, 3: 25 };
    const expertiseMap = { low: 100, medium: 60, high: 25 };
    const opScore = (
      (effortMap[ctrl.operational.implementation] || 50) * 0.5 +
      (toilMap[ctrl.operational.ongoing_toil] || 50) * 0.25 +
      (expertiseMap[ctrl.operational.expertise] || 50) * 0.25
    );

    // 5. Confidence (0-100, weight 20%)
    // Based on evidence completeness and control type
    const typeConfidence = { policy: 90, replace: 80, harden: 70, remediate: 85, architecture: 60 };
    const confidenceScore = typeConfidence[ctrl.action_type] || 70;

    // Composite score
    const composite = Math.round(
      pathBreakScore * 0.40 * feasibilityScore +
      blastScore * 0.20 +
      opScore * 0.20 +
      confidenceScore * 0.20
    );

    return {
      ...ctrl,
      score: {
        composite,
        path_break: Math.round(pathBreakScore),
        feasibility: feasibilityScore === 1.0 ? 'met' : 'partial',
        blast_radius: Math.round(blastScore),
        operational_cost: Math.round(opScore),
        confidence: confidenceScore,
      },
      blast_estimate: {
        workloads_affected: controlBlastEstimate,
        total_in_zone: blastRadius,
        affected_workload_names: affectedWorkloads.slice(0, 5),
      },
    };
  });

  // Sort by composite score descending
  scored.sort((a, b) => b.score.composite - a.score.composite);
  return scored;
}

// Compute credential chain for an attack path
function computeCredentialChain(attackPath, allNodes, allRels) {
  const workloadName = (attackPath.workload || '').toLowerCase();
  const chain = [];

  // Find identity node
  const identityNode = allNodes.find(n =>
    (n.label || '').toLowerCase() === workloadName &&
    (n.type === 'workload' || n.type === 'a2a-agent' || n.type === 'mcp-server')
  );
  if (!identityNode) return chain;
  chain.push({ id: identityNode.id, label: identityNode.label, type: 'identity', node_type: identityNode.type });

  // Find credentials connected to this identity
  for (const r of allRels) {
    const s = typeof r.source === 'object' ? r.source.id : r.source;
    const t = typeof r.target === 'object' ? r.target.id : r.target;
    if (s === identityNode.id && r.type === 'holds-credential') {
      const credNode = allNodes.find(n => n.id === t);
      if (credNode) {
        chain.push({ id: credNode.id, label: credNode.label, type: 'credential', node_type: credNode.type, relationship: r.type });
        // Find resource connected to this credential
        for (const r2 of allRels) {
          const s2 = typeof r2.source === 'object' ? r2.source.id : r2.source;
          const t2 = typeof r2.target === 'object' ? r2.target.id : r2.target;
          if (s2 === credNode.id && r2.type === 'accesses-api') {
            const resNode = allNodes.find(n => n.id === t2);
            if (resNode) {
              chain.push({ id: resNode.id, label: resNode.label, type: 'resource', node_type: resNode.type, relationship: r2.type });
            }
          }
        }
      }
    }
  }
  return chain;
}

// ── Build graph from DB workloads ──
async function buildGraph(dbClient) {
  // Fetch all workloads
  const result = await dbClient.query(`
    SELECT id, spiffe_id, name, type, namespace, environment,
           category, subcategory, cloud_provider, region, account_id,
           security_score, verified, trust_level,
           is_shadow, is_dormant, shadow_score, dormancy_score,
           shadow_reasons, dormancy_reasons, cost_center,
           is_rogue, rogue_score, rogue_reasons,
           is_orphan, orphan_reasons,
           is_publicly_exposed, exposure_reasons,
           is_unused_iam,
           classification, classification_tags,
           owner, team, labels, metadata,
           attestation_data, last_attestation, attestation_expires
    FROM workloads
    WHERE name NOT IN ('__federation_config__', 'Public Internet', 'Internal VPC', 'federation')
      AND NOT (
        cloud_provider = 'aws'
        AND type IN ('iam-role', 'iam-user', 'iam-group')
        AND (metadata->>'is_service_linked')::boolean IS TRUE
      )
    ORDER BY created_at DESC LIMIT 500
  `);

  const workloads = result.rows;

  // Group by provider and run relationship scanner for each
  const byProvider = {};
  for (const w of workloads) {
    const p = w.cloud_provider || 'unknown';
    (byProvider[p] = byProvider[p] || []).push(w);
  }

  // Merge graphs from all providers
  let allNodes = [];
  let allRels = [];
  let allPaths = [];

  for (const [provider, providerWorkloads] of Object.entries(byProvider)) {
    const scanner = new RelationshipScanner({
      project: process.env.GCP_PROJECT_ID,
      region: process.env.AWS_DEFAULT_REGION || 'us-east-1',
      subscriptionId: process.env.AZURE_SUBSCRIPTION_ID,
    });

    const graph = await scanner.discover(providerWorkloads, provider);
    allNodes.push(...graph.nodes);
    allRels.push(...graph.relationships);
    allPaths.push(...(graph.attack_paths || []));
    // Scanner findings (a2a-unsigned-card, a2a-invalid-signature, etc.)
    if (graph.findings?.length) allPaths.push(...graph.findings);
  }

  // ═══════════════════════════════════════════════════════════════════════
  // SINGLE SOURCE OF TRUTH: Workload DB is canonical for credentials & resources.
  // Protocol scanner nodes for credentials/resources are removed from the graph.
  // Only scanner-generated findings, attack paths, and identity relationships are kept.
  // ═══════════════════════════════════════════════════════════════════════

  // Step 1: Dedupe nodes by id
  const nodeMap = {};
  for (const n of allNodes) nodeMap[n.id] = n;
  allNodes = Object.values(nodeMap);

  // Step 2: Remove scanner-generated credential/resource nodes (they duplicate DB entries)
  // Build a set of names that belong to DB credentials/resources (all case variants + slugs)
  const dbCredResourceNames = new Set();
  for (const w of workloads) {
    if (w.type !== 'credential' && w.type !== 'external-resource') continue;
    const name = (w.name || '').toLowerCase();
    const slug = name.replace(/\s+/g, '-');
    dbCredResourceNames.add(name);
    dbCredResourceNames.add(slug); // "Stripe API Key" → "stripe-api-key"
    // Strip common suffixes: "stripe-api-key" → "stripe-api", "salesforce-oauth-token" → "salesforce-oauth"
    const stripped = slug.replace(/-(key|token|secret|cert|credential|cred)$/i, '');
    if (stripped !== slug) dbCredResourceNames.add(stripped);
    // Also add provider name as resource match (e.g. "stripe", "slack", "salesforce")
    const meta = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
    if (meta.provider) dbCredResourceNames.add(meta.provider.toLowerCase());
  }
  const removedIds = new Set();
  allNodes = allNodes.filter(n => {
    // Remove scanner-generated credential/external nodes (duplicated by DB in Step 3)
    // KEEP exposure nodes (exp:public, exp:internal) — infrastructure topology for attack paths
    const isExposure = n.group === 'exposure' || n.type === 'exposure';
    const isScannerType = !isExposure && (
      ['external', 'credential'].includes(n.group) ||
      ['external-api', 'external-credential', 'credential'].includes(n.type)
    );
    const isScannerName = !isExposure && dbCredResourceNames.has((n.label || '').toLowerCase());
    if (isScannerType || isScannerName) { removedIds.add(n.id); return false; }
    return true;
  });

  // Step 3: Inject DB-sourced credential & resource nodes into the graph
  const existingLabels = new Set(allNodes.map(n => (n.label || '').toLowerCase()));
  for (const w of workloads) {
    if (w.type !== 'credential' && w.type !== 'external-resource') continue;
    if (existingLabels.has((w.name || '').toLowerCase())) continue;

    const meta = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
    const isCredential = w.type === 'credential';
    const node = {
      id: `db:${w.id}`,
      label: w.name,
      type: isCredential ? 'credential' : 'external-resource',
      group: isCredential ? 'credential' : 'external',
      workload_id: w.id,
      nhi_bucket: isCredential ? 'credential' : 'resource',
      workload_type: w.type,
      trust: w.trust_level,
      score: w.security_score,
      owner: w.owner,
      team: w.team,
      verified: w.verified,
      risk: isCredential ? (meta.risk_level || 'medium') : 'low',
    };

    // Add enrichment data
    if (isCredential) {
      node.credential = {
        type: meta.credential_type || meta.subcategory,
        provider: meta.provider,
        parent_identity: meta.parent_identity,
        lifecycle_status: meta.lifecycle_status || 'active',
        risk_level: meta.risk_level || 'medium',
        risk_flags: meta.risk_flags || [],
        scope: meta.scope || [],
        storage_method: meta.storage_method,
        never_expires: meta.never_expires,
        last_rotated: meta.last_rotated,
      };
    } else {
      node.resource = {
        provider: meta.provider,
        parent_identity: meta.parent_identity,
        verification: meta.verification ? {
          score: meta.verification.composite_score,
          status: meta.verification.composite_status,
          tiers: (meta.verification.tiers || []).map(t => ({ tier: t.tier, label: t.label, score: t.score, status: t.status })),
        } : null,
      };
    }

    allNodes.push(node);
    existingLabels.add(w.name.toLowerCase());

    // Create relationships: parent_identity → credential → resource
    if (meta.parent_identity) {
      const parentNode = allNodes.find(n => (n.label || '').toLowerCase() === meta.parent_identity.toLowerCase());
      if (parentNode) {
        if (isCredential) {
          allRels.push({ id: `rel:${parentNode.id}->${node.id}`, source: parentNode.id, target: node.id, type: 'holds-credential', discovered_by: 'Workload identity metadata', evidence: `Parent identity ${parentNode.label} holds credential ${node.label}` });
        } else {
          // Resource: find credential for same provider, link credential → resource
          const credNode = allNodes.find(n => n.nhi_bucket === 'credential' && n.credential?.provider?.toLowerCase() === meta.provider?.toLowerCase());
          if (credNode) {
            allRels.push({ id: `rel:${credNode.id}->${node.id}`, source: credNode.id, target: node.id, type: 'accesses-api', discovered_by: 'Credential chain analysis', evidence: `Credential ${credNode.label} → resource ${node.label}` });
          } else {
            allRels.push({ id: `rel:${parentNode.id}->${node.id}`, source: parentNode.id, target: node.id, type: 'accesses-api', discovered_by: 'Workload identity metadata', evidence: `Identity ${parentNode.label} accesses ${node.label}` });
          }
        }
      }
    }
  }

  // Step 4: Enrich identity nodes with DB metadata, categories, and security scores
  const workloadByName = {};
  for (const w of workloads) {
    workloadByName[w.name] = w;
    workloadByName[w.name.toLowerCase()] = w;
  }
  for (const node of allNodes) {
    if (node.workload_id) continue; // already enriched (credentials/resources from Step 3)
    const w = workloadByName[node.label] || workloadByName[(node.label || '').toLowerCase()];
    if (w) {
      const meta = typeof w.metadata === 'string' ? (() => { try { return JSON.parse(w.metadata); } catch { return {}; } })() : (w.metadata || {});
      node.workload_id = w.id;
      node.wid = w.id;
      node.spiffeId = w.spiffe_id || node.spiffeId;
      node.nhi_bucket = 'identity';
      node.workload_type = w.type;

      // Trust level: use DB value, or compute from verification_method if missing
      node.trust = w.trust_level || determineTrustLevel(w.verification_method) || node.trust;

      // Security score: use DB value, or compute if 0/null
      node.score = (w.security_score && w.security_score > 0)
        ? w.security_score
        : calculateSecurityScore({ ...w, trust_level: node.trust });

      node.owner = w.owner;
      node.team = w.team;
      node.verified = w.verified;
      node.environment = w.environment;
      node.cost_center = w.cost_center;

      // Propagate attestation_data to node.meta so IETF AIMS mapper can derive attestation_type
      if (w.attestation_data) {
        node.meta = node.meta || {};
        node.meta.attestation_data = w.attestation_data;
      }
      // Classification fields
      node.is_shadow = w.is_shadow;
      node.shadow_score = w.shadow_score || 0;
      node.shadow_reasons = w.shadow_reasons || [];
      node.is_dormant = w.is_dormant;
      node.dormancy_score = w.dormancy_score || 0;
      node.dormancy_reasons = w.dormancy_reasons || [];
      node.is_rogue = w.is_rogue;
      node.rogue_score = w.rogue_score || 0;
      node.rogue_reasons = w.rogue_reasons || [];
      node.is_orphan = w.is_orphan;
      node.orphan_reasons = w.orphan_reasons || [];
      node.is_unused_iam = w.is_unused_iam;
      node.is_publicly_exposed = w.is_publicly_exposed;
      node.exposure_reasons = w.exposure_reasons || [];
      node.classification = w.classification || 'pending';
      node.classification_tags = w.classification_tags || [];

      // SPIRE/SPIFFE servers are attestation roots — auto-verify as cryptographic
      const nameLC = (w.name || '').toLowerCase();
      if (nameLC.includes('spire') || nameLC.includes('spiffe') || w.type === 'spire-server') {
        node.verified = true;
        if (!node.trust || node.trust === 'none') node.trust = 'cryptographic';
        if (!w.category) w.category = 'Infrastructure';
        if (!w.subcategory) w.subcategory = 'Service Mesh';
      }

      // AI agents: normalize type so frontend icon logic works consistently
      if (w.is_ai_agent && node.type !== 'a2a-agent' && node.type !== 'mcp-server') {
        node.type = 'a2a-agent';
      }
      if (w.is_mcp_server && node.type !== 'mcp-server') {
        node.type = 'mcp-server';
      }

      // Derive protocol/transport from type if not set by active probing
      node.meta = node.meta || {};
      if (!node.meta.protocol && !node.meta.transport) {
        if (node.type === 'a2a-agent') node.meta.protocol = 'a2a';
        else if (node.type === 'mcp-server') node.meta.protocol = 'mcp';
      }
      // Derive auth from labels if not set by active probing
      if (node.meta.has_auth === undefined) {
        const labels = w.labels || {};
        const authLabel = labels['a2a.auth'];
        if (authLabel) node.meta.has_auth = authLabel !== 'none';
      }

      // Category: use DB value, or detect from name/type
      const cat = detectCategory(w);
      node.category = w.category || cat.category;
      node.subcategory = w.subcategory || cat.subcategory;

      const credSummary = meta.credential_summary;
      if (credSummary) {
        node.credential_summary = {
          ...credSummary,
          count: credSummary.count ?? credSummary.total ?? 0,
          static_count: credSummary.static_count ?? credSummary.not_in_vault ?? 0,
          providers: credSummary.providers || (w.cloud_provider ? [w.cloud_provider] : []),
        };
      }

      // Attach full metadata so the frontend can display captured resource details
      node.metadata = meta;

      // Merge protocol-scanner fields into metadata (scanner stores in node.meta)
      if (node.meta) {
        if (node.meta.signature_status) node.metadata.signature_status = node.meta.signature_status;
        if (node.meta.signature_kid) node.metadata.signature_kid = node.meta.signature_kid;
        if (node.meta.is_signed !== undefined) node.metadata.is_signed = node.meta.is_signed;
      }

      // Preserve AI enrichment from protocol-scanner (fixes Bug 1 frontend gap)
      if (!node.ai_enrichment && meta.ai_enrichment) {
        node.ai_enrichment = meta.ai_enrichment;
      }

      // Expose meta fields the frontend reads for AI Agent panel
      node.meta = node.meta || {};
      if (meta.transport) node.meta.transport = meta.transport;
      if (meta.protocol) node.meta.protocol = meta.protocol;
      if (meta.skills) node.meta.skills = meta.skills;
      if (meta.tools) node.meta.tools = meta.tools;
      if (meta.requires_human_delegator !== undefined) node.meta.requires_human_delegator = meta.requires_human_delegator;
      if (meta.has_auth !== undefined) node.meta.has_auth = meta.has_auth;
      if (meta.is_signed !== undefined) node.meta.is_signed = meta.is_signed;
      if (meta.model) node.meta.model = meta.model;
      if (meta.embedding_model) node.meta.embedding_model = meta.embedding_model;
      if (meta.vector_store) node.meta.vector_store = meta.vector_store;
      if (meta.llm_providers) node.meta.llm_providers = meta.llm_providers;
      if (meta.human_in_loop !== undefined) node.meta.human_in_loop = meta.human_in_loop;
      if (meta.scope_ceiling) node.meta.scope_ceiling = meta.scope_ceiling;

      // Cloud resource details (IAM, storage, network, security scanners)
      if (meta.credentials) node.meta.credentials = meta.credentials;
      if (meta.instance_type) node.meta.instance_type = meta.instance_type;
      if (meta.runtime) node.meta.runtime = meta.runtime;
      if (meta.engine) node.meta.engine = meta.engine;
      if (meta.vpc_id) node.meta.vpc_id = meta.vpc_id;
      if (meta.security_groups) node.meta.security_groups = meta.security_groups;
      if (meta.publicly_accessible !== undefined) node.meta.publicly_accessible = meta.publicly_accessible;
      if (meta.storage_encrypted !== undefined) node.meta.storage_encrypted = meta.storage_encrypted;
      if (meta.rotation_enabled !== undefined) node.meta.rotation_enabled = meta.rotation_enabled;
      if (meta.is_public !== undefined) node.meta.is_public = meta.is_public;
      if (meta.ingress_rules) node.meta.ingress_rules = meta.ingress_rules;
      if (meta.allows_public_ingress !== undefined) node.meta.allows_public_ingress = meta.allows_public_ingress;
      if (meta.attached_policies) node.meta.attached_policies = meta.attached_policies;
      if (meta.inline_policies) node.meta.inline_policies = meta.inline_policies;
      if (meta.cross_account_trusts) node.meta.cross_account_trusts = meta.cross_account_trusts;
      if (meta.effective_permissions_summary) node.meta.effective_permissions_summary = meta.effective_permissions_summary;
    } else {
      // Scanner-only node (SA, role, exposure) — compute score from node properties
      if (!node.score || node.score === 0) {
        node.score = calculateSecurityScore({ trust_level: node.trust, verified: !!node.trust });
      }
      if (!node.category) {
        const cat = detectCategory({ name: node.label, type: node.type, metadata: node.meta || {} });
        node.category = cat.category;
        node.subcategory = cat.subcategory;
      }
    }
  }

  // Step 5: Clean up relationships pointing to removed nodes
  allRels = allRels.filter(r => {
    const s = typeof r.source === 'object' ? r.source.id : r.source;
    const t = typeof r.target === 'object' ? r.target.id : r.target;
    return !removedIds.has(s) && !removedIds.has(t);
  });

  // Dedupe rels — keep the version with richer provenance
  const relMap = {};
  for (const r of allRels) {
    const s = typeof r.source === 'object' ? r.source.id : r.source;
    const t = typeof r.target === 'object' ? r.target.id : r.target;
    const key = `${s}->${t}->${r.type}`;
    const existing = relMap[key];
    if (!existing) {
      relMap[key] = r;
    } else {
      // Merge: keep the version with discovered_by, or merge fields from both
      if (r.discovered_by && !existing.discovered_by) {
        relMap[key] = { ...existing, ...r };
      } else if (existing.discovered_by && !r.discovered_by) {
        relMap[key] = { ...r, ...existing };
      } else {
        // Both have provenance or neither does — keep existing, merge extra fields
        relMap[key] = { ...r, ...existing };
      }
    }
  }
  allRels = Object.values(relMap);

  // Step 6: Mark orphan nodes (no relationships) and classify service-linked roles
  const connectedIds = new Set();
  for (const r of allRels) {
    const s = typeof r.source === 'object' ? r.source.id : r.source;
    const t = typeof r.target === 'object' ? r.target.id : r.target;
    connectedIds.add(s);
    connectedIds.add(t);
  }
  const orphanUpdates = [];
  for (const node of allNodes) {
    const wasOrphan = node.is_orphan;
    node.is_orphan = !connectedIds.has(node.id);

    // Classify AWS service-linked roles
    const label = (node.label || '').toLowerCase();
    if (label.startsWith('awsservicerolefor')) {
      node.is_service_linked = true;
      node.subcategory = 'Service-Linked Role';
    }

    // Build orphan reasons
    if (node.is_orphan) {
      node.orphan_reasons = node.is_service_linked
        ? ['Service-linked role — expected orphan (auto-managed by AWS)']
        : ['No relationships in identity graph'];

      // Update classification if it was 'managed'
      if (node.classification === 'managed' || node.classification === 'pending') {
        node.classification = 'orphan';
      }
      if (!node.classification_tags.includes('orphan')) {
        node.classification_tags = [...(node.classification_tags || []), 'orphan'];
      }
    } else {
      node.orphan_reasons = [];
    }

    // Track orphan status changes for DB persistence
    if (node.spiffe_id && node.is_orphan !== wasOrphan) {
      orphanUpdates.push({
        spiffe_id: node.spiffe_id,
        is_orphan: node.is_orphan,
        orphan_reasons: node.orphan_reasons,
        classification: node.classification,
        classification_tags: node.classification_tags,
      });
    }
  }

  // Persist orphan status changes to DB (fire-and-forget, don't block graph response)
  if (orphanUpdates.length > 0 && dbClient) {
    (async () => {
      try {
        for (const u of orphanUpdates) {
          await dbClient.query(
            `UPDATE workloads SET is_orphan = $1, orphan_reasons = $2,
             classification = $3, classification_tags = $4, updated_at = NOW()
             WHERE spiffe_id = $5`,
            [u.is_orphan, JSON.stringify(u.orphan_reasons),
             u.classification, JSON.stringify(u.classification_tags), u.spiffe_id]
          );
        }
      } catch (e) {
        console.log('  ⚠️ Orphan status DB update failed:', e.message);
      }
    })();
  }

  // Add orphan-based attack paths (orphan detection happens after relationship scanner)
  for (const node of allNodes) {
    if (node.is_orphan && !node.is_service_linked) {
      allPaths.push({
        id: `orphaned-asset:${node.label || node.id}`,
        finding_type: 'orphaned-asset',
        title: `Orphaned Asset — ${node.label || node.id}`,
        severity: 'medium',
        description: `Resource has no relationships in the identity graph. ${(node.orphan_reasons || []).join('. ')}`,
        recommendation: 'Assign an owner, quarantine the resource, or schedule cleanup if no longer needed.',
        workload: node.label || node.id,
        blast_radius: 1,
        entry_points: [node.label || node.id],
      });
    }
  }

  // Step 7: IETF AIMS enrichment — derive agent identity fields from existing data
  try {
    const { IETFAimsMapper } = require('./ietf-aims-mapper');
    const aimsMapper = new IETFAimsMapper(dbClient);
    await aimsMapper.enrichNodes(allNodes);
  } catch (e) {
    console.log('  ⚠️ IETF AIMS enrichment skipped:', e.message);
  }

  // Step 8: Cloud log enrichment — attach observed cloud API usage to nodes
  try {
    const { CloudLogEnricher } = require('./cloud-log-enricher');
    const { ProviderRegistry } = require('./provider-registry');
    const enricher = new CloudLogEnricher(dbClient, ProviderRegistry.getInstance());
    const cloudResults = await enricher.enrichAll(workloads);
    if (cloudResults.gcp.length || cloudResults.aws.length) {
      console.log(`  ☁️ Cloud log enrichments: GCP=${cloudResults.gcp.length} AWS=${cloudResults.aws.length}`);
    }
  } catch (e) {
    console.log('  ⚠️ Cloud log enrichment skipped:', e.message);
  }

  const graphResult = {
    nodes: allNodes,
    relationships: allRels,
    attack_paths: allPaths,
    summary: {
      total_nodes: allNodes.length,
      total_relationships: allRels.length,
      total_attack_paths: allPaths.length,
      critical_paths: allPaths.filter(p => p.severity === 'critical').length,
      providers: Object.keys(byProvider),
    },
    generated_at: new Date().toISOString(),
  };

  // ── Enrich attack paths with control scoring, blast radius, credential chain ──
  console.log(`  🎯 Enriching ${allPaths.length} attack paths with controls...`);
  for (const ap of allPaths) {
    // Scored controls
    const ft = ap.finding_type || ap.type;
    const catalogHit = CONTROL_CATALOG[ft];
    ap.ranked_controls = scoreControls(ap, allNodes, allRels);
    console.log(`    ${ft}: catalog=${catalogHit ? catalogHit.length : 'miss'} scored=${ap.ranked_controls.length} workload=${ap.workload || 'none'}`);
    // Credential chain (identity → credential → resource)
    ap.credential_chain = computeCredentialChain(ap, allNodes, allRels);
    // Re-compute blast radius using FINAL node set (attack paths computed pre-Step-3 have stale IDs)
    const wName = (ap.workload || '').toLowerCase();
    const epNames = (ap.entry_points || []).map(e => e.toLowerCase()).filter(Boolean);
    const connected = new Set();
    // Seed: exact label match (no empty-string trap)
    if (wName) {
      for (const n of allNodes) {
        const nl = (n.label || '').toLowerCase();
        if (nl === wName || nl.startsWith(wName + '-')) connected.add(n.id);
      }
    }
    if (connected.size === 0 && epNames.length) {
      for (const ep of epNames) {
        const n = allNodes.find(x => (x.label || '').toLowerCase() === ep);
        if (n) connected.add(n.id);
      }
    }
    // BFS from seeds — directional traversal along trust propagation
    // runs-as edges go SA→workload, but blast flows workload→SA, so reverse those.
    // shares-identity is excluded: shared-SA blast is captured by the finding itself.
    const BLAST_EDGE_TYPES = new Set([
      'runs-as', 'has-role', 'grants-access',
      'holds-credential', 'accesses-api', 'can-delegate-to',
    ]);
    if (connected.size > 0) {
      const q = [...connected]; const vis = new Set(q);
      while (q.length) {
        const c = q.shift();
        for (const r of allRels) {
          if (!BLAST_EDGE_TYPES.has(r.type)) continue;
          const s = typeof r.source === 'object' ? r.source.id : r.source;
          const t = typeof r.target === 'object' ? r.target.id : r.target;
          if (r.type === 'runs-as') {
            // runs-as: SA(source)→workload(target). Blast goes reverse: workload→SA only.
            if (t === c && !vis.has(s)) { vis.add(s); q.push(s); connected.add(s); }
          } else {
            // All other edges: follow forward (source→target) only
            if (s === c && !vis.has(t)) { vis.add(t); q.push(t); connected.add(t); }
          }
        }
      }
      ap.nodes = [...connected];
      const affectedWorkloads = allNodes
        .filter(n => connected.has(n.id) && ['cloud-run','cloud-run-service','a2a-agent','mcp-server','lambda','ec2','container','pod'].includes(n.type));
      ap.blast_radius = affectedWorkloads.length;
      ap.affected_workloads = affectedWorkloads.map(n => n.label || n.id);
    }
  }

  // ── Re-score nodes based on findings ──
  // Governance score alone can give "A" to nodes with critical findings.
  // Apply finding-based penalties so the score reflects actual risk.
  const findingsByLabel = {};
  for (const ap of allPaths) {
    const lbl = (ap.workload || '').toLowerCase();
    if (!lbl) continue;
    if (!findingsByLabel[lbl]) findingsByLabel[lbl] = [];
    findingsByLabel[lbl].push({ severity: ap.severity || 'medium' });
  }
  for (const node of allNodes) {
    const findings = findingsByLabel[(node.label || '').toLowerCase()];
    if (findings?.length > 0) {
      node.finding_count = findings.length;
      node.score = applyFindingPenalties(node.score || 50, findings);
    }
  }

  // Cache it (system-level since buildGraph is called outside request context)
  setGraphCache('_system', graphResult, new Date().toISOString());

  // ── Agent tagging: back-propagate protocol scanner agent/MCP detection to workloads ──
  try {
    // ── Auto-detect agents: back-propagate protocol scanner results to existing workloads ──
    // If the protocol scanner created an a2a/mcp node linked to a workload, update that workload
    const agentNodes = allNodes.filter(n => (n.type === 'a2a-agent' || n.type === 'mcp-server') && n.protocol);
    const agentRels = allRels.filter(r => r.type === 'runs-as-protocol');
    let agentTagged = 0;
    for (const rel of agentRels) {
      const srcId = typeof rel.source === 'object' ? rel.source.id : rel.source;
      const tgtId = typeof rel.target === 'object' ? rel.target.id : rel.target;
      // Find the agent node and the workload node
      const agentNode = allNodes.find(n => n.id === srcId && (n.type === 'a2a-agent' || n.type === 'mcp-server'));
      const workloadNodeId = agentNode ? tgtId : null;
      if (!agentNode || !workloadNodeId) continue;

      // Extract the workload name from the node ID (format: "w:uuid" or "w:name")
      const wNode = allNodes.find(n => n.id === workloadNodeId);
      if (!wNode || !wNode.label) continue;

      const isA2A = agentNode.type === 'a2a-agent';
      const isMCP = agentNode.type === 'mcp-server';

      try {
        const result = await dbClient.query(`
          UPDATE workloads SET
            is_ai_agent = CASE WHEN $2 THEN true ELSE is_ai_agent END,
            is_mcp_server = CASE WHEN $3 THEN true ELSE is_mcp_server END,
            type = CASE
              WHEN $2 AND type NOT IN ('a2a-agent', 'mcp-server') THEN 'a2a-agent'
              WHEN $3 AND type NOT IN ('a2a-agent', 'mcp-server') THEN 'mcp-server'
              ELSE type
            END,
            category = CASE
              WHEN ($2 OR $3) AND (category IS NULL OR category NOT IN ('AI & Agents')) THEN 'AI & Agents'
              ELSE category
            END,
            updated_at = NOW()
          WHERE name = $1 AND (
            ($2 AND NOT COALESCE(is_ai_agent, false)) OR
            ($3 AND NOT COALESCE(is_mcp_server, false))
          )
          RETURNING name, type, is_ai_agent, is_mcp_server
        `, [wNode.label, isA2A, isMCP]);
        if (result.rows.length > 0) {
          agentTagged++;
          console.log(`[graph] Auto-tagged ${wNode.label} as ${isA2A ? 'AI Agent' : 'MCP Server'}`);
        }
      } catch (e) { /* skip */ }
    }
    if (agentTagged > 0) console.log(`[graph] Auto-tagged ${agentTagged} workloads as agents/MCP servers`);

    // ── Persist protocol scanner fields (has_auth, is_signed, protocol, skills) to workload metadata ──
    for (const rel of agentRels) {
      const srcId = typeof rel.source === 'object' ? rel.source.id : rel.source;
      const tgtId = typeof rel.target === 'object' ? rel.target.id : rel.target;
      const agentNode = allNodes.find(n => n.id === srcId && (n.type === 'a2a-agent' || n.type === 'mcp-server'));
      if (!agentNode) continue;
      const wNode = allNodes.find(n => n.id === tgtId);
      if (!wNode?.wid) continue;

      const protoMeta = agentNode.meta || {};
      const updates = {};
      if (protoMeta.has_auth !== undefined) updates.has_auth = protoMeta.has_auth;
      if (protoMeta.is_signed !== undefined) updates.is_signed = protoMeta.is_signed;
      if (protoMeta.transport) updates.transport = protoMeta.transport;
      if (agentNode.protocol) updates.protocol = agentNode.protocol;
      if (protoMeta.skills?.length) updates.a2a_skills = protoMeta.skills;
      if (protoMeta.tools?.length) updates.tools = protoMeta.tools;
      if (protoMeta.requires_human_delegator !== undefined) updates.requires_human_delegator = protoMeta.requires_human_delegator;

      if (Object.keys(updates).length > 0) {
        try {
          await dbClient.query(`
            UPDATE workloads SET metadata = metadata || $2::jsonb, updated_at = NOW()
            WHERE id = $1
          `, [wNode.wid, JSON.stringify(updates)]);
        } catch (e) { /* skip */ }
      }
    }

    // ── Also detect by metadata/env hints (for workloads not yet probed) ──
    for (const w of workloads) {
      if (w.is_ai_agent || w.is_mcp_server) continue; // already tagged
      const meta = w.metadata || {};
      const labels = w.labels || {};
      const env = meta.env || {};

      const isAgent =
        meta.model || meta.scope_ceiling || meta.human_in_loop !== undefined ||
        labels['ai-agent'] === 'true' || labels['a2a'] === 'true' ||
        env.AI_AGENT === 'true' || env.A2A_AGENT_CARD_PATH ||
        (w.name && /agent/i.test(w.name) && !/relay|proxy/i.test(w.name));

      const isMCP =
        meta.tools || meta.mcp_version ||
        labels['mcp-server'] === 'true' ||
        env.MCP_SERVER === 'true' || env.MCP_TRANSPORT ||
        (w.name && /mcp.*server/i.test(w.name));

      if (isAgent || isMCP) {
        try {
          await dbClient.query(`
            UPDATE workloads SET
              is_ai_agent = CASE WHEN $2 THEN true ELSE is_ai_agent END,
              is_mcp_server = CASE WHEN $3 THEN true ELSE is_mcp_server END,
              type = CASE
                WHEN $2 AND type NOT IN ('a2a-agent', 'mcp-server') THEN 'a2a-agent'
                WHEN $3 AND type NOT IN ('a2a-agent', 'mcp-server') THEN 'mcp-server'
                ELSE type
              END,
              category = COALESCE(NULLIF(category, ''), 'AI & Agents'),
              updated_at = NOW()
            WHERE id = $1
          `, [w.id, !!isAgent, !!isMCP]);
          agentTagged++;
          console.log(`[graph] Metadata-tagged ${w.name} as ${isAgent ? 'AI Agent' : 'MCP Server'}`);
        } catch (e) { /* skip */ }
      }
    }

  } catch (e) { console.error('Agent tagging error:', e.message); }

  // Persist to DB if table exists
  try {
    await dbClient.query(`
      INSERT INTO identity_graph (id, graph_data, generated_at)
      VALUES ('latest', $1, NOW())
      ON CONFLICT (id) DO UPDATE SET graph_data = $1, generated_at = NOW()
    `, [JSON.stringify(graphResult)]);
  } catch (e) { /* table might not exist yet */ }

  return graphResult;
}

// Export for integration into runDiscovery
async function refreshGraph(dbClient) {
  try {
    return await buildGraph(dbClient);
  } catch (e) {
    console.error('Graph refresh error:', e.message);
    return null;
  }
}

// =============================================================================
// Auto-generate baseline policies from discovered graph topology
// Creates audit-mode access policies for each workload→workload relationship
// =============================================================================
async function generateBaselinePolicies(graph, dbClient) {
  if (!graph || !graph.nodes) return 0;

  const pairs = new Map();

  // 1. Extract cross-service pairs from graph relationships
  for (const rel of (graph.relationships || [])) {
    const src = graph.nodes.find(n => n.id === rel.source);
    const dst = graph.nodes.find(n => n.id === rel.target);
    if (!src || !dst) continue;
    // Skip self-referential (SPIFFE→workload for same entity)
    if (src.label === dst.label) continue;
    // Only workload-to-workload
    if (src.group !== 'workload' && dst.group !== 'workload') continue;
    const key = `${src.label}→${dst.label}`;
    if (!pairs.has(key)) {
      pairs.set(key, { source: src, target: dst, relType: rel.type });
    }
  }

  // 2. Generate policies from known WID service topology
  // These represent the actual inter-service calls in the platform
  const knownTopology = [
    { src: 'wip-discovery', dst: 'wip-policy-sync', rel: 'graph-enrichment' },
    { src: 'wip-discovery', dst: 'wip-token-service', rel: 'attestation-token' },
    { src: 'wip-web', dst: 'wip-discovery', rel: 'graph-api' },
    { src: 'wip-web', dst: 'wip-policy-sync', rel: 'policy-api' },
    { src: 'wip-relay', dst: 'wip-policy-sync', rel: 'policy-sync' },
    { src: 'wip-credential-broker', dst: 'wip-vault', rel: 'secret-retrieval' },
    { src: 'wip-decision-generator', dst: 'wip-relay', rel: 'decision-generation' },
    { src: 'wip-policy-sync', dst: 'wip-opa', rel: 'policy-evaluation' },
    { src: 'wip-token-service', dst: 'wip-opa', rel: 'token-validation' },
    { src: 'wip-audit-service', dst: 'wip-policy-sync', rel: 'audit-health' },
  ];

  for (const { src, dst, rel } of knownTopology) {
    const srcNode = graph.nodes.find(n => n.label === src);
    const dstNode = graph.nodes.find(n => n.label === dst);
    if (!srcNode || !dstNode) continue;
    const key = `${src}→${dst}`;
    if (!pairs.has(key)) {
      pairs.set(key, { source: srcNode, target: dstNode, relType: rel });
    }
  }

  let created = 0;
  for (const [, { source, target, relType }] of pairs) {
    const name = `auto-baseline-${source.label}-to-${target.label}`.substring(0, 100);
    try {
      const result = await dbClient.query(`
        INSERT INTO policies (name, description, policy_type, enforcement_mode, effect, enabled, priority, conditions, actions)
        VALUES ($1, $2, 'access', 'audit', 'allow', true, 100, $3, $4)
        ON CONFLICT (name) DO NOTHING RETURNING id
      `, [
        name,
        `Auto-generated baseline: ${source.label} → ${target.label} (${relType})`,
        JSON.stringify([
          { field: 'client.name', operator: 'contains', value: source.label },
          { field: 'server.name', operator: 'contains', value: target.label },
        ]),
        JSON.stringify([{ type: 'allow', scopes: ['*'] }]),
      ]);
      if (result.rowCount > 0) created++;
    } catch (e) {
      // Policy name conflict or constraint violation — skip
    }
  }

  // No explicit default-deny policy needed — the gateway evaluate endpoint
  // already defaults to deny when no policy matches (zero-trust default)

  if (created > 0) {
    console.log(`[graph] Generated ${created} baseline policies (audit mode) + default deny`);
  }
  return created;
}

// =============================================================================
// FINDING_TYPE_DEFAULTS — labels + descriptions for all known finding types
// Used as fallback when finding_type_metadata table is empty, and as seed data.
// =============================================================================
const FINDING_TYPE_DEFAULTS = {
  'static-external-credential': { label: 'Static External Credential', description: 'Hardcoded API keys or secrets stored in env vars instead of a secret manager. Rotate and migrate to vault.', severity: 'critical', category: 'credential' },
  'toxic-combo': { label: 'Toxic Combination', description: 'Identity has dangerous permission combinations (e.g., admin + no MFA + static credentials). Reduce scope or add guardrails.', severity: 'critical', category: 'access' },
  'mcp-static-credentials': { label: 'MCP Static Credentials', description: 'MCP server using static API keys. Replace with short-lived SPIFFE-bound tokens.', severity: 'high', category: 'credential' },
  'a2a-no-auth': { label: 'A2A No Authentication', description: 'Agent-to-agent communication without mutual authentication. Enable mTLS or token-based auth.', severity: 'high', category: 'access' },
  'a2a-unsigned-card': { label: 'A2A Unsigned Agent Card', description: 'A2A agent card not cryptographically signed. Require signed agent cards for trust.', severity: 'medium', category: 'access' },
  'shared-sa': { label: 'Shared Service Account', description: 'Multiple workloads sharing one service account. Create dedicated SAs per workload.', severity: 'high', category: 'identity' },
  'key-leak': { label: 'Key Leak', description: 'Credential exposed in logs, repos, or public endpoints. Revoke immediately and rotate.', severity: 'critical', category: 'credential' },
  'over-privileged': { label: 'Over-Privileged', description: 'Identity has broader permissions than needed. Apply least-privilege scoping.', severity: 'high', category: 'access' },
  'public-internal-pivot': { label: 'Public-to-Internal Pivot', description: 'Public-facing service can reach internal resources. Add network segmentation.', severity: 'critical', category: 'network' },
  'privilege-escalation': { label: 'Privilege Escalation', description: 'Identity can escalate privileges through role chaining or permission inheritance.', severity: 'critical', category: 'access' },
  'cross-account-trust': { label: 'Cross-Account Trust', description: 'Trust relationship to an external or unverified account. Validate account ownership and add ExternalId.', severity: 'high', category: 'identity' },
  'unbounded-admin': { label: 'Admin Without Guardrails', description: 'Admin identity with no permission boundary. Any compromised credential has unlimited blast radius. Apply a permission boundary.', severity: 'critical', category: 'access' },
  'public-data-exposure': { label: 'Public Data Exposure', description: 'Storage bucket or database publicly accessible. Enable access blocks and encryption.', severity: 'critical', category: 'data' },
  'public-database': { label: 'Public Database', description: 'Database instance accessible from the public internet. Restrict to private networking.', severity: 'critical', category: 'data' },
  'unencrypted-data-store': { label: 'Unencrypted Data Store', description: 'Data store without encryption at rest. Enable encryption with customer-managed keys.', severity: 'high', category: 'data' },
  'overly-permissive-sg': { label: 'Overly Permissive Security Group', description: 'Security group or firewall rule allows broad inbound access. Restrict to required CIDR ranges.', severity: 'high', category: 'network' },
  'unrotated-kms-key': { label: 'Unrotated KMS Key', description: 'KMS encryption key has not been rotated per policy. Enable automatic rotation.', severity: 'medium', category: 'credential' },
  'stale-secret': { label: 'Stale Secret', description: 'Secret has not been rotated within the required timeframe. Rotate and update consumers.', severity: 'high', category: 'credential' },
  'internet-to-data': { label: 'Internet-to-Data Path', description: 'Direct path from internet to data store without WAF or API gateway. Add defense in depth.', severity: 'critical', category: 'network' },
  'zombie-workload': { label: 'Zombie Workload', description: 'Identity inactive for 90+ days but still has active credentials. Quarantine or decommission.', severity: 'medium', category: 'lifecycle' },
  'rogue-workload': { label: 'Rogue Workload', description: 'Identity bypassing governance controls — cross-account trust without ExternalId, wildcard trust, or unapproved public exposure.', severity: 'high', category: 'governance' },
  'unused-iam-role': { label: 'Unused IAM Role', description: 'IAM role/user with no recent activity. Detach permissions or schedule for deletion.', severity: 'medium', category: 'lifecycle' },
  'public-exposure-untagged': { label: 'Public Exposure (Untagged)', description: 'Resource is publicly accessible without an explicit security team approval tag. Restrict access or add approved-public tag.', severity: 'high', category: 'governance' },
  'orphaned-asset': { label: 'Orphaned Asset', description: 'Identity with no relationships in the graph — no consumers, no credentials, no policies. Assign an owner or decommission.', severity: 'medium', category: 'lifecycle' },
  'account-outside-org': { label: 'Account Outside Organization', description: 'Cross-account trust to an account not in the organization allow-list. Verify account ownership.', severity: 'high', category: 'governance' },
  'blended-identity-no-delegator': { label: 'Blended Identity (No Delegator)', description: 'Blended human+agent identity without delegation chain. Require OBO token with human root.', severity: 'high', category: 'access' },
  'unregistered-ai-endpoint': { label: 'Unregistered AI Endpoint', description: 'Cloud AI inference endpoint not registered in governance. Register with owner, data classification, and usage policy.', severity: 'high', category: 'governance' },
  'shadow-ai-usage': { label: 'Shadow AI Usage', description: 'Workload calling AI APIs without governance approval. Register usage and apply rate limiting.', severity: 'high', category: 'governance' },
  'ai-permission-without-workload': { label: 'AI Permission Without Workload', description: 'Identity has AI platform permissions but no registered AI workload. Audit and revoke if unused.', severity: 'medium', category: 'access' },
  'public-ai-endpoint': { label: 'Public AI Endpoint', description: 'AI inference endpoint publicly accessible. Restrict to VPC-only and enforce authentication.', severity: 'critical', category: 'network' },
  'mcp-capability-drift': { label: 'MCP Capability Drift', description: 'MCP server capabilities changed since last scan — tools added, removed, or descriptions modified. Investigate for supply-chain tampering.', severity: 'high', category: 'supply-chain' },
  'a2a-invalid-signature': { label: 'A2A Invalid Signature', description: 'A2A Agent Card has an invalid cryptographic signature. Card may have been tampered with. Investigate immediately.', severity: 'high', category: 'access' },
};

// =============================================================================
// Seed finding_type_metadata from FINDING_TYPE_DEFAULTS (idempotent)
// =============================================================================
async function seedFindingTypeMetadata(dbClient) {
  // Ensure table exists (migration safety)
  try {
    await dbClient.query(`
      CREATE TABLE IF NOT EXISTS finding_type_metadata (
        finding_type   VARCHAR(100) PRIMARY KEY,
        label          VARCHAR(255) NOT NULL,
        description    TEXT NOT NULL,
        severity       VARCHAR(20) DEFAULT 'high',
        category       VARCHAR(50),
        enabled        BOOLEAN DEFAULT TRUE,
        created_at     TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  } catch { /* table may exist */ }

  let count = 0;
  for (const [ft, meta] of Object.entries(FINDING_TYPE_DEFAULTS)) {
    try {
      await dbClient.query(`
        INSERT INTO finding_type_metadata (finding_type, label, description, severity, category)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (finding_type) DO UPDATE SET
          label = EXCLUDED.label, description = EXCLUDED.description,
          severity = EXCLUDED.severity, category = EXCLUDED.category
      `, [ft, meta.label, meta.description, meta.severity, meta.category]);
      count++;
    } catch { /* skip */ }
  }

  console.log(`  [seed] Finding type metadata: ${count} types upserted`);
  return count;
}

// =============================================================================
// Seed CONTROL_CATALOG → remediation_intents + remediation_templates (DB)
// Idempotent: ON CONFLICT DO UPDATE. Called at startup in mountGraphRoutes.
// =============================================================================
async function seedRemediationIntents(dbClient) {
  // Ensure tables exist (migration safety)
  try {
    await dbClient.query(`
      CREATE TABLE IF NOT EXISTS remediation_intents (
        id               VARCHAR(100) PRIMARY KEY,
        control_id       VARCHAR(100) NOT NULL,
        name             VARCHAR(255) NOT NULL,
        description      TEXT NOT NULL,
        goal             TEXT,
        action_type      VARCHAR(50) NOT NULL,
        remediation_type VARCHAR(50) NOT NULL,
        finding_types    TEXT[] DEFAULT '{}',
        scope            VARCHAR(50) DEFAULT 'resource',
        resource_types   TEXT[] DEFAULT '{}',
        path_break       JSONB NOT NULL DEFAULT '{}',
        feasibility      JSONB NOT NULL DEFAULT '{}',
        operational      JSONB NOT NULL DEFAULT '{}',
        risk_reduction   JSONB DEFAULT '{}',
        rollback_strategy TEXT,
        preconditions    JSONB DEFAULT '[]',
        validation       JSONB DEFAULT '[]',
        template_id      VARCHAR(100),
        enabled          BOOLEAN DEFAULT TRUE,
        created_at       TIMESTAMPTZ DEFAULT NOW(),
        updated_at       TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await dbClient.query(`
      CREATE TABLE IF NOT EXISTS remediation_templates (
        id                SERIAL PRIMARY KEY,
        intent_id         VARCHAR(100) NOT NULL REFERENCES remediation_intents(id) ON DELETE CASCADE,
        provider          VARCHAR(50) NOT NULL,
        resource_type     VARCHAR(100),
        channel           VARCHAR(50) NOT NULL,
        title             VARCHAR(255),
        template_body     TEXT NOT NULL,
        variables         JSONB DEFAULT '[]',
        validate_template TEXT,
        rollback_template TEXT,
        priority          INTEGER DEFAULT 100,
        enabled           BOOLEAN DEFAULT TRUE,
        created_at        TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_ri_finding ON remediation_intents USING GIN(finding_types)');
    await dbClient.query('CREATE UNIQUE INDEX IF NOT EXISTS idx_rt_unique ON remediation_templates(intent_id, provider, COALESCE(resource_type,\'\'), channel)');
  } catch (e) { /* tables may exist */ }

  let intentCount = 0;
  let templateCount = 0;

  for (const [findingType, controls] of Object.entries(CONTROL_CATALOG)) {
    for (const ctrl of controls) {
      // Upsert intent
      try {
        // Build finding_types: merge with existing to support controls mapped to multiple finding types
        await dbClient.query(`
          INSERT INTO remediation_intents (
            id, control_id, name, description, goal, action_type, remediation_type,
            finding_types, path_break, feasibility, operational, template_id
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
          ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name, description = EXCLUDED.description,
            action_type = EXCLUDED.action_type, remediation_type = EXCLUDED.remediation_type,
            finding_types = (
              SELECT ARRAY(SELECT DISTINCT unnest(remediation_intents.finding_types || EXCLUDED.finding_types))
            ),
            path_break = EXCLUDED.path_break, feasibility = EXCLUDED.feasibility,
            operational = EXCLUDED.operational, template_id = EXCLUDED.template_id,
            updated_at = NOW()
        `, [
          ctrl.id,
          ctrl.id.toUpperCase().replace(/-/g, '.'),
          ctrl.name,
          ctrl.description,
          ctrl.description, // goal = description as default
          ctrl.action_type,
          ctrl.remediation_type || 'iac',
          [findingType],
          JSON.stringify(ctrl.path_break || {}),
          JSON.stringify(ctrl.feasibility || {}),
          JSON.stringify(ctrl.operational || {}),
          ctrl.template_id || null,
        ]);
        intentCount++;
      } catch (e) { /* skip */ }

      // Upsert templates from remediation_guide
      const guide = ctrl.remediation_guide || {};
      for (const [provider, providerGuide] of Object.entries(guide)) {
        // CLI steps → cli channel
        if (providerGuide.steps && providerGuide.steps.length > 0) {
          try {
            await dbClient.query(`
              INSERT INTO remediation_templates (intent_id, provider, channel, title, template_body, priority)
              VALUES ($1, $2, 'cli', $3, $4, 100)
              ON CONFLICT (intent_id, provider, COALESCE(resource_type,''), channel) DO UPDATE SET
                title = EXCLUDED.title, template_body = EXCLUDED.template_body
            `, [ctrl.id, provider, providerGuide.title || ctrl.name, providerGuide.steps.join('\n')]);
            templateCount++;
          } catch { /* skip */ }
        }

        // Terraform snippet → terraform channel
        if (providerGuide.terraform) {
          try {
            await dbClient.query(`
              INSERT INTO remediation_templates (intent_id, provider, channel, title, template_body, priority)
              VALUES ($1, $2, 'terraform', $3, $4, 200)
              ON CONFLICT (intent_id, provider, COALESCE(resource_type,''), channel) DO UPDATE SET
                title = EXCLUDED.title, template_body = EXCLUDED.template_body
            `, [ctrl.id, provider, `Terraform: ${providerGuide.title || ctrl.name}`, providerGuide.terraform]);
            templateCount++;
          } catch { /* skip */ }
        }
      }
    }
  }

  console.log(`  [seed] Remediation intents: ${intentCount} upserted, ${templateCount} templates`);
  return { intentCount, templateCount };
}

// =============================================================================
// scoreControlsAsync — DB-backed scoring with CONTROL_CATALOG fallback
// =============================================================================
async function scoreControlsAsync(attackPath, allNodes, allRels, dbClient) {
  if (!dbClient) return scoreControls(attackPath, allNodes, allRels);

  const findingType = attackPath.finding_type || attackPath.type;
  if (!findingType) return scoreControls(attackPath, allNodes, allRels);

  try {
    const result = await dbClient.query(
      `SELECT * FROM remediation_intents WHERE enabled = true AND $1 = ANY(finding_types)`,
      [findingType]
    );

    if (result.rows.length > 0) {
      // Map DB intents back to the same shape as CONTROL_CATALOG entries for scoring
      const candidates = result.rows.map(row => ({
        id: row.id,
        name: row.name,
        description: row.description,
        action_type: row.action_type,
        remediation_type: row.remediation_type,
        path_break: row.path_break || {},
        feasibility: row.feasibility || {},
        operational: row.operational || {},
        template_id: row.template_id,
        // Flag that this came from DB
        _db_backed: true,
      }));

      // Use the same scoring logic as scoreControls but with DB candidates
      return scoreControlsWithCandidates(candidates, attackPath, allNodes, allRels);
    }
  } catch {
    // Table may not exist — fall through to sync
  }

  return scoreControls(attackPath, allNodes, allRels);
}

// Score pre-loaded candidates (shared logic extracted from scoreControls)
function scoreControlsWithCandidates(candidates, attackPath, allNodes, allRels) {
  if (candidates.length === 0) return [];

  const workloadName = (attackPath.workload || '').toLowerCase();
  const connectedNodeIds = new Set();
  const affectedWorkloads = [];

  if (workloadName) {
    for (const n of allNodes) {
      const nl = (n.label || '').toLowerCase();
      if (nl === workloadName || nl.startsWith(workloadName + '-') || nl.startsWith(workloadName + ' ')) {
        connectedNodeIds.add(n.id);
      }
    }
  } else if (attackPath.nodes?.length) {
    for (const nid of attackPath.nodes.slice(0, 10)) connectedNodeIds.add(nid);
  } else if (attackPath.entry_points?.length) {
    for (const ep of attackPath.entry_points) {
      const n = allNodes.find(x => (x.label || '').toLowerCase() === ep.toLowerCase());
      if (n) connectedNodeIds.add(n.id);
    }
  }

  const queue = [...connectedNodeIds];
  const visited = new Set(queue);
  while (queue.length > 0) {
    const current = queue.shift();
    for (const r of allRels) {
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      if (s === current && !visited.has(t)) { visited.add(t); queue.push(t); connectedNodeIds.add(t); }
      if (t === current && !visited.has(s)) { visited.add(s); queue.push(s); connectedNodeIds.add(s); }
    }
  }

  for (const nid of connectedNodeIds) {
    const n = allNodes.find(nd => nd.id === nid);
    if (n && ['workload', 'a2a-agent', 'mcp-server'].includes(n.type)) {
      affectedWorkloads.push(n.label || n.id);
    }
  }

  const blastRadius = connectedNodeIds.size;
  const crownJewelNearby = allNodes.some(n =>
    connectedNodeIds.has(n.id) && (n.type === 'external-resource' || n.workload_type === 'external-resource')
  );

  const scored = candidates.map(ctrl => {
    const pb = ctrl.path_break || {};
    const edgePositionScore = pb.edge_position === 'entry' ? 100 : pb.edge_position === 'credential' ? 70 : 40;
    const edgesSevered = Math.min((pb.edges_severed || 0) * 35, 100);
    const crownJewel = (pb.crown_jewel_proximity || 0) * (crownJewelNearby ? 100 : 50);
    const pathBreakScore = (edgePositionScore * 0.4 + edgesSevered * 0.3 + crownJewel * 0.3);

    const hardPreconditions = ['can-split-workload', 'delegation-chain-available', 'approval-workflow'];
    const preconditions = ctrl.feasibility?.preconditions || [];
    const feasible = !preconditions.some(p => hardPreconditions.includes(p));
    const feasibilityScore = feasible ? 1.0 : 0.3;

    const maxBlast = Math.max(blastRadius, 1);
    const controlBlastEstimate = (pb.edges_severed || 0) > 1 ? maxBlast : Math.ceil(maxBlast * 0.5);
    const blastScore = Math.max(0, 100 - (controlBlastEstimate * 8));

    const op = ctrl.operational || {};
    const effortMap = { 1: 95, 2: 80, 3: 65, 4: 50, 5: 35, 8: 15 };
    const toilMap = { 0: 100, 1: 75, 2: 50, 3: 25 };
    const expertiseMap = { low: 100, medium: 60, high: 25 };
    const opScore = (
      (effortMap[op.implementation] || 50) * 0.5 +
      (toilMap[op.ongoing_toil] || 50) * 0.25 +
      (expertiseMap[op.expertise] || 50) * 0.25
    );

    const typeConfidence = { policy: 90, replace: 80, harden: 70, remediate: 85, architecture: 60 };
    const confidenceScore = typeConfidence[ctrl.action_type] || 70;

    const composite = Math.round(
      pathBreakScore * 0.40 * feasibilityScore +
      blastScore * 0.20 +
      opScore * 0.20 +
      confidenceScore * 0.20
    );

    return {
      ...ctrl,
      score: {
        composite,
        path_break: Math.round(pathBreakScore),
        feasibility: feasibilityScore === 1.0 ? 'met' : 'partial',
        blast_radius: Math.round(blastScore),
        operational_cost: Math.round(opScore),
        confidence: confidenceScore,
      },
      blast_estimate: {
        workloads_affected: controlBlastEstimate,
        total_in_zone: blastRadius,
        affected_workload_names: affectedWorkloads.slice(0, 5),
      },
    };
  });

  scored.sort((a, b) => b.score.composite - a.score.composite);
  return scored;
}

function clearGraphCache(tenantId) {
  if (tenantId) {
    graphCaches.delete(tenantId);
  } else {
    // Clear all tenant caches
    graphCaches.clear();
  }
}

// ── Seed Provider Registry from defaults ───────────────────────────────────

async function seedProviderRegistry(dbClient) {
  const { ProviderRegistry } = require('./provider-registry');

  // Ensure table exists (migration safety)
  try {
    await dbClient.query(`
      CREATE TABLE IF NOT EXISTS provider_registry (
        id              VARCHAR(100) PRIMARY KEY,
        registry_type   VARCHAR(50) NOT NULL,
        label           VARCHAR(255) NOT NULL,
        category        VARCHAR(100) NOT NULL,
        credential_keys TEXT[] DEFAULT '{}',
        ai_config       JSONB DEFAULT NULL,
        domain_patterns TEXT[] DEFAULT '{}',
        domain_type     VARCHAR(50),
        image_patterns  TEXT[] DEFAULT '{}',
        signal_patterns TEXT[] DEFAULT '{}',
        enabled         BOOLEAN DEFAULT TRUE,
        sort_order      INTEGER DEFAULT 100,
        created_at      TIMESTAMPTZ DEFAULT NOW(),
        updated_at      TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_pr_type ON provider_registry(registry_type)');
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_pr_category ON provider_registry(category)');
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_pr_enabled ON provider_registry(enabled) WHERE enabled = TRUE');
    await dbClient.query('CREATE INDEX IF NOT EXISTS idx_pr_keys ON provider_registry USING GIN(credential_keys)');
  } catch (e) { /* table may exist */ }

  const defaults = ProviderRegistry.getDefaults();
  let count = 0;

  for (const row of defaults) {
    try {
      await dbClient.query(`
        INSERT INTO provider_registry (id, registry_type, label, category, credential_keys, ai_config, domain_patterns, domain_type, image_patterns, signal_patterns)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (id) DO UPDATE SET
          label = EXCLUDED.label, category = EXCLUDED.category,
          credential_keys = EXCLUDED.credential_keys,
          ai_config = EXCLUDED.ai_config,
          domain_patterns = EXCLUDED.domain_patterns,
          domain_type = EXCLUDED.domain_type,
          image_patterns = EXCLUDED.image_patterns,
          signal_patterns = EXCLUDED.signal_patterns,
          updated_at = NOW()
      `, [
        row.id, row.registry_type, row.label, row.category,
        row.credential_keys, row.ai_config ? JSON.stringify(row.ai_config) : null,
        row.domain_patterns, row.domain_type,
        row.image_patterns, row.signal_patterns,
      ]);
      count++;
    } catch (e) {
      console.warn(`  [seed] Provider registry entry "${row.id}" failed: ${e.message}`);
    }
  }

  console.log(`  [seed] Provider registry: ${count} entries seeded`);

  // Initialize the singleton with DB
  await ProviderRegistry.initialize(dbClient);
}

module.exports = { mountGraphRoutes, refreshGraph, buildGraph, clearGraphCache, generateBaselinePolicies, seedRemediationIntents, seedFindingTypeMetadata, seedProviderRegistry, scoreControlsAsync, FINDING_TYPE_DEFAULTS };
