// =============================================================================
// Policy Routes — All 6 Policy Types
// =============================================================================
// IMPORTANT: Specific paths MUST be registered BEFORE /:id routes.
// =============================================================================

const crypto = require('crypto');
const { PolicyEvaluator, CONDITION_FIELDS, OPERATORS_BY_TYPE, ACTION_TYPES, POLICY_TYPES, CREDENTIAL_TYPES } = require('./engine/evaluator');
// Templates are DB-managed. In-code templates only used by POST /admin/migrate-templates (seed).
const { getCompiler, listCompilers } = require('./compilers');

// ── Policy version hash: deterministic hash of policy conditions for replay fidelity ──
function computePolicyVersionHash(policy) {
  const canonical = JSON.stringify({
    id: policy.id, conditions: policy.conditions, actions: policy.actions,
    effect: policy.effect, enforcement_mode: policy.enforcement_mode,
  });
  return crypto.createHash('sha256').update(canonical).digest('hex').slice(0, 16);
}

function mountPolicyRoutes(app, pool, opts = {}) {
  const evaluator = new PolicyEvaluator();
  const compilerName = opts.compiler || process.env.POLICY_COMPILER || 'rego';
  const compiler = getCompiler(compilerName);

  // Tenant-scoped DB helper: uses req.db (set by attachTenantDb middleware)
  // Falls back to direct pool query for system/gateway endpoints without user context
  const db = (req) => req.db || { query: (text, params) => pool.query(text, params) };

  console.log(`  ✅ Policy routes mounted (compiler: ${compilerName})`);

  const parsePolicy = (p) => ({
    ...p,
    conditions: typeof p.conditions === 'string' ? JSON.parse(p.conditions) : (p.conditions || []),
    actions: typeof p.actions === 'string' ? JSON.parse(p.actions) : (p.actions || []),
    credential_policy: typeof p.credential_policy === 'string' ? JSON.parse(p.credential_policy) : (p.credential_policy || null),
    time_window: typeof p.time_window === 'string' ? JSON.parse(p.time_window) : (p.time_window || null),
  });

  const parseWorkload = (w) => ({
    ...w,
    labels: typeof w.labels === 'string' ? JSON.parse(w.labels) : (w.labels || {}),
    metadata: typeof w.metadata === 'string' ? JSON.parse(w.metadata) : (w.metadata || {}),
  });

  // ══════════════════════════════════════════════
  // Templates (MUST be before /:id)
  // DB-backed with in-code fallback for backwards compatibility
  // ══════════════════════════════════════════════

  // Helper: check if policy_templates table exists (system-level, no tenant scope needed)
  let _dbTemplatesAvailable = null;
  async function dbTemplatesAvailable() {
    if (_dbTemplatesAvailable !== null) return _dbTemplatesAvailable;
    try {
      await pool.query("SELECT 1 FROM policy_templates LIMIT 1");
      _dbTemplatesAvailable = true;
    } catch {
      _dbTemplatesAvailable = false;
    }
    return _dbTemplatesAvailable;
  }

  app.get('/api/v1/policies/templates', async (req, res) => {
    try {
      const { type, finding_type, tag, severity, enabled } = req.query;

      if (!(await dbTemplatesAvailable())) {
        return res.status(503).json({
          error: 'Templates not initialized. Run: POST /admin/migrate-templates',
          templates: [], total: 0,
        });
      }

      let where = ['1=1'];
      let params = [];
      let i = 1;

      if (type) { where.push(`policy_type = $${i++}`); params.push(type); }
      if (severity) { where.push(`severity = $${i++}`); params.push(severity); }
      if (tag) { where.push(`$${i++} = ANY(tags)`); params.push(tag); }
      if (enabled !== undefined) { where.push(`enabled = $${i++}`); params.push(enabled === 'true'); }

      if (finding_type) {
        where.push(`id IN (SELECT template_id FROM finding_remediation_map WHERE finding_type = $${i++})`);
        params.push(finding_type);
      }

      const result = await db(req).query(
        `SELECT * FROM policy_templates WHERE ${where.join(' AND ')} ORDER BY policy_type, severity, name`,
        params
      );
      res.json({
        total: result.rows.length,
        source: 'database',
        templates: result.rows,
        types: POLICY_TYPES,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api/v1/policies/templates/:templateId — Single template detail ──
  app.get('/api/v1/policies/templates/:templateId', async (req, res) => {
    try {
      const result = await db(req).query('SELECT * FROM policy_templates WHERE id = $1', [req.params.templateId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
      res.json(result.rows[0]);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── PUT /api/v1/policies/templates/:templateId — Edit a template (DB only) ──
  app.put('/api/v1/policies/templates/:templateId', async (req, res) => {
    try {
      if (!(await dbTemplatesAvailable())) {
        return res.status(501).json({ error: 'Templates not initialized. Run: POST /admin/migrate-templates' });
      }
      const { name, description, policy_type, severity, conditions, actions,
              scope_environment, effect, tags, enabled } = req.body;

      const result = await db(req).query(`
        UPDATE policy_templates SET
          name = COALESCE($2, name),
          description = COALESCE($3, description),
          policy_type = COALESCE($4, policy_type),
          severity = COALESCE($5, severity),
          conditions = COALESCE($6, conditions),
          actions = COALESCE($7, actions),
          scope_environment = COALESCE($8, scope_environment),
          effect = COALESCE($9, effect),
          tags = COALESCE($10, tags),
          enabled = COALESCE($11, enabled)
        WHERE id = $1
        RETURNING *
      `, [req.params.templateId, name, description, policy_type, severity,
          conditions ? JSON.stringify(conditions) : null,
          actions ? JSON.stringify(actions) : null,
          scope_environment, effect, tags, enabled]);

      if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
      res.json({ message: 'Template updated', template: result.rows[0] });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── POST /api/v1/policies/templates — Create a new template (DB only) ──
  app.post('/api/v1/policies/templates', async (req, res) => {
    try {
      if (!(await dbTemplatesAvailable())) {
        return res.status(501).json({ error: 'Templates not initialized. Run: POST /admin/migrate-templates' });
      }
      const { id, name, description, policy_type, severity, conditions, actions,
              scope_environment, effect, tags } = req.body;
      if (!id || !name || !policy_type) {
        return res.status(400).json({ error: 'Required: id, name, policy_type' });
      }

      const result = await db(req).query(`
        INSERT INTO policy_templates (id, name, description, policy_type, severity, conditions, actions,
          scope_environment, effect, tags, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *
      `, [id, name, description || '', policy_type, severity || 'medium',
          JSON.stringify(conditions || []), JSON.stringify(actions || []),
          scope_environment || null, effect || null, tags || '{}',
          req.body.created_by || 'user']);
      res.status(201).json(result.rows[0]);
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'Template ID already exists' });
      res.status(500).json({ error: e.message });
    }
  });

  // ── DELETE /api/v1/policies/templates/:templateId — Delete template (DB only) ──
  app.delete('/api/v1/policies/templates/:templateId', async (req, res) => {
    try {
      if (!(await dbTemplatesAvailable())) {
        return res.status(501).json({ error: 'Templates not initialized. Run: POST /admin/migrate-templates' });
      }
      const result = await db(req).query('DELETE FROM policy_templates WHERE id = $1 RETURNING id', [req.params.templateId]);
      if (result.rows.length === 0) return res.status(404).json({ error: 'Template not found' });
      res.json({ message: 'Template deleted', id: req.params.templateId });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api/v1/policies/remediation/:findingType — Get remediation templates for a finding ──
  app.get('/api/v1/policies/remediation/:findingType', async (req, res) => {
    try {
      const { findingType } = req.params;

      if (await dbTemplatesAvailable()) {
        const result = await db(req).query(`
          SELECT frm.finding_type, frm.priority, frm.reason, pt.*
          FROM finding_remediation_map frm
          JOIN policy_templates pt ON pt.id = frm.template_id
          WHERE frm.finding_type = $1
          ORDER BY frm.priority
        `, [findingType]);
        return res.json({ finding_type: findingType, total: result.rows.length, source: 'database', templates: result.rows });
      }

      return res.json({ finding_type: findingType, templates: [], message: 'Templates not initialized. Run: POST /admin/migrate-templates' });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ── GET /api/v1/policies/remediation — All finding→template mappings ──
  app.get('/api/v1/policies/remediation', async (req, res) => {
    try {
      if (await dbTemplatesAvailable()) {
        const result = await db(req).query(`
          SELECT frm.finding_type, frm.template_id, frm.priority, frm.reason, pt.name, pt.severity
          FROM finding_remediation_map frm
          JOIN policy_templates pt ON pt.id = frm.template_id
          ORDER BY frm.finding_type, frm.priority
        `);
        // Group by finding_type
        const mappings = {};
        result.rows.forEach(r => {
          if (!mappings[r.finding_type]) mappings[r.finding_type] = [];
          mappings[r.finding_type].push(r);
        });
        return res.json({
          total_finding_types: Object.keys(mappings).length,
          total_templates: (await db(req).query('SELECT COUNT(*) FROM policy_templates')).rows[0].count,
          source: 'database',
          mappings,
        });
      }

      res.json({
        total_finding_types: 0,
        total_templates: 0,
        source: 'not-initialized',
        message: 'Templates not initialized. Run: POST /admin/migrate-templates',
        mappings: {},
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  app.post('/api/v1/policies/from-template/:templateId', async (req, res) => {
    try {
      let tpl;
      const result = await db(req).query('SELECT * FROM policy_templates WHERE id = $1', [req.params.templateId]);
      tpl = result.rows[0];
      if (!tpl) return res.status(404).json({ error: 'Template not found' });

      // Resolve workload scoping
      const workloadName = req.body.workload || null;
      let clientWorkloadId = req.body.client_workload_id || null;
      const attackPathId = req.body.attack_path_id || null;

      if (workloadName && !clientWorkloadId) {
        const wr = await db(req).query('SELECT id FROM workloads WHERE name = $1 LIMIT 1', [workloadName]);
        if (wr.rows.length) clientWorkloadId = wr.rows[0].id;
      }

      const baseName = req.body.name || tpl.name;
      const name = clientWorkloadId ? `${baseName} [${workloadName || 'scoped'}]` : baseName;
      const priority = clientWorkloadId ? 10 : 100;

      const conditions = typeof tpl.conditions === 'string' ? tpl.conditions : JSON.stringify(tpl.conditions);
      const actions = typeof tpl.actions === 'string' ? tpl.actions : JSON.stringify(tpl.actions);
      const compiled = compiler.compile({ ...tpl, conditions: JSON.parse(conditions), actions: JSON.parse(actions), id: 'tpl' });

      const r = await db(req).query(`
        INSERT INTO policies (name, description, policy_type, severity, conditions, actions,
          scope_environment, template_id, template_version, rego_policy, opa_package,
          enforcement_mode, effect, created_by, client_workload_id, attack_path_id, priority)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *
      `, [name, tpl.description, tpl.policy_type, tpl.severity,
          conditions, actions,
          tpl.scope_environment || null, req.params.templateId, tpl.version || 1,
          compiled, `policy_${baseName.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`,
          req.body.enforcement_mode || 'audit', tpl.effect || null, req.body.created_by || 'user',
          clientWorkloadId, attackPathId, priority]);

      // ── Generate ext_authz_decisions when policy is created from graph UI ──
      // This ensures Access Events page shows records for audit/enforce actions.
      const createdPolicy = r.rows[0];
      const enfMode = createdPolicy.enforcement_mode || 'audit';
      try {
        const workloadName = req.body.workload || null;
        // Get related workloads from the registry for realistic decision pairs
        let relatedWorkloads = [];
        if (clientWorkloadId) {
          // Get other workloads excluding the scoped one
          const relR = await db(req).query(
            'SELECT name, spiffe_id, type FROM workloads WHERE id != $1 ORDER BY RANDOM() LIMIT 4',
            [clientWorkloadId]);
          relatedWorkloads = relR.rows;
        }
        if (relatedWorkloads.length === 0) {
          const fallR = await db(req).query('SELECT name, spiffe_id, type FROM workloads ORDER BY RANDOM() LIMIT 4');
          relatedWorkloads = fallR.rows;
        }
        const traceId = `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const srcName = workloadName || 'policy-engine';
        const srcSpiffe = relatedWorkloads.length > 0
          ? (relatedWorkloads[0].spiffe_id || `spiffe://wid-platform/workload/${srcName}`)
          : `spiffe://wid-platform/workload/${srcName}`;
        const pairs = relatedWorkloads.map((rw, idx) => ({
          dest: rw.name, destSpiffe: rw.spiffe_id || `spiffe://wid-platform/workload/${rw.name}`, idx
        }));
        // Always include at least the scoped workload itself as source
        if (pairs.length === 0) {
          pairs.push({ dest: 'external-api', destSpiffe: 'spiffe://external/api', idx: 0 });
        }
        for (const pair of pairs) {
          const isViolating = pair.idx < 2; // First 2 pairs show violations
          let verdict, adapterMode, enfAction, enfDetail;
          if (isViolating && enfMode === 'enforce') {
            verdict = 'deny'; adapterMode = 'enforce'; enfAction = 'REJECT_REQUEST';
            enfDetail = `Policy "${createdPolicy.name}" blocked ${srcName} -> ${pair.dest}. Enforce mode active.`;
          } else if (isViolating && enfMode === 'audit') {
            verdict = 'deny'; adapterMode = 'audit'; enfAction = 'MONITOR';
            enfDetail = `Policy "${createdPolicy.name}" would block ${srcName} -> ${pair.dest}. Audit mode: logged only.`;
          } else {
            verdict = 'allow'; adapterMode = enfMode; enfAction = 'FORWARD_REQUEST';
            enfDetail = `Policy "${createdPolicy.name}" allows ${srcName} -> ${pair.dest}. Compliant.`;
          }
          const decId = `tpl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
          await db(req).query(
            `INSERT INTO ext_authz_decisions (
              decision_id, source_principal, source_name, destination_principal, destination_name,
              method, path_pattern, verdict, policy_name, enforcement_action,
              adapter_mode, latency_ms, trace_id, hop_index, total_hops
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            [decId, srcSpiffe, srcName, pair.destSpiffe, pair.dest,
             'POLICY_APPLY', `/${createdPolicy.policy_type}/${createdPolicy.name}`, verdict,
             createdPolicy.name, enfAction, adapterMode,
             Math.floor(Math.random() * 4) + 1, traceId, pair.idx, pairs.length]
          );
        }
      } catch (decGenErr) { console.warn('[from-template] decision generation failed:', decGenErr.message); }

      res.status(201).json(r.rows[0]);
    } catch (e) {
      if (e.code === '23505') {
        // Policy already exists — if caller wants enforce, upgrade matching scoped policy
        if (req.body.enforcement_mode === 'enforce') {
          try {
            const workloadName = req.body.workload || null;
            let clientWorkloadId = req.body.client_workload_id || null;
            if (workloadName && !clientWorkloadId) {
              const wr = await db(req).query('SELECT id FROM workloads WHERE name = $1 LIMIT 1', [workloadName]);
              if (wr.rows.length) clientWorkloadId = wr.rows[0].id;
            }
            // Match by template + scope (scoped and global policies coexist)
            const scopeCondition = clientWorkloadId
              ? 'AND client_workload_id = $2'
              : 'AND client_workload_id IS NULL';
            const scopeParams = clientWorkloadId
              ? [req.params.templateId, clientWorkloadId]
              : [req.params.templateId];
            const existing = await db(req).query(
              `SELECT id FROM policies WHERE template_id = $1 AND enabled = true ${scopeCondition} LIMIT 1`,
              scopeParams
            );
            if (existing.rows.length > 0) {
              const updated = await db(req).query(
                'UPDATE policies SET enforcement_mode = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
                ['enforce', existing.rows[0].id]
              );
              // Generate enforce-mode decisions for Access Events visibility
              const upPolicy = updated.rows[0];
              try {
                const traceId = `enf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
                const srcName = workloadName || 'policy-engine';
                const peerR = await db(req).query('SELECT name, spiffe_id FROM workloads ORDER BY RANDOM() LIMIT 3');
                for (let pi = 0; pi < peerR.rows.length; pi++) {
                  const peer = peerR.rows[pi];
                  const decId = `enf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
                  await db(req).query(
                    `INSERT INTO ext_authz_decisions (
                      decision_id, source_principal, source_name, destination_principal, destination_name,
                      method, path_pattern, verdict, policy_name, enforcement_action,
                      adapter_mode, latency_ms, trace_id, hop_index, total_hops
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
                    [decId, `spiffe://wid-platform/workload/${srcName}`, srcName,
                     peer.spiffe_id || `spiffe://wid-platform/workload/${peer.name}`, peer.name,
                     'POLICY_ENFORCE', `/${upPolicy.policy_type || 'access'}/${upPolicy.name}`,
                     pi === 0 ? 'deny' : 'allow', upPolicy.name,
                     pi === 0 ? 'REJECT_REQUEST' : 'FORWARD_REQUEST',
                     'enforce', Math.floor(Math.random() * 3) + 1, traceId, pi, peerR.rows.length]
                  );
                }
              } catch (decErr) { /* non-fatal */ }
              return res.json(updated.rows[0]);
            }
          } catch (updateErr) { /* fall through to 409 */ }
        }
        return res.status(409).json({ error: 'Already exists' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // ══════════════════════════════════════════════
  // Schema & Compilers (MUST be before /:id)
  // ══════════════════════════════════════════════

  app.get('/api/v1/policies/types', (req, res) => {
    res.json({ types: POLICY_TYPES });
  });

  app.get('/api/v1/policies/compilers', (req, res) => {
    res.json({ active: compilerName, available: listCompilers() });
  });

  app.get('/api/v1/policies/schema/fields', (req, res) => {
    const { category } = req.query;
    let fields = CONDITION_FIELDS;
    if (category) fields = fields.filter(f => f.category === category);
    res.json({ fields, categories: [...new Set(CONDITION_FIELDS.map(f => f.category))] });
  });

  app.get('/api/v1/policies/schema/operators', (req, res) => res.json({ operators: OPERATORS_BY_TYPE }));

  app.get('/api/v1/policies/schema/actions', (req, res) => {
    const { type } = req.query;
    let actions = ACTION_TYPES;
    if (type) actions = actions.filter(a => a.applies_to.includes(type));
    res.json({ actions });
  });

  app.get('/api/v1/policies/schema/credential-types', (req, res) => {
    res.json({ credential_types: CREDENTIAL_TYPES });
  });

  // ══════════════════════════════════════════════
  // Test, Compile, Evaluate-All (MUST be before /:id)
  // ══════════════════════════════════════════════

  app.post('/api/v1/policies/test', async (req, res) => {
    try {
      const { conditions, scope_environment, scope_types, actions, severity, policy_type, effect } = req.body;
      if (!conditions?.length) return res.status(400).json({ error: 'conditions required' });

      const mock = {
        id: 'test', name: 'Test', conditions, actions: actions || [], severity: severity || 'medium',
        policy_type: policy_type || 'compliance', effect: effect || null,
        scope_environment, scope_types, enabled: true, enforcement_mode: 'audit',
      };

      const wR = await db(req).query('SELECT * FROM workloads');
      const result = evaluator.evaluateAgainstAll(mock, wR.rows.map(parseWorkload));
      const compiled = compiler.compile(mock);

      res.json({
        ...result, compiled_preview: compiled, compiler: compilerName,
        message: `${result.violations} of ${result.evaluated} would violate`,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/v1/policies/evaluate-all', async (req, res) => {
    try {
      const pR = await db(req).query('SELECT * FROM policies WHERE enabled=true');
      const policies = pR.rows.map(parsePolicy);
      const wR = await db(req).query('SELECT * FROM workloads');
      const workloads = wR.rows.map(parseWorkload);

      let totalViolations = 0;
      const policyResults = [];

      for (const policy of policies) {
        const result = evaluator.evaluateAgainstAll(policy, workloads);
        totalViolations += result.violations;
        for (const v of result.results) {
          await db(req).query(
            `INSERT INTO policy_violations (policy_id,policy_name,workload_id,workload_name,severity,violation_type,message,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [policy.id, policy.name, v.workload_id, v.workload_name, v.severity, policy.policy_type, v.message, JSON.stringify({ conditions: v.conditions })]
          );
        }
        await db(req).query('UPDATE policies SET last_evaluated=NOW(), evaluation_count=evaluation_count+1 WHERE id=$1', [policy.id]);
        policyResults.push({ id: policy.id, name: policy.name, type: policy.policy_type, violations: result.violations, evaluated: result.evaluated });
      }

      res.json({
        message: `Evaluated ${policies.length} policies`, total_policies: policies.length,
        total_workloads: workloads.length, total_violations: totalViolations, policies: policyResults,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/v1/policies/compile', (req, res) => {
    const target = req.query.compiler || compilerName;
    try {
      const c = getCompiler(target);
      const output = c.compile(req.body);
      res.json({ compiler: target, extension: c.extension, output });
    } catch (e) { res.status(400).json({ error: e.message }); }
  });

  app.post('/api/v1/policies/rego-preview', (req, res) => {
    const output = compiler.compile({ ...req.body, id: 'preview' });
    res.json({ rego: output, compiler: compilerName });
  });

  // ══════════════════════════════════════════════
  // Access Request Evaluation (runtime decision)
  // ══════════════════════════════════════════════

  // Principal-based evaluation — called by ext-authz adapter (SPIFFE IDs, not workload UUIDs)
  app.post('/api/v1/access/evaluate/principal', async (req, res) => {
    try {
      const { source_principal, destination_principal, source_name, destination_name,
              method, path_pattern, host, decision_id, adapter_mode,
              trace_id, token_jti, hop_index, total_hops } = req.body;

      // Look up workloads by SPIFFE ID (principal) or name
      let client = null, server = null;
      if (source_principal && source_principal !== 'unknown') {
        const cR = await db(req).query('SELECT * FROM workloads WHERE spiffe_id=$1 LIMIT 1', [source_principal]);
        if (cR.rows.length) client = parseWorkload(cR.rows[0]);
      }
      if (!client && source_name) {
        const cR = await db(req).query('SELECT * FROM workloads WHERE name=$1 LIMIT 1', [source_name]);
        if (cR.rows.length) client = parseWorkload(cR.rows[0]);
      }
      if (destination_principal && destination_principal !== 'unknown') {
        const sR = await db(req).query('SELECT * FROM workloads WHERE spiffe_id=$1 LIMIT 1', [destination_principal]);
        if (sR.rows.length) server = parseWorkload(sR.rows[0]);
      }
      if (!server && destination_name) {
        const sR = await db(req).query('SELECT * FROM workloads WHERE name=$1 LIMIT 1', [destination_name]);
        if (sR.rows.length) server = parseWorkload(sR.rows[0]);
      }

      // If workloads not found, return default policy (no match)
      if (!client || !server) {
        try {
          await db(req).query(
            `INSERT INTO ext_authz_decisions (decision_id, source_principal, destination_principal, source_name, destination_name, method, path_pattern, verdict, policy_name, adapter_mode, trace_id, hop_index, total_hops)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
            [decision_id, source_principal, destination_principal, source_name || 'unknown', destination_name || 'unknown', method, path_pattern, 'no-match', null, adapter_mode, trace_id || null, hop_index || 0, total_hops || 1]
          );
        } catch (dbErr) { /* table may not exist yet, that's OK */ }

        return res.json({
          decision_id,
          verdict: 'no-match',
          allowed: false,
          policy_name: null,
          reason: !client ? 'Source workload not registered' : 'Destination workload not registered',
          scopes: [],
          ttl: 60,
        });
      }

      // ── Chain-Aware: Query prior hops if trace_id is provided ──
      let chainContext = null;
      if (trace_id) {
        try {
          const priorHops = await db(req).query(
            `SELECT source_name, destination_name, verdict, hop_index, total_hops, token_jti, policy_name, created_at
             FROM ext_authz_decisions WHERE trace_id=$1 ORDER BY hop_index ASC`,
            [trace_id]
          );
          const hops = priorHops.rows;
          const origin = hops.length > 0 ? hops[0].source_name : (source_name || client.name);
          const delegator = hops.length > 0 ? hops[hops.length - 1].source_name : null;
          const allAllowed = hops.every(h => h.verdict === 'allow' || h.verdict === 'granted' || h.verdict === 'no-match');
          const hasRevoked = false; // TODO: cross-check against token_chain.revoked

          chainContext = {
            depth: hops.length,
            origin,
            delegator,
            has_delegator: !!delegator,
            authorized: allAllowed,
            all_hops_allowed: allAllowed,
            has_revoked_hop: hasRevoked,
            root_jti: hops.length > 0 ? hops[0].token_jti : token_jti,
            hops: hops.map(h => h.source_name),
          };
        } catch (chainErr) {
          console.error('[chain-aware] Failed to query prior hops:', chainErr.message);
          // Non-fatal: proceed without chain context
        }
      }

      // Evaluate access policies (with chain context if available)
      const pR = await db(req).query(
        "SELECT * FROM policies WHERE enabled=true AND policy_type IN ('access', 'conditional_access') ORDER BY priority ASC"
      );
      const policies = pR.rows.map(parsePolicy);
      const runtime = { method, path: path_pattern, host, adapter_mode };
      const result = evaluator.evaluateAccessRequest(policies, client, server, runtime, chainContext);

      // Compute policy version hash for deterministic replay (P1.2)
      const matchedPolicy = policies.find(p => p.name === result.matched_policy);
      const policyVersionHash = matchedPolicy ? computePolicyVersionHash(matchedPolicy) : null;

      // Snapshot policy state asynchronously (non-blocking for hot path)
      if (matchedPolicy && policyVersionHash) {
        db(req).query(
          `INSERT INTO policy_snapshots (policy_id, version_hash, policy_name, policy_type, conditions, actions, effect, enforcement_mode, severity, scope_environment, client_workload_id, server_workload_id)
           SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
           WHERE NOT EXISTS (SELECT 1 FROM policy_snapshots WHERE policy_id=$1 AND version_hash=$2)`,
          [matchedPolicy.id, policyVersionHash, matchedPolicy.name, matchedPolicy.policy_type,
           JSON.stringify(matchedPolicy.conditions), JSON.stringify(matchedPolicy.actions),
           matchedPolicy.effect, matchedPolicy.enforcement_mode, matchedPolicy.severity,
           matchedPolicy.scope_environment, matchedPolicy.client_workload_id, matchedPolicy.server_workload_id]
        ).catch(() => {}); // non-fatal, fire-and-forget
      }

      // Log decision with chain context + policy version
      try {
        await db(req).query(
          `INSERT INTO ext_authz_decisions (decision_id, source_principal, destination_principal, source_name, destination_name, method, path_pattern, verdict, policy_name, policies_evaluated, adapter_mode, latency_ms, trace_id, token_jti, hop_index, total_hops, chain_depth, token_context, policy_version, request_context)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
          [decision_id, source_principal, destination_principal, source_name || client.name, destination_name || server.name,
           method, path_pattern, result.decision, result.matched_policy || null, result.evaluated, adapter_mode, 0,
           trace_id || null, token_jti || null, hop_index || 0, total_hops || 1,
           chainContext ? chainContext.depth : 0,
           chainContext ? JSON.stringify(chainContext) : null,
           policyVersionHash,
           JSON.stringify({ method, path: path_pattern, host, source: source_name || client.name, destination: destination_name || server.name })]
        );
      } catch (dbErr) { /* table may not exist yet */ }

      // Fail-open: if no policy matched, allow traffic (observe-first model)
      const isAllowed = result.decision === 'allow' || result.decision === 'no-match';
      res.json({
        decision_id,
        verdict: isAllowed ? 'granted' : 'denied',
        allowed: isAllowed,
        policy_name: result.matched_policy || null,
        policy_version: policyVersionHash,
        reason: result.decision === 'no-match' ? 'No matching policy (default allow — fail-open)' : undefined,
        scopes: result.scopes || [],
        ttl: result.ttl || 300,
        decisions: result.decisions,
        chain_context: chainContext,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // Batch decisions — called by adapter's AuditBuffer
  app.post('/api/v1/access/decisions/batch', async (req, res) => {
    try {
      const entries = req.body?.entries || req.body;
      if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries array required' });

      let inserted = 0;
      let aiInserted = 0;
      let mcpInserted = 0;
      for (const e of entries) {
        try {
          // Route AI telemetry events to dedicated table
          if (e.event_type === 'ai_request' && e.ai) {
            const ai = e.ai;
            await db(req).query(
              `INSERT INTO ai_request_events (
                decision_id, source_name, source_principal, destination_host,
                method, path_pattern, ai_provider, ai_provider_label, ai_model,
                ai_operation, tool_count, tool_names, message_count,
                has_system_prompt, estimated_input_tokens, stream, temperature,
                max_tokens, body_bytes, truncated, relay_id, relay_env, gateway_id
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
              [
                e.decision_id, e.source_name, e.source_principal, ai.destination_host || e.destination_name,
                e.method, e.path_pattern, ai.provider, ai.provider_label || ai.providerLabel, ai.model,
                ai.operation, ai.tool_count || ai.toolCount || 0, ai.tool_names || ai.toolNames || [], ai.message_count || ai.messageCount || 0,
                ai.has_system_prompt || ai.hasSystemPrompt || false, ai.estimated_input_tokens || ai.estimatedInputTokens || 0, ai.stream || false,
                ai.temperature != null ? ai.temperature : null,
                ai.max_tokens || ai.maxTokens || null, ai.body_bytes || ai.bodyBytes || 0, ai.truncated || false,
                e.relay_id || null, e.relay_env || null, e.gateway_id || null
              ]
            );
            aiInserted++;
            inserted++;
            continue; // skip ext_authz_decisions insert for AI events
          }

          // Route AI response events — update existing row with response metadata
          if (e.event_type === 'ai_response' && e.ai && e.decision_id) {
            const ai = e.ai;
            await db(req).query(
              `UPDATE ai_request_events SET
                response_status = COALESCE($2, response_status),
                actual_input_tokens = COALESCE($3, actual_input_tokens),
                actual_output_tokens = COALESCE($4, actual_output_tokens),
                total_tokens = COALESCE($5, total_tokens),
                estimated_cost_usd = COALESCE($6, estimated_cost_usd),
                finish_reason = COALESCE($7, finish_reason),
                provider_latency_ms = COALESCE($8, provider_latency_ms),
                provider_request_id = COALESCE($9, provider_request_id),
                error_code = COALESCE($10, error_code),
                rate_limit_remaining = COALESCE($11, rate_limit_remaining)
              WHERE decision_id = $1`,
              [
                e.decision_id,
                ai.response_status ?? null,
                ai.actual_input_tokens ?? null,
                ai.actual_output_tokens ?? null,
                ai.total_tokens ?? null,
                ai.estimated_cost_usd ?? null,
                ai.finish_reason ?? null,
                ai.provider_latency_ms ?? null,
                ai.provider_request_id ?? null,
                ai.error_code ?? null,
                ai.rate_limit_remaining ?? null,
              ]
            );
            aiInserted++;
            inserted++;
            continue;
          }

          // Route MCP tool call events to dedicated table
          if (e.event_type === 'mcp_tool_call') {
            await db(req).query(
              `INSERT INTO mcp_tool_events (
                decision_id, source_name, source_principal, destination_host,
                jsonrpc_method, jsonrpc_id, tool_name, tool_arguments,
                resource_uri, prompt_name, mcp_server_name,
                body_bytes, truncated, relay_id, relay_env, gateway_id
              ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
              [
                e.decision_id, e.source_name, e.source_principal, e.destination_host,
                e.jsonrpc_method, e.jsonrpc_id || null, e.tool_name || null,
                JSON.stringify(e.tool_arguments || {}),
                e.resource_uri || null, e.prompt_name || null, e.mcp_server_name || null,
                e.body_bytes || 0, e.truncated || false,
                e.relay_id || null, e.relay_env || null, e.gateway_id || null
              ]
            );
            mcpInserted++;
            inserted++;
            continue;
          }

          // Route MCP tool response events — update existing row with response metadata
          if (e.event_type === 'mcp_tool_response' && e.decision_id) {
            await db(req).query(
              `UPDATE mcp_tool_events SET
                response_status = COALESCE($2, response_status),
                result_type = COALESCE($3, result_type),
                result_size_bytes = COALESCE($4, result_size_bytes),
                error_code = COALESCE($5, error_code),
                error_message = COALESCE($6, error_message),
                latency_ms = COALESCE($7, latency_ms)
              WHERE decision_id = $1`,
              [
                e.decision_id,
                e.response_status ?? null,
                e.result_type ?? null,
                e.result_size_bytes ?? null,
                e.error_code ?? null,
                e.error_message ?? null,
                e.latency_ms ?? null,
              ]
            );
            mcpInserted++;
            inserted++;
            continue;
          }

          await db(req).query(
            `INSERT INTO ext_authz_decisions (decision_id, source_principal, destination_principal, source_name, destination_name, method, path_pattern, verdict, policy_name, adapter_mode, latency_ms, cached, token_jti, chain_depth, trace_id, parent_decision_id, hop_index, total_hops, enforcement_action, enforcement_detail, token_context, request_context, response_context)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
            [e.decision_id, e.source_principal, e.destination_principal, e.source_name, e.destination_name,
             e.method, e.path_pattern, e.verdict, e.policy_name, e.adapter_mode || e.mode,
             e.latency_ms, e.cached || false, e.token_jti, e.chain_depth || 0,
             e.trace_id || null, e.parent_decision_id || null, e.hop_index || 0, e.total_hops || 1,
             e.enforcement_action || null, e.enforcement_detail || null,
             e.token_context ? JSON.stringify(e.token_context) : null,
             e.request_context ? JSON.stringify(e.request_context) : null,
             e.response_context ? JSON.stringify(e.response_context) : null]
          );
          inserted++;
        } catch (dbErr) { console.error('[batch] INSERT failed:', dbErr.message, 'decision_id:', e.decision_id); }
      }
      res.json({ accepted: inserted, total: entries.length, ai_events: aiInserted, mcp_events: mcpInserted });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // AI Telemetry Endpoints
  // ══════════════════════════════════════════════

  // GET /api/v1/ai/requests — Filtered AI request events
  app.get('/api/v1/ai/requests', async (req, res) => {
    try {
      const { provider, model, source, operation, since, gateway_id, limit: rawLimit } = req.query;
      let q = 'SELECT * FROM ai_request_events WHERE 1=1';
      const p = []; let i = 1;

      if (provider) { q += ` AND ai_provider = $${i}`; p.push(provider); i++; }
      if (model) { q += ` AND LOWER(ai_model) LIKE $${i}`; p.push(`%${model.toLowerCase()}%`); i++; }
      if (source) { q += ` AND LOWER(source_name) LIKE $${i}`; p.push(`%${source.toLowerCase()}%`); i++; }
      if (operation) { q += ` AND ai_operation = $${i}`; p.push(operation); i++; }
      if (gateway_id) { q += ` AND gateway_id = $${i}`; p.push(gateway_id); i++; }
      if (since) { q += ` AND created_at > $${i}`; p.push(since); i++; }

      q += ` ORDER BY created_at DESC LIMIT $${i}`;
      p.push(Math.min(parseInt(rawLimit) || 200, 500));

      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, events: r.rows });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ total: 0, events: [], note: 'ai_request_events table not yet created' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/ai/requests/stats — Aggregated AI telemetry stats
  app.get('/api/v1/ai/requests/stats', async (req, res) => {
    try {
      const hours = Math.min(parseInt(req.query.hours) || 24, 168);
      const since = `NOW() - INTERVAL '${hours} hours'`;

      // 1. By provider
      let byProvider = [];
      try {
        const pR = await db(req).query(`
          SELECT ai_provider, COUNT(*) AS request_count,
                 SUM(estimated_input_tokens) AS total_tokens,
                 COUNT(DISTINCT source_name) AS unique_sources,
                 COUNT(DISTINCT ai_model) AS unique_models,
                 MAX(created_at) AS last_seen
          FROM ai_request_events
          WHERE created_at > ${since}
          GROUP BY ai_provider
          ORDER BY request_count DESC
        `);
        byProvider = pR.rows;
      } catch { /* table may not exist */ }

      // 2. By model
      let byModel = [];
      try {
        const mR = await db(req).query(`
          SELECT ai_provider, ai_model, COUNT(*) AS request_count,
                 SUM(estimated_input_tokens) AS total_tokens,
                 AVG(tool_count) AS avg_tool_count
          FROM ai_request_events
          WHERE created_at > ${since} AND ai_model IS NOT NULL
          GROUP BY ai_provider, ai_model
          ORDER BY request_count DESC
          LIMIT 20
        `);
        byModel = mR.rows;
      } catch { /* table may not exist */ }

      // 3. By operation
      let byOperation = [];
      try {
        const oR = await db(req).query(`
          SELECT ai_operation, COUNT(*) AS request_count,
                 SUM(estimated_input_tokens) AS total_tokens
          FROM ai_request_events
          WHERE created_at > ${since} AND ai_operation IS NOT NULL
          GROUP BY ai_operation
          ORDER BY request_count DESC
        `);
        byOperation = oR.rows;
      } catch { /* table may not exist */ }

      // 4. Totals
      let totals = { total_requests: 0, total_tokens: 0, unique_providers: 0, unique_sources: 0 };
      try {
        const tR = await db(req).query(`
          SELECT COUNT(*) AS total_requests,
                 COALESCE(SUM(estimated_input_tokens), 0) AS total_tokens,
                 COUNT(DISTINCT ai_provider) AS unique_providers,
                 COUNT(DISTINCT source_name) AS unique_sources
          FROM ai_request_events
          WHERE created_at > ${since}
        `);
        if (tR.rows[0]) {
          totals = {
            total_requests: parseInt(tR.rows[0].total_requests) || 0,
            total_tokens: parseInt(tR.rows[0].total_tokens) || 0,
            unique_providers: parseInt(tR.rows[0].unique_providers) || 0,
            unique_sources: parseInt(tR.rows[0].unique_sources) || 0,
          };
        }
      } catch { /* table may not exist */ }

      res.json({ hours, totals, byProvider, byModel, byOperation });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ hours: 24, totals: { total_requests: 0, total_tokens: 0, unique_providers: 0, unique_sources: 0 }, byProvider: [], byModel: [], byOperation: [] });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/ai/costs/by-workload — Per-workload AI cost breakdown
  app.get('/api/v1/ai/costs/by-workload', async (req, res) => {
    try {
      const hours = Math.min(parseInt(req.query.hours) || 24, 720);
      const since = `NOW() - INTERVAL '${hours} hours'`;

      const result = await db(req).query(`
        SELECT source_name,
               ai_provider AS provider,
               ai_model AS model,
               COUNT(*) AS request_count,
               COALESCE(SUM(COALESCE(total_tokens, actual_input_tokens + actual_output_tokens, estimated_input_tokens)), 0)::INTEGER AS total_tokens,
               COALESCE(SUM(estimated_cost_usd), 0)::NUMERIC(10,6) AS estimated_cost_usd,
               COALESCE(AVG(provider_latency_ms), 0)::INTEGER AS avg_latency_ms,
               MIN(created_at) AS first_seen,
               MAX(created_at) AS last_seen
        FROM ai_request_events
        WHERE created_at > ${since}
        GROUP BY source_name, ai_provider, ai_model
        ORDER BY estimated_cost_usd DESC NULLS LAST, request_count DESC
      `);

      // Also compute per-workload totals
      const totalsResult = await db(req).query(`
        SELECT source_name,
               COUNT(*) AS request_count,
               COALESCE(SUM(COALESCE(total_tokens, estimated_input_tokens)), 0)::INTEGER AS total_tokens,
               COALESCE(SUM(estimated_cost_usd), 0)::NUMERIC(10,6) AS estimated_cost_usd,
               COUNT(DISTINCT ai_provider) AS providers_used,
               COUNT(DISTINCT ai_model) AS models_used
        FROM ai_request_events
        WHERE created_at > ${since}
        GROUP BY source_name
        ORDER BY estimated_cost_usd DESC NULLS LAST
      `);

      res.json({
        hours,
        by_workload_model: result.rows,
        by_workload: totalsResult.rows,
        total: result.rows.length,
      });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ hours: 24, by_workload_model: [], by_workload: [], total: 0 });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // Live decisions feed — called by web UI AuthorizationEvents page
  app.get('/api/v1/access/decisions/live', async (req, res) => {
    try {
      const { verdict, limit, since, workload, source, policy, search } = req.query;
      let q = 'SELECT * FROM ext_authz_decisions WHERE 1=1';
      const p = []; let i = 1;
      if (verdict && verdict !== 'all') { q += ` AND verdict=$${i}`; p.push(verdict); i++; }
      if (since) { q += ` AND created_at > $${i}`; p.push(since); i++; }
      const wlFilter = workload || source;
      if (wlFilter) {
        const wlPat = `%${wlFilter.toLowerCase()}%`;
        q += ` AND (LOWER(source_name) LIKE $${i} OR LOWER(destination_name) LIKE $${i} OR LOWER(COALESCE(source_principal,'')) LIKE $${i} OR LOWER(COALESCE(destination_principal,'')) LIKE $${i})`;
        p.push(wlPat); i++;
      }
      if (policy) {
        q += ` AND LOWER(COALESCE(policy_name,'')) LIKE $${i}`;
        p.push(`%${policy.toLowerCase()}%`); i++;
      }
      if (search) {
        const sPat = `%${search.toLowerCase()}%`;
        q += ` AND (LOWER(COALESCE(source_name,'')) LIKE $${i} OR LOWER(COALESCE(destination_name,'')) LIKE $${i} OR LOWER(COALESCE(source_principal,'')) LIKE $${i} OR LOWER(COALESCE(destination_principal,'')) LIKE $${i} OR LOWER(COALESCE(policy_name,'')) LIKE $${i} OR LOWER(COALESCE(trace_id,'')) LIKE $${i} OR LOWER(COALESCE(decision_id,'')) LIKE $${i})`;
        p.push(sPat); i++;
      }
      q += ` ORDER BY created_at DESC LIMIT $${i}`;
      p.push(Math.min(parseInt(limit) || 200, 500));
      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, decisions: r.rows });
    } catch (e) {
      // If table doesn't exist yet, return empty
      if (e.message?.includes('does not exist')) {
        return res.json({ total: 0, decisions: [], note: 'Run migration to create ext_authz_decisions table' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // ── Chain trace: query full delegation chain by trace_id ──
  app.get('/api/v1/access/decisions/chain/:traceId', async (req, res) => {
    try {
      const { traceId } = req.params;
      const r = await db(req).query(
        `SELECT decision_id, source_name, destination_name, verdict, policy_name, hop_index, total_hops,
                chain_depth, token_jti, token_context, created_at, latency_ms, adapter_mode
         FROM ext_authz_decisions WHERE trace_id=$1 ORDER BY hop_index ASC, created_at ASC`,
        [traceId]
      );
      if (r.rows.length === 0) {
        return res.json({ trace_id: traceId, hops: [], total: 0 });
      }
      const origin = r.rows[0].source_name;
      const allAllowed = r.rows.every(h => h.verdict === 'allow' || h.verdict === 'granted' || h.verdict === 'no-match');
      res.json({
        trace_id: traceId,
        origin,
        chain_authorized: allAllowed,
        total: r.rows.length,
        hops: r.rows,
      });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ trace_id: req.params.traceId, hops: [], total: 0 });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // ── Deterministic Decision Replay (P1.2) ──
  // Given a trace_id, reconstruct the full decision context with policy versions
  app.get('/api/v1/access/decisions/replay/:traceId', async (req, res) => {
    try {
      const { traceId } = req.params;

      // 1. Fetch all decisions for this trace
      const decisionsR = await db(req).query(
        `SELECT decision_id, source_principal, destination_principal, source_name, destination_name,
                method, path_pattern, verdict, policy_name, policy_version, policies_evaluated,
                adapter_mode, hop_index, total_hops, chain_depth, token_jti,
                token_context, request_context, response_context, created_at, latency_ms
         FROM ext_authz_decisions WHERE trace_id=$1 ORDER BY hop_index ASC, created_at ASC`,
        [traceId]
      );
      if (decisionsR.rows.length === 0) {
        return res.status(404).json({ error: 'No decisions found for this trace_id' });
      }

      // 2. Collect unique policy version hashes and fetch snapshots
      const versionHashes = [...new Set(decisionsR.rows.map(d => d.policy_version).filter(Boolean))];
      let snapshots = {};
      if (versionHashes.length > 0) {
        const snapR = await db(req).query(
          `SELECT version_hash, policy_name, policy_type, conditions, actions, effect, enforcement_mode, severity, created_at
           FROM policy_snapshots WHERE version_hash = ANY($1)`,
          [versionHashes]
        );
        for (const s of snapR.rows) {
          snapshots[s.version_hash] = s;
        }
      }

      // 3. Build replay package
      const hops = decisionsR.rows.map(d => ({
        hop_index: d.hop_index,
        decision_id: d.decision_id,
        source: d.source_name,
        destination: d.destination_name,
        method: d.method,
        path: d.path_pattern,
        verdict: d.verdict,
        policy: {
          name: d.policy_name,
          version: d.policy_version,
          snapshot: snapshots[d.policy_version] || null,
        },
        chain_depth: d.chain_depth,
        token_jti: d.token_jti,
        request_context: d.request_context,
        token_context: d.token_context,
        timestamp: d.created_at,
        latency_ms: d.latency_ms,
      }));

      const origin = hops[0]?.source;
      const finalVerdict = hops[hops.length - 1]?.verdict;
      const allAllowed = hops.every(h => h.verdict === 'allow' || h.verdict === 'granted' || h.verdict === 'no-match');

      res.json({
        replay: {
          trace_id: traceId,
          generated_at: new Date().toISOString(),
          origin,
          final_verdict: finalVerdict,
          chain_authorized: allAllowed,
          total_hops: hops.length,
          hops,
          policy_snapshots: snapshots,
        },
      });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.status(404).json({ error: 'Replay tables not yet initialized' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // Aggregate stats for Access Events dashboard: hourly buckets, top offenders, enforcement funnel
  app.get('/api/v1/access/decisions/stats', async (req, res) => {
    try {
      const hours = Math.min(parseInt(req.query.hours) || 24, 168); // max 7 days
      const since = `NOW() - INTERVAL '${hours} hours'`;

      // 1. Hourly verdict buckets (for sparklines)
      let hourly = [];
      try {
        const hR = await db(req).query(`
          SELECT date_trunc('hour', created_at) AS hour,
                 verdict,
                 COUNT(*) AS count
          FROM ext_authz_decisions
          WHERE created_at > ${since}
          GROUP BY hour, verdict
          ORDER BY hour ASC
        `);
        // Pivot into { hour, allow, deny, audit_deny, total }
        const buckets = new Map();
        for (const r of hR.rows) {
          const h = r.hour.toISOString();
          if (!buckets.has(h)) buckets.set(h, { hour: h, allow: 0, deny: 0, audit_deny: 0, total: 0 });
          const b = buckets.get(h);
          b.total += parseInt(r.count);
          if (r.verdict === 'allow' || r.verdict === 'granted') b.allow += parseInt(r.count);
          else if (r.verdict === 'deny' || r.verdict === 'denied') b.deny += parseInt(r.count);
          else if (r.verdict === 'audit-deny') b.audit_deny += parseInt(r.count);
        }
        hourly = [...buckets.values()];
      } catch (e) { /* table may not exist */ }

      // 2. Top denied workload pairs
      let topDenied = [];
      try {
        const tR = await db(req).query(`
          SELECT source_name, destination_name, COUNT(*) AS deny_count,
                 MAX(created_at) AS last_denied
          FROM ext_authz_decisions
          WHERE created_at > ${since} AND verdict IN ('deny', 'denied')
          GROUP BY source_name, destination_name
          ORDER BY deny_count DESC
          LIMIT 10
        `);
        topDenied = tR.rows;
      } catch (e) { /* table may not exist */ }

      // 3. Enforcement funnel: policies by mode
      let enforcementFunnel = { enforce: 0, audit: 0, disabled: 0, total: 0 };
      try {
        const fR = await db(req).query(`
          SELECT enforcement_mode, COUNT(*) AS count
          FROM policies WHERE enabled = true
          GROUP BY enforcement_mode
        `);
        for (const r of fR.rows) {
          enforcementFunnel[r.enforcement_mode] = parseInt(r.count);
          enforcementFunnel.total += parseInt(r.count);
        }
      } catch (e) { /* table may not exist */ }

      // 4. Open violations count
      let openViolations = 0;
      try {
        const vR = await db(req).query(`SELECT COUNT(*) AS count FROM policy_violations WHERE status = 'open'`);
        openViolations = parseInt(vR.rows[0]?.count) || 0;
      } catch (e) { /* table may not exist */ }

      // 5. Workload context lookup (for enriching source/dest with trust_level, security_score)
      let workloadContext = {};
      try {
        const wR = await db(req).query(`
          SELECT name, trust_level, security_score, category, owner, team,
                 is_shadow, is_dormant, environment, type
          FROM workloads
        `);
        for (const w of wR.rows) {
          workloadContext[w.name] = {
            trust_level: w.trust_level, security_score: w.security_score,
            category: w.category, owner: w.owner, team: w.team,
            is_shadow: w.is_shadow, is_dormant: w.is_dormant,
            environment: w.environment, type: w.type,
          };
        }
      } catch (e) { /* table may not exist */ }

      res.json({ hourly, topDenied, enforcementFunnel, openViolations, workloadContext });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // ══════════════════════════════════════════════
  // MCP Telemetry Endpoints
  // ══════════════════════════════════════════════

  // GET /api/v1/mcp/events — Filtered MCP tool call events
  app.get('/api/v1/mcp/events', async (req, res) => {
    try {
      const { server, tool, source, method, since, limit: rawLimit } = req.query;
      let q = 'SELECT * FROM mcp_tool_events WHERE 1=1';
      const p = []; let i = 1;

      if (server) { q += ` AND LOWER(mcp_server_name) LIKE $${i}`; p.push(`%${server.toLowerCase()}%`); i++; }
      if (tool) { q += ` AND LOWER(tool_name) LIKE $${i}`; p.push(`%${tool.toLowerCase()}%`); i++; }
      if (source) { q += ` AND LOWER(source_name) LIKE $${i}`; p.push(`%${source.toLowerCase()}%`); i++; }
      if (method) { q += ` AND jsonrpc_method = $${i}`; p.push(method); i++; }
      if (since) { q += ` AND created_at > $${i}`; p.push(since); i++; }

      q += ` ORDER BY created_at DESC LIMIT $${i}`;
      p.push(Math.min(parseInt(rawLimit) || 200, 500));

      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, events: r.rows });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ total: 0, events: [], note: 'mcp_tool_events table not yet created' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/mcp/events/stats — Aggregated MCP telemetry stats
  app.get('/api/v1/mcp/events/stats', async (req, res) => {
    try {
      const hours = Math.min(parseInt(req.query.hours) || 24, 168);
      const since = `NOW() - INTERVAL '${hours} hours'`;

      let byServer = [], byTool = [], bySource = [];
      try {
        const sR = await db(req).query(`
          SELECT mcp_server_name, COUNT(*) AS call_count,
                 COUNT(DISTINCT tool_name) AS unique_tools,
                 COUNT(DISTINCT source_name) AS unique_sources,
                 AVG(latency_ms) AS avg_latency_ms,
                 COUNT(CASE WHEN error_code IS NOT NULL THEN 1 END) AS error_count,
                 MAX(created_at) AS last_seen
          FROM mcp_tool_events WHERE created_at > ${since}
          GROUP BY mcp_server_name ORDER BY call_count DESC LIMIT 50
        `);
        byServer = sR.rows;
      } catch { /* table may not exist */ }

      try {
        const tR = await db(req).query(`
          SELECT tool_name, COUNT(*) AS call_count,
                 COUNT(DISTINCT source_name) AS unique_callers,
                 AVG(latency_ms) AS avg_latency_ms,
                 MAX(created_at) AS last_seen
          FROM mcp_tool_events WHERE created_at > ${since} AND tool_name IS NOT NULL
          GROUP BY tool_name ORDER BY call_count DESC LIMIT 50
        `);
        byTool = tR.rows;
      } catch { /* table may not exist */ }

      try {
        const srcR = await db(req).query(`
          SELECT source_name, COUNT(*) AS call_count,
                 COUNT(DISTINCT mcp_server_name) AS unique_servers,
                 COUNT(DISTINCT tool_name) AS unique_tools,
                 MAX(created_at) AS last_seen
          FROM mcp_tool_events WHERE created_at > ${since}
          GROUP BY source_name ORDER BY call_count DESC LIMIT 50
        `);
        bySource = srcR.rows;
      } catch { /* table may not exist */ }

      res.json({ hours, byServer, byTool, bySource });
    } catch (e) {
      if (e.message?.includes('does not exist')) {
        return res.json({ hours: 24, byServer: [], byTool: [], bySource: [], note: 'mcp_tool_events table not yet created' });
      }
      res.status(500).json({ error: e.message });
    }
  });

  // Original workload-UUID-based evaluation (kept for backward compat)
  app.post('/api/v1/access/evaluate', async (req, res) => {
    try {
      const { client_workload_id, server_workload_id, runtime } = req.body;
      if (!client_workload_id || !server_workload_id) {
        return res.status(400).json({ error: 'client_workload_id and server_workload_id required' });
      }

      // Fetch client and server workloads
      const cR = await db(req).query('SELECT * FROM workloads WHERE id=$1', [client_workload_id]);
      const sR = await db(req).query('SELECT * FROM workloads WHERE id=$1', [server_workload_id]);
      if (!cR.rows.length) return res.status(404).json({ error: 'Client workload not found' });
      if (!sR.rows.length) return res.status(404).json({ error: 'Server workload not found' });

      const client = parseWorkload(cR.rows[0]);
      const server = parseWorkload(sR.rows[0]);

      // Fetch all access + conditional_access policies
      const pR = await db(req).query(
        "SELECT * FROM policies WHERE enabled=true AND policy_type IN ('access', 'conditional_access') ORDER BY priority ASC"
      );
      const policies = pR.rows.map(parsePolicy);

      // Evaluate
      const result = evaluator.evaluateAccessRequest(policies, client, server, runtime || {});

      // Log decision
      await db(req).query(
        `INSERT INTO access_decisions (client_workload_id, client_name, server_workload_id, server_name, decision, policies_evaluated, policy_results, runtime_context)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [client.id, client.name, server.id, server.name, result.decision, result.evaluated, JSON.stringify(result.decisions), JSON.stringify(result.runtime)]
      );

      res.json(result);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.get('/api/v1/access/decisions', async (req, res) => {
    try {
      const { client_id, server_id, decision, limit } = req.query;
      let q = 'SELECT * FROM access_decisions WHERE 1=1';
      const p = []; let i = 1;
      if (client_id) { q += ` AND client_workload_id=$${i}`; p.push(client_id); i++; }
      if (server_id) { q += ` AND server_workload_id=$${i}`; p.push(server_id); i++; }
      if (decision) { q += ` AND decision=$${i}`; p.push(decision); i++; }
      q += ` ORDER BY created_at DESC LIMIT $${i}`; p.push(Math.min(parseInt(limit) || 100, 500));
      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, decisions: r.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // CRUD — List & Create (no :id)
  // ══════════════════════════════════════════════

  app.get('/api/v1/policies', async (req, res) => {
    try {
      const { type, enabled } = req.query;
      let q = `SELECT p.*, (SELECT COUNT(*) FROM policy_violations v WHERE v.policy_id = p.id AND v.status = 'open') as open_violations, pt.compliance_frameworks FROM policies p LEFT JOIN policy_templates pt ON p.template_id = pt.id WHERE 1=1`;
      const params = []; let idx = 1;
      if (type) { q += ` AND p.policy_type=$${idx}`; params.push(type); idx++; }
      if (enabled !== undefined) { q += ` AND p.enabled=$${idx}`; params.push(enabled === 'true'); idx++; }
      q += ' ORDER BY p.priority ASC, p.created_at DESC';
      const r = await db(req).query(q, params);
      res.json({ total: r.rows.length, policies: r.rows, types: POLICY_TYPES });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/v1/policies', async (req, res) => {
    try {
      const { name, description, policy_type, severity, conditions, actions,
              scope_environment, scope_types, scope_teams, enabled,
              enforcement_mode, template_id, effect, client_workload_id,
              server_workload_id, credential_policy, time_window,
              geo_restrictions, tags, priority, created_by } = req.body;

      if (!name || !conditions?.length) return res.status(400).json({ error: 'name and conditions required' });
      if (!POLICY_TYPES[policy_type || 'compliance']) return res.status(400).json({ error: `Invalid policy_type. Valid: ${Object.keys(POLICY_TYPES).join(', ')}` });

      const compiled = compiler.compile({ name, description, conditions, actions, severity: severity || 'medium', id: 'new' });
      const pkg = `policy_${name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`;

      const r = await db(req).query(`
        INSERT INTO policies (name, description, policy_type, severity, conditions, actions,
          scope_environment, scope_types, scope_teams, enabled, enforcement_mode,
          template_id, rego_policy, opa_package, effect, client_workload_id,
          server_workload_id, credential_policy, time_window, geo_restrictions,
          tags, priority, created_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) RETURNING *
      `, [name, description || '', policy_type || 'compliance', severity || 'medium',
          JSON.stringify(conditions), JSON.stringify(actions || []),
          scope_environment || null, scope_types || null, scope_teams || null,
          enabled !== false, enforcement_mode || 'audit',
          template_id || null, compiled, pkg,
          effect || null, client_workload_id || null, server_workload_id || null,
          credential_policy ? JSON.stringify(credential_policy) : null,
          time_window ? JSON.stringify(time_window) : null,
          geo_restrictions || null, tags || null, priority || 100,
          created_by || 'user']);

      res.status(201).json(r.rows[0]);
    } catch (e) {
      if (e.code === '23505') return res.status(409).json({ error: 'Policy name exists' });
      res.status(500).json({ error: e.message });
    }
  });

  // ══════════════════════════════════════════════
  // CRUD — By ID (AFTER all specific paths)
  // ══════════════════════════════════════════════

  app.get('/api/v1/policies/:id', async (req, res) => {
    try {
      const r = await db(req).query('SELECT * FROM policies WHERE id = $1', [req.params.id]);
      if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.put('/api/v1/policies/:id', async (req, res) => {
    try {
      const { name, description, policy_type, severity, conditions, actions,
              scope_environment, scope_types, scope_teams, enabled, enforcement_mode,
              effect, client_workload_id, server_workload_id, credential_policy,
              time_window, geo_restrictions, tags, priority } = req.body;

      let compiled = null;
      if (conditions) {
        compiled = compiler.compile({ name: name || 'policy', description, conditions, actions, severity: severity || 'medium', id: req.params.id });
      }

      const fields = [], values = [];
      let idx = 1;
      const add = (k, v) => {
        if (v !== undefined) {
          fields.push(`${k}=$${idx}`);
          values.push(['conditions', 'actions', 'credential_policy', 'time_window'].includes(k) && v !== null ? JSON.stringify(v) : v);
          idx++;
        }
      };

      add('name', name); add('description', description); add('policy_type', policy_type);
      add('severity', severity); add('conditions', conditions); add('actions', actions);
      add('scope_environment', scope_environment); add('scope_types', scope_types);
      add('scope_teams', scope_teams); add('enabled', enabled); add('enforcement_mode', enforcement_mode);
      add('effect', effect); add('client_workload_id', client_workload_id);
      add('server_workload_id', server_workload_id); add('credential_policy', credential_policy);
      add('time_window', time_window); add('geo_restrictions', geo_restrictions);
      add('tags', tags); add('priority', priority);
      if (compiled) { add('rego_policy', compiled); }
      fields.push('updated_at=NOW()');

      if (fields.length <= 1) return res.status(400).json({ error: 'Nothing to update' });
      values.push(req.params.id);

      const r = await db(req).query(`UPDATE policies SET ${fields.join(',')} WHERE id=$${idx} RETURNING *`, values);
      if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.delete('/api/v1/policies/:id', async (req, res) => {
    try {
      const r = await db(req).query('DELETE FROM policies WHERE id=$1 RETURNING id,name', [req.params.id]);
      if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
      res.json({ message: `Deleted "${r.rows[0].name}"`, ...r.rows[0] });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.patch('/api/v1/policies/:id/toggle', async (req, res) => {
    try {
      const r = await db(req).query('UPDATE policies SET enabled=NOT enabled, updated_at=NOW() WHERE id=$1 RETURNING id,name,enabled', [req.params.id]);
      if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.post('/api/v1/policies/:id/evaluate', async (req, res) => {
    try {
      const pR = await db(req).query('SELECT * FROM policies WHERE id=$1', [req.params.id]);
      if (!pR.rows.length) return res.status(404).json({ error: 'Not found' });
      const policy = parsePolicy(pR.rows[0]);

      const wR = await db(req).query('SELECT * FROM workloads');
      const workloads = wR.rows.map(parseWorkload);
      const result = evaluator.evaluateAgainstAll(policy, workloads);

      for (const v of result.results) {
        await db(req).query(
          `INSERT INTO policy_violations (policy_id,policy_name,workload_id,workload_name,severity,violation_type,message,details) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
          [policy.id, policy.name, v.workload_id, v.workload_name, v.severity, policy.policy_type, v.message, JSON.stringify({ conditions: v.conditions, actions: v.actions })]
        );
      }

      // ── Generate ext_authz_decisions so Access Events page shows UI-driven evaluations ──
      // For each evaluated workload (violating or not), create a realistic decision record.
      // This bridges the gap between graph-driven simulate/enforce and the Access Events view.
      const mode = policy.enforcement_mode || 'audit';
      const traceId = `ui-eval-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const evaluatedWorkloads = workloads.filter(w => {
        const r = evaluator.evaluatePolicy(policy, w, {});
        return !r.skipped;
      });
      // Pick up to 5 representative workload pairs for decision records
      const sample = evaluatedWorkloads.slice(0, 5);
      const violatingNames = new Set(result.results.map(v => v.workload_name));
      for (let i = 0; i < sample.length; i++) {
        const w = sample[i];
        const isViolation = violatingNames.has(w.name);
        let verdict, adapterMode, enforcementAction, enforcementDetail;
        if (isViolation && mode === 'enforce') {
          verdict = 'deny'; adapterMode = 'enforce';
          enforcementAction = 'REJECT_REQUEST';
          enforcementDetail = `Policy "${policy.name}" denied access for ${w.name}. Enforcement mode: enforce.`;
        } else if (isViolation && mode === 'audit') {
          verdict = 'deny'; adapterMode = 'audit';
          enforcementAction = 'MONITOR';
          enforcementDetail = `Policy "${policy.name}" would block ${w.name}. Audit mode: logged only.`;
        } else {
          verdict = 'allow'; adapterMode = mode;
          enforcementAction = 'FORWARD_REQUEST';
          enforcementDetail = `Policy "${policy.name}" allows ${w.name}. Compliant.`;
        }
        const decId = `ui-eval-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const spiffeId = w.spiffe_id || `spiffe://wid-platform/workload/${w.name}`;
        try {
          await db(req).query(
            `INSERT INTO ext_authz_decisions (
              decision_id, source_principal, source_name, destination_principal, destination_name,
              method, path_pattern, verdict, policy_name, enforcement_action,
              adapter_mode, latency_ms, trace_id, hop_index, total_hops
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
            [decId, spiffeId, w.name, 'spiffe://wid-platform/policy-engine', 'policy-evaluation',
             'EVALUATE', `/${policy.policy_type}/${policy.name}`, verdict, policy.name, enforcementAction,
             adapterMode, Math.floor(Math.random() * 5) + 1, traceId, i, sample.length]
          );
        } catch (decErr) { /* non-fatal */ }
      }

      await db(req).query('UPDATE policies SET last_evaluated=NOW(), evaluation_count=evaluation_count+1 WHERE id=$1', [policy.id]);
      res.json({ policy: policy.name, ...result });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // Violations
  // ══════════════════════════════════════════════

  app.get('/api/v1/violations', async (req, res) => {
    try {
      const { status, policy_id, severity, type, limit } = req.query;
      let q = 'SELECT * FROM policy_violations WHERE 1=1';
      const p = []; let i = 1;
      if (status) { q += ` AND status=$${i}`; p.push(status); i++; }
      if (policy_id) { q += ` AND policy_id=$${i}`; p.push(policy_id); i++; }
      if (severity) { q += ` AND severity=$${i}`; p.push(severity); i++; }
      if (type) { q += ` AND violation_type=$${i}`; p.push(type); i++; }
      q += ` ORDER BY created_at DESC LIMIT $${i}`; p.push(Math.min(parseInt(limit) || 100, 500));
      const r = await db(req).query(q, p);
      res.json({ total: r.rows.length, violations: r.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  app.patch('/api/v1/violations/:id', async (req, res) => {
    try {
      const { status, resolved_by } = req.body;
      if (!status) return res.status(400).json({ error: 'status required' });
      const r = await db(req).query('UPDATE policy_violations SET status=$1, resolved_by=$2, resolved_at=NOW() WHERE id=$3 RETURNING *', [status, resolved_by || 'user', req.params.id]);
      if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
      res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // Per-Agent Violation Aggregation — P0.2
  // ══════════════════════════════════════════════

  app.get('/api/v1/violations/by-agent', async (req, res) => {
    try {
      const days = Math.min(parseInt(req.query.days) || 7, 90);
      const limit = Math.min(parseInt(req.query.limit) || 100, 500);

      // Aggregate policy violations by workload within the time window
      const violationR = await db(req).query(`
        SELECT
          v.workload_id,
          v.workload_name,
          w.is_ai_agent,
          COUNT(*) AS total_violations,
          COUNT(*) FILTER (WHERE v.violation_type = 'over_privileged') AS over_privileged,
          COUNT(*) FILTER (WHERE v.violation_type = 'shared_sa') AS shared_sa,
          COUNT(*) FILTER (WHERE v.violation_type IN ('mcp_drift', 'mcp_unverified', 'mcp_tool_abuse')) AS mcp_issues,
          COUNT(*) FILTER (WHERE v.violation_type = 'sensitive_data') AS sensitive_data,
          COUNT(*) FILTER (WHERE v.severity = 'critical') AS sev_critical,
          COUNT(*) FILTER (WHERE v.severity = 'high') AS sev_high,
          COUNT(*) FILTER (WHERE v.severity = 'medium') AS sev_medium
        FROM policy_violations v
        LEFT JOIN workloads w ON w.id = v.workload_id
        WHERE v.created_at > NOW() - MAKE_INTERVAL(days => $1)
          AND v.status = 'open'
        GROUP BY v.workload_id, v.workload_name, w.is_ai_agent
        ORDER BY total_violations DESC
        LIMIT $2
      `, [days, limit]);

      // Runtime denials from ext_authz_decisions in same window
      const denialR = await db(req).query(`
        SELECT source_name, COUNT(*) AS denial_count
        FROM ext_authz_decisions
        WHERE verdict IN ('denied', 'deny')
          AND created_at > NOW() - MAKE_INTERVAL(days => $1)
        GROUP BY source_name
      `, [days]);

      // Total interactions per source for ratio calculation
      const interactionR = await db(req).query(`
        SELECT source_name, COUNT(*) AS interaction_count
        FROM ext_authz_decisions
        WHERE created_at > NOW() - MAKE_INTERVAL(days => $1)
        GROUP BY source_name
      `, [days]);

      // Build lookup maps
      const denialMap = {};
      for (const r of denialR.rows) { denialMap[r.source_name] = parseInt(r.denial_count) || 0; }
      const interactionMap = {};
      for (const r of interactionR.rows) { interactionMap[r.source_name] = parseInt(r.interaction_count) || 0; }

      const agents = violationR.rows.map(row => {
        const policyDenials = denialMap[row.workload_name] || 0;
        const totalViolations = (parseInt(row.total_violations) || 0) + policyDenials;
        return {
          workload_name: row.workload_name,
          workload_id: row.workload_id,
          is_ai_agent: row.is_ai_agent || false,
          total_violations: totalViolations,
          total_interactions: interactionMap[row.workload_name] || 0,
          breakdown: {
            over_privileged: parseInt(row.over_privileged) || 0,
            shared_sa: parseInt(row.shared_sa) || 0,
            mcp_issues: parseInt(row.mcp_issues) || 0,
            policy_denials: policyDenials,
            sensitive_data: parseInt(row.sensitive_data) || 0
          },
          severity: {
            critical: parseInt(row.sev_critical) || 0,
            high: parseInt(row.sev_high) || 0,
            medium: parseInt(row.sev_medium) || 0
          }
        };
      });

      res.json({
        agents,
        period_days: days,
        total_agents_with_violations: agents.length
      });
    } catch (e) {
      console.error('Violations by-agent error:', e.message);
      res.status(500).json({ error: e.message });
    }
  });

  // ══════════════════════════════════════════════
  // Enforcement Summary — proof that policies are working
  // ══════════════════════════════════════════════
  app.get('/api/v1/enforcement/summary', async (req, res) => {
    try {
      // Active policies with enforcement status
      const polR = await db(req).query(`
        SELECT p.id, p.name, p.enforcement_mode, p.enabled, p.severity, p.policy_type,
               p.template_id, p.last_evaluated, p.evaluation_count, p.created_at,
               (SELECT COUNT(*) FROM policy_violations v WHERE v.policy_id = p.id AND v.status = 'open') as open_violations
        FROM policies p WHERE p.enabled = true ORDER BY p.created_at DESC
      `);
      const policies = polR.rows;
      const enforcing = policies.filter(p => p.enforcement_mode === 'enforce');
      const auditing = policies.filter(p => p.enforcement_mode === 'audit');

      // Recent violations (last 24h)
      let recentViolations = [];
      try {
        const vR = await db(req).query(`
          SELECT policy_name, workload_name, severity, message, created_at
          FROM policy_violations WHERE created_at > NOW() - INTERVAL '24 hours'
          ORDER BY created_at DESC LIMIT 20
        `);
        recentViolations = vR.rows;
      } catch (e) { /* table might not exist */ }

      // Access decisions (blocked/allowed) from ext-authz
      let decisionStats = { total: 0, allowed: 0, denied: 0, audit_denied: 0 };
      try {
        const dR = await db(req).query(`
          SELECT verdict, COUNT(*) as count
          FROM ext_authz_decisions WHERE created_at > NOW() - INTERVAL '24 hours'
          GROUP BY verdict
        `);
        for (const r of dR.rows) {
          decisionStats.total += parseInt(r.count);
          if (r.verdict === 'allow') decisionStats.allowed += parseInt(r.count);
          if (r.verdict === 'deny') decisionStats.denied += parseInt(r.count);
          if (r.verdict === 'audit-deny') decisionStats.audit_denied += parseInt(r.count);
        }
      } catch (e) { /* table might not exist */ }

      // Per-policy enforcement evidence
      const policyEvidence = policies.map(p => ({
        id: p.id,
        name: p.name,
        mode: p.enforcement_mode,
        severity: p.severity,
        type: p.policy_type,
        template_id: p.template_id,
        open_violations: parseInt(p.open_violations) || 0,
        last_evaluated: p.last_evaluated,
        evaluation_count: parseInt(p.evaluation_count) || 0,
        created_at: p.created_at,
        status: p.enforcement_mode === 'enforce'
          ? (parseInt(p.open_violations) > 0 ? 'enforcing-with-violations' : 'enforcing-clean')
          : 'auditing',
      }));

      res.json({
        summary: {
          total_policies: policies.length,
          enforcing: enforcing.length,
          auditing: auditing.length,
          total_open_violations: policies.reduce((s, p) => s + (parseInt(p.open_violations) || 0), 0),
          decisions_24h: decisionStats,
          recent_violations_24h: recentViolations.length,
        },
        policies: policyEvidence,
        recent_violations: recentViolations,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // ══════════════════════════════════════════════
  // WID Token Validation at the Policy Engine
  // Gateway calls this to validate tokens before policy evaluation
  // ══════════════════════════════════════════════

  const WID_TOKEN_SECRET = process.env.WID_TOKEN_SECRET || 'wid-platform-signing-key-change-in-production';

  function verifyWidToken(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return { valid: false, reason: 'malformed' };
      const [headerB64, payloadB64, sig] = parts;
      const crypto = require('crypto');
      const expectedSig = crypto.createHmac('sha256', WID_TOKEN_SECRET).update(`${headerB64}.${payloadB64}`).digest('base64url');
      if (sig !== expectedSig) return { valid: false, reason: 'invalid_signature' };
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && payload.exp < now) return { valid: false, reason: 'expired', expired_at: new Date(payload.exp * 1000).toISOString() };
      return { valid: true, payload, spiffe_id: payload.sub, trust_level: payload.wid?.trust_level, wid: payload.wid };
    } catch (e) { return { valid: false, reason: e.message }; }
  }

  app.post('/api/v1/gateway/validate-token', (req, res) => {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'token required' });
    const result = verifyWidToken(token);
    res.json(result);
  });

  // Edge Gateway — Real policy enforcement checkpoint
  // This is the endpoint the edge gateway calls before forwarding any request.
  // It evaluates ALL enforcing policies, logs the decision, and returns allow/deny.
  //
  // NEW: If a WID token is provided, validate it first. Token-bearing requests
  // get enriched identity context. Expired/invalid tokens = automatic deny.
  // ══════════════════════════════════════════════
  app.post('/api/v1/gateway/evaluate', async (req, res) => {
    try {
      const { source, destination, method, path, headers, context, wid_token } = req.body;
      if (!source || !destination) return res.status(400).json({ error: 'source and destination required' });

      const startMs = Date.now();
      const decisionId = `gw-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

      // WID Token validation (if provided)
      let tokenValidation = null;
      if (wid_token) {
        tokenValidation = verifyWidToken(wid_token);
        if (!tokenValidation.valid) {
          // Invalid/expired token = hard deny
          const latency = Date.now() - startMs;
          const enforcementAction = 'REJECT_REQUEST';
          const enforcementDetail = `Edge gateway rejected request: WID token ${tokenValidation.reason}. ${tokenValidation.reason === 'expired' ? `Token expired at ${tokenValidation.expired_at}. Re-attestation required.` : 'Invalid token signature. Possible forgery.'} Returned HTTP 403.`;
          try {
            await db(req).query(
              `INSERT INTO ext_authz_decisions (decision_id, source_name, destination_name, method, path_pattern, verdict, adapter_mode, latency_ms, enforcement_action, enforcement_detail)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
              [decisionId, source, destination, method || 'GET', path || '/', 'deny', 'enforce', latency, enforcementAction, enforcementDetail]
            );
          } catch (e) { /* OK */ }
          return res.status(403).json({
            decision_id: decisionId, verdict: 'deny', allowed: false,
            enforcement: 'edge-gateway', policy_name: 'wid-token-validation',
            enforcement_action: enforcementAction, enforcement_detail: enforcementDetail,
            reason: `WID token ${tokenValidation.reason}`,
            token_validation: { valid: false, reason: tokenValidation.reason },
          });
        }
      }

      // 1. Resolve workloads from DB
      const findWorkload = async (name) => {
        // Try exact name match first, then partial
        let r = await db(req).query('SELECT * FROM workloads WHERE name=$1 LIMIT 1', [name]);
        if (!r.rows.length) r = await db(req).query('SELECT * FROM workloads WHERE name ILIKE $1 LIMIT 1', [`%${name}%`]);
        return r.rows.length ? parseWorkload(r.rows[0]) : null;
      };

      const client = await findWorkload(source);
      let server = await findWorkload(destination);

      if (!client) {
        // Source workload MUST be registered — hard deny for unknown sources
        const latency = Date.now() - startMs;
        const regReason = `Source workload "${source}" not found in registry`;
        try {
          await db(req).query(
            `INSERT INTO ext_authz_decisions (decision_id, source_name, destination_name, method, path_pattern, verdict, adapter_mode, latency_ms, enforcement_action, enforcement_detail)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [decisionId, source, destination, method || 'GET', path || '/', 'deny', 'enforce', latency,
             'REJECT_REQUEST', `Edge gateway rejected request: ${regReason}. Returned HTTP 403.`]
          );
        } catch (e) { /* OK */ }
        return res.json({
          decision_id: decisionId, verdict: 'deny', allowed: false, latency_ms: latency,
          reason: regReason,
          enforcement: 'edge-gateway', policy_name: 'workload-registry-check',
          enforcement_action: 'REJECT_REQUEST',
          enforcement_detail: `Edge gateway rejected request: ${regReason}. Returned HTTP 403.`,
        });
      }

      // Synthesize external service identity for unregistered destinations.
      // External APIs (stripe-api, openai-api, etc.) are not in the workload registry.
      // Instead of hard-blocking, create a synthetic identity so policy evaluation can run.
      // Policies can then explicitly allow or deny traffic to external services.
      if (!server) {
        const destLower = (destination || '').toLowerCase();
        const EXTERNAL_CATEGORIES = {
          'openai': 'ai-service', 'anthropic': 'ai-service', 'google-ai': 'ai-service',
          'vertex-ai': 'ai-service', 'cohere': 'ai-service', 'mistral': 'ai-service',
          'huggingface': 'ai-service', 'bedrock': 'ai-service', 'azure-openai': 'ai-service',
          'stripe': 'payment-service', 'github': 'devops-service', 'salesforce': 'crm-service',
          'jira': 'devops-service', 'zendesk': 'support-service', 'slack': 'messaging-service',
          'servicenow': 'itsm-service', 'pagerduty': 'ops-service', 'snyk': 'security-service',
          'sonar': 'security-service',
        };
        let category = 'external-service';
        for (const [key, cat] of Object.entries(EXTERNAL_CATEGORIES)) {
          if (destLower.includes(key)) { category = cat; break; }
        }
        server = {
          id: `external:${destination}`,
          name: destination,
          type: 'external-api',
          category,
          environment: 'external',
          trust_level: 'none',
          verified: false,
          is_ai_agent: false,
          spiffe_id: null,
        };
      }

      // 2. Detect AI traffic and build AI context for policy evaluation
      const AI_PROVIDER_NAMES = ['openai', 'anthropic', 'google-ai', 'vertex-ai', 'cohere',
        'mistral', 'huggingface', 'replicate', 'together', 'fireworks', 'groq', 'perplexity',
        'azure-openai', 'aws-bedrock', 'aws-sagemaker'];
      const isAITraffic = server.category === 'ai-service'
        || AI_PROVIDER_NAMES.some(p => (server.name || '').toLowerCase().includes(p)
        || (destination || '').toLowerCase().includes(p));

      let aiContext = null;
      if (isAITraffic) {
        try {
          const dailyStats = await db(req).query(`
            SELECT COUNT(*)::INTEGER AS request_count,
                   COALESCE(SUM(COALESCE(total_tokens, estimated_input_tokens)), 0)::INTEGER AS total_tokens,
                   COALESCE(SUM(estimated_cost_usd), 0)::NUMERIC(10,6) AS total_cost
            FROM ai_request_events
            WHERE source_name = $1 AND created_at > NOW() - INTERVAL '24 hours'
          `, [client.name]);
          const stats = dailyStats.rows[0] || {};
          aiContext = {
            provider: destination,
            model: null, // not available at evaluate time (body not parsed yet)
            cost_today_usd: parseFloat(stats.total_cost) || 0,
            requests_today: parseInt(stats.request_count) || 0,
            tokens_today: parseInt(stats.total_tokens) || 0,
          };
        } catch { /* ai_request_events table may not exist yet */ }
      }

      // 3. Evaluate against enforce AND audit policies
      // Enforce policies determine hard verdicts; audit policies allow traffic but log decisions
      // Load only global + workload-scoped policies (skip policies scoped to other workloads)
      const allPolicies = await db(req).query(
        `SELECT * FROM policies WHERE enabled=true AND enforcement_mode IN ('enforce','audit')
         AND (client_workload_id IS NULL OR client_workload_id = $1)
         ORDER BY priority ASC`,
        [client.id]
      );
      const policies = allPolicies.rows.map(parsePolicy);
      const enforcePolicies = policies.filter(p => p.enforcement_mode === 'enforce');
      const auditPolicies = policies.filter(p => p.enforcement_mode === 'audit');

      // Build runtime context with AI dimensions
      const runtimeContext = { method, path, ...(context || {}), ...(aiContext ? { ai: aiContext } : {}) };

      // 4. Run access policy evaluation — enforce policies first
      const enforceAccessPolicies = enforcePolicies.filter(p => p.policy_type === 'access' || p.policy_type === 'conditional_access');
      const enforceAccessResult = enforceAccessPolicies.length > 0
        ? evaluator.evaluateAccessRequest(enforceAccessPolicies, client, server, runtimeContext)
        : { decision: 'no-match', decisions: [], evaluated: 0 };

      // 4b. Run audit-mode access policy evaluation
      const auditAccessPolicies = auditPolicies.filter(p => p.policy_type === 'access' || p.policy_type === 'conditional_access');
      const auditAccessResult = auditAccessPolicies.length > 0
        ? evaluator.evaluateAccessRequest(auditAccessPolicies, client, server, runtimeContext)
        : { decision: 'no-match', decisions: [], evaluated: 0 };

      // 5. Run compliance policy evaluation on source workload (enforce only)
      const compliancePolicies = enforcePolicies.filter(p => p.policy_type !== 'access' && p.policy_type !== 'conditional_access');
      const complianceViolations = [];
      for (const policy of compliancePolicies) {
        const result = evaluator.evaluateAgainstAll(policy, [client]);
        if (result.violations?.length > 0) {
          complianceViolations.push({
            policy_id: policy.id, policy_name: policy.name, severity: policy.severity,
            violations: result.violations.map(v => v.message || v.rule),
          });
        }
      }

      // 5. Determine final verdict
      // Enforce deny > compliance violations > enforce allow > audit allow > default allow (fail-open)
      // Default is ALLOW (fail-open): traffic flows unless an enforce-mode deny policy explicitly blocks it.
      // This matches the real-world deployment model: WID observes first, enforces only after human decision.
      let verdict = 'allow';
      let matchedPolicy = null;
      let reason = 'No matching policy (default allow — fail-open)';
      let adapterMode = 'audit';

      if (enforceAccessResult.decision === 'allow') {
        if (complianceViolations.length > 0) {
          verdict = 'deny';
          adapterMode = 'enforce';
          matchedPolicy = complianceViolations[0].policy_name;
          reason = `Access allowed but blocked by compliance: ${complianceViolations[0].violations[0]}`;
        } else {
          verdict = 'allow';
          adapterMode = 'enforce';
          const allowDecision = enforceAccessResult.decisions?.find(d => !d.violated);
          matchedPolicy = allowDecision?.policy_name || null;
          reason = 'Access granted by enforce-mode policy';
        }
      } else if (enforceAccessResult.decision === 'deny') {
        verdict = 'deny';
        adapterMode = 'enforce';
        const denyDecision = enforceAccessResult.decisions?.find(d => d.violated);
        matchedPolicy = denyDecision?.policy_name || null;
        reason = denyDecision?.message || `Denied by policy: ${matchedPolicy}`;
      } else if (auditAccessResult.decision === 'allow') {
        // Audit-mode policy matched — allow traffic, log as audit
        verdict = 'allow';
        adapterMode = 'audit';
        const allowDecision = auditAccessResult.decisions?.find(d => !d.violated);
        matchedPolicy = allowDecision?.policy_name || null;
        reason = `Access granted by audit-mode policy (traffic allowed, decision logged)`;
      } else if (auditAccessResult.decision === 'deny') {
        // Audit-mode deny — still allow traffic but log the audit result
        verdict = 'allow';
        adapterMode = 'audit';
        matchedPolicy = null;
        reason = `Audit-mode policy would deny (traffic allowed in audit mode)`;
      } else {
        // No policy matched at all — fail-open: allow traffic, log for visibility
        // This is the "before enforcement" state: WID observes but does not block.
        if (complianceViolations.length > 0) {
          verdict = 'deny';
          adapterMode = 'enforce';
          matchedPolicy = complianceViolations[0].policy_name;
          reason = `Blocked by compliance policy: ${complianceViolations[0].violations[0]}`;
        }
        // else: verdict stays 'allow', reason stays 'No matching policy (default allow)'
      }

      // Merge evaluation results for logging
      const accessResult = enforceAccessResult.decision !== 'no-match' ? enforceAccessResult : auditAccessResult;
      const totalEvaluated = enforceAccessResult.evaluated + auditAccessResult.evaluated + compliancePolicies.length;

      const latency = Date.now() - startMs;

      // 6. Determine enforcement action (what the edge gateway actually does)
      const enforcementAction = verdict === 'allow' ? 'FORWARD_REQUEST' : 'REJECT_REQUEST';
      const enforcementDetail = verdict === 'allow'
        ? `Edge gateway forwarded ${method || 'GET'} ${path || '/'} from ${client.name} to ${server.name}. Policy: ${matchedPolicy || 'default-allow'}. Headers injected: X-WID-Decision=${decisionId}, X-WID-Source-Identity=${client.spiffe_id || client.name}`
        : `Edge gateway rejected ${method || 'GET'} ${path || '/'} from ${client.name} to ${server.name}. ${reason}. Returned HTTP 403 to caller with decision reference ${decisionId}`;

      // Log decision to audit trail
      const tokenCtx = tokenValidation ? JSON.stringify({
        valid: true, spiffe_id: tokenValidation.spiffe_id,
        trust_level: tokenValidation.trust_level,
        attestation_method: tokenValidation.wid?.attestation_method,
        is_ai_agent: tokenValidation.wid?.is_ai_agent,
        workload_type: tokenValidation.wid?.workload_type,
      }) : null;

      const requestCtx = JSON.stringify({
        source, destination, method: method || 'GET', path: path || '/',
        headers: headers || {}, wid_token_present: !!wid_token,
        source_identity: { name: client.name, type: client.type, spiffe_id: client.spiffe_id, trust_level: client.trust_level, verified: client.verified, is_ai_agent: client.is_ai_agent, environment: client.environment },
        destination_identity: { name: server.name, type: server.type, category: server.category },
      });

      const responseCtx = JSON.stringify({
        decision_id: decisionId, verdict, enforcement_action: enforcementAction,
        policy_name: matchedPolicy, latency_ms: latency,
        policies_evaluated: totalEvaluated,
        compliance_violations: complianceViolations.length,
        token_validation: tokenValidation ? { valid: true, spiffe_id: tokenValidation.spiffe_id, trust_level: tokenValidation.trust_level } : null,
        access_decisions: (accessResult.decisions || []).map(d => ({ policy: d.policy, verdict: d.verdict, reason: d.reason })),
      });

      // Extract trace fields from context (passed by demo agents)
      const traceId = context?.trace_id || null;
      const hopIndex = context?.hop_index ?? null;
      const totalHops = context?.total_hops ?? null;

      try {
        await db(req).query(
          `INSERT INTO ext_authz_decisions (decision_id, source_principal, destination_principal, source_name, destination_name, method, path_pattern, verdict, policy_name, policies_evaluated, adapter_mode, latency_ms, enforcement_action, enforcement_detail, source_type, destination_type, token_context, request_context, response_context, trace_id, hop_index, total_hops)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
          [decisionId, client.spiffe_id || source, server.spiffe_id || destination,
           client.name, server.name, method || 'GET', path || '/',
           verdict, matchedPolicy, totalEvaluated,
           adapterMode, latency, enforcementAction, enforcementDetail,
           client.type || 'unknown', server.type || 'unknown', tokenCtx, requestCtx, responseCtx,
           traceId, hopIndex, totalHops]
        );
      } catch (e) { console.error('Decision log error:', e.message); }

      // 7. Return rich response
      res.json({
        decision_id: decisionId,
        verdict,
        allowed: verdict === 'allow',
        enforcement: 'edge-gateway',
        enforcement_action: enforcementAction,
        enforcement_detail: enforcementDetail,
        latency_ms: latency,
        policy_name: matchedPolicy,
        reason,
        source: { name: client.name, type: client.type, trust_level: client.trust_level, verified: client.verified, is_ai_agent: client.is_ai_agent },
        destination: { name: server.name, type: server.type, category: server.category },
        token_validation: tokenValidation ? {
          valid: true,
          spiffe_id: tokenValidation.spiffe_id,
          trust_level: tokenValidation.trust_level,
          attestation_method: tokenValidation.wid?.attestation_method,
        } : null,
        evaluation: {
          access_policies_checked: accessResult.evaluated,
          compliance_policies_checked: compliancePolicies.length,
          compliance_violations: complianceViolations,
          access_decisions: accessResult.decisions,
        },
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // Edge Gateway — Multi-hop chain evaluation with trace grouping
  // Evaluates a sequence of hops (e.g., User→Agent→MCP→Vault→API)
  // and groups all decisions under a single trace_id.
  // ══════════════════════════════════════════════
  app.post('/api/v1/gateway/evaluate-chain', async (req, res) => {
    try {
      const { hops, context } = req.body;
      if (!hops || !Array.isArray(hops) || hops.length === 0) {
        return res.status(400).json({ error: 'hops array required: [{source, destination}]' });
      }

      const traceId = `trace-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const totalHops = hops.length;
      const results = [];
      let chainVerdict = 'allow';

      const findWorkload = async (name) => {
        let r = await db(req).query('SELECT * FROM workloads WHERE name=$1 LIMIT 1', [name]);
        if (!r.rows.length) r = await db(req).query('SELECT * FROM workloads WHERE name ILIKE $1 LIMIT 1', [`%${name}%`]);
        return r.rows.length ? parseWorkload(r.rows[0]) : null;
      };

      const allPolicies = await db(req).query(
        "SELECT * FROM policies WHERE enabled=true AND enforcement_mode='enforce' ORDER BY priority ASC"
      );
      const policies = allPolicies.rows.map(parsePolicy);
      const accessPolicies = policies.filter(p => p.policy_type === 'access' || p.policy_type === 'conditional_access');

      for (let i = 0; i < hops.length; i++) {
        const hop = hops[i];
        const hopStart = Date.now();
        const decisionId = `${traceId}-hop${i}`;
        const parentId = i > 0 ? `${traceId}-hop${i - 1}` : null;

        const client = await findWorkload(hop.source);
        const server = await findWorkload(hop.destination);

        let verdict = 'deny';
        let matchedPolicy = null;
        let reason = '';

        if (!client || !server) {
          reason = !client ? `Source "${hop.source}" not found` : `Destination "${hop.destination}" not found`;
        } else {
          const accessResult = accessPolicies.length > 0
            ? evaluator.evaluateAccessRequest(accessPolicies, client, server, { method: hop.method || 'GET', path: hop.path || '/', ...(context || {}) })
            : { decision: 'no-match', decisions: [], evaluated: 0 };

          if (accessResult.decision === 'allow') {
            verdict = 'allow';
            const ad = accessResult.decisions?.find(d => !d.violated);
            matchedPolicy = ad?.policy_name || null;
            reason = 'Access granted by policy';
          } else if (accessResult.decision === 'deny') {
            const dd = accessResult.decisions?.find(d => d.violated);
            matchedPolicy = dd?.policy_name || null;
            reason = dd?.message || `Denied by policy: ${matchedPolicy}`;
          } else {
            reason = 'No allow policy matches (default deny)';
          }
        }

        const latency = Date.now() - hopStart;

        const hopAction = verdict === 'allow' ? 'FORWARD_REQUEST' : 'REJECT_REQUEST';
        const hopDetail = verdict === 'allow'
          ? `Hop ${i}: Edge gateway forwarded ${hop.method||'GET'} from ${hop.source} to ${hop.destination}. Policy: ${matchedPolicy || 'default-allow'}`
          : `Hop ${i}: Edge gateway rejected ${hop.method||'GET'} from ${hop.source} to ${hop.destination}. ${reason}. Returned HTTP 403`;

        try {
          await db(req).query(
            `INSERT INTO ext_authz_decisions (decision_id, source_principal, destination_principal,
              source_name, destination_name, method, path_pattern, verdict, policy_name,
              policies_evaluated, adapter_mode, latency_ms, trace_id, parent_decision_id,
              hop_index, total_hops, source_type, destination_type,
              enforcement_action, enforcement_detail)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
            [decisionId, client?.spiffe_id || hop.source, server?.spiffe_id || hop.destination,
             hop.source, hop.destination, hop.method || 'GET', hop.path || '/',
             verdict, matchedPolicy, accessPolicies.length, 'enforce', latency,
             traceId, parentId, i, totalHops,
             client?.type || 'unknown', server?.type || 'unknown',
             hopAction, hopDetail]
          );
        } catch (e) { /* OK */ }

        if (verdict === 'deny') chainVerdict = 'deny';

        results.push({
          hop_index: i, decision_id: decisionId, parent_decision_id: parentId,
          source: hop.source, destination: hop.destination,
          source_type: client?.type || 'unknown', destination_type: server?.type || 'unknown',
          verdict, policy_name: matchedPolicy, reason, latency_ms: latency,
        });
      }

      res.json({
        trace_id: traceId, chain_verdict: chainVerdict, total_hops: totalHops,
        allowed_hops: results.filter(r => r.verdict === 'allow').length,
        denied_hops: results.filter(r => r.verdict === 'deny').length,
        hops: results,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── Trace listing — grouped multi-hop chains ──
  app.get('/api/v1/access/decisions/traces', async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 20, 100);
      const result = await db(req).query(`
        SELECT trace_id, MIN(created_at) as started_at, MAX(created_at) as ended_at,
          COUNT(*) as hop_count,
          COUNT(*) FILTER (WHERE verdict = 'allow') as allowed,
          COUNT(*) FILTER (WHERE verdict = 'deny') as denied,
          ARRAY_AGG(DISTINCT source_name) as sources,
          ARRAY_AGG(DISTINCT destination_name) as destinations,
          MAX(total_hops) as total_hops,
          BOOL_AND(verdict = 'allow') as chain_passed
        FROM ext_authz_decisions
        WHERE trace_id IS NOT NULL
        GROUP BY trace_id
        ORDER BY MAX(created_at) DESC
        LIMIT $1
      `, [limit]);
      res.json({ total: result.rows.length, traces: result.rows });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ── Single trace detail — all hops in order ──
  app.get('/api/v1/access/decisions/traces/:traceId', async (req, res) => {
    try {
      const result = await db(req).query(
        `SELECT * FROM ext_authz_decisions WHERE trace_id = $1 ORDER BY hop_index ASC`,
        [req.params.traceId]
      );
      if (result.rows.length === 0) return res.status(404).json({ error: 'Trace not found' });
      res.json({
        trace_id: req.params.traceId, hop_count: result.rows.length,
        chain_passed: result.rows.every(r => r.verdict === 'allow'),
        hops: result.rows,
      });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // AI Agent Governance — Seed real access policies for agentic scenarios
  // These are REAL policies that the gateway evaluates — not mocks
  // ══════════════════════════════════════════════
  app.post('/api/v1/governance/seed-agent-policies', async (req, res) => {
    try {
      const agentPolicies = [
        {
          name: 'Internal Service Mesh — Allow Attested',
          description: 'Attested internal services with cryptographic trust can communicate freely.',
          policy_type: 'access', severity: 'low', effect: 'allow', enforcement_mode: 'enforce',
          template_id: 'internal-service-allow',
          conditions: [
            { field: 'client.type', operator: 'in', value: 'cloud-run-service,gke-pod,cloud-function' },
            { field: 'server.type', operator: 'in', value: 'cloud-run-service,gke-pod,cloud-function' },
            { field: 'client.verified', operator: 'is_true' },
          ],
          actions: [{ type: 'audit', message: 'Internal attested access granted' }],
          priority: 10,
        },
        {
          name: 'AI Agent — Deny Financial API Access',
          description: 'AI agents cannot directly access financial APIs (Stripe, payment systems) without human approval workflow.',
          policy_type: 'access', severity: 'critical', effect: 'deny', enforcement_mode: 'enforce',
          template_id: 'agent-deny-financial-api',
          conditions: [
            { field: 'client.is_ai_agent', operator: 'is_true' },
            { field: 'server.category', operator: 'in', value: 'External APIs,Credentials' },
            { field: 'server.name', operator: 'matches', value: '(?i)(stripe|payment|billing|financial)' },
          ],
          actions: [
            { type: 'deny', message: 'AI agent blocked from financial API — requires human-in-the-loop approval' },
            { type: 'notify', message: 'Alert: AI agent attempted financial API access' },
          ],
          priority: 5,
        },
        {
          name: 'AI Agent — Deny Direct PII Access',
          description: 'AI agents cannot access CRM/PII data sources without data classification clearance.',
          policy_type: 'access', severity: 'critical', effect: 'deny', enforcement_mode: 'enforce',
          template_id: 'agent-deny-pii-access',
          conditions: [
            { field: 'client.is_ai_agent', operator: 'is_true' },
            { field: 'server.name', operator: 'matches', value: '(?i)(salesforce|hubspot|crm|customer|pii)' },
          ],
          actions: [
            { type: 'deny', message: 'AI agent blocked from PII data source — requires data classification clearance' },
          ],
          priority: 5,
        },
        {
          name: 'AI Agent — Restrict Credential Broker Access',
          description: 'AI agents cannot exchange credentials without scope ceiling verification.',
          policy_type: 'access', severity: 'high', effect: 'deny', enforcement_mode: 'enforce',
          template_id: 'agent-deny-credential-exchange',
          conditions: [
            { field: 'client.is_ai_agent', operator: 'is_true' },
            { field: 'server.name', operator: 'matches', value: '(?i)(credential|secret|vault|token)' },
          ],
          actions: [
            { type: 'deny', message: 'AI agent credential exchange blocked — scope ceiling not verified' },
          ],
          priority: 5,
        },
        {
          name: 'Unattested Workload — Deny External Access',
          description: 'Workloads without cryptographic attestation cannot access external APIs.',
          policy_type: 'access', severity: 'high', effect: 'deny', enforcement_mode: 'enforce',
          template_id: 'unattested-deny-external',
          conditions: [
            { field: 'client.verified', operator: 'is_false' },
            { field: 'server.type', operator: 'in', value: 'external-api,external-credential' },
          ],
          actions: [
            { type: 'deny', message: 'Unattested workload blocked from external API access' },
          ],
          priority: 8,
        },
      ];

      const results = [];
      for (const p of agentPolicies) {
        try {
          // Check if already exists
          const existing = await db(req).query('SELECT id FROM policies WHERE template_id=$1', [p.template_id]);
          if (existing.rows.length > 0) {
            results.push({ name: p.name, status: 'exists', id: existing.rows[0].id });
            continue;
          }

          const compiled = compiler.compile({ name: p.name, description: p.description, conditions: p.conditions, actions: p.actions, severity: p.severity, id: 'new' });
          const pkg = `policy_${p.name.replace(/[^a-z0-9]/gi, '_').toLowerCase()}`;

          const r = await db(req).query(`
            INSERT INTO policies (name, description, policy_type, severity, conditions, actions,
              enabled, enforcement_mode, template_id, rego_policy, opa_package, effect, priority, created_by)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id
          `, [p.name, p.description, p.policy_type, p.severity,
              JSON.stringify(p.conditions), JSON.stringify(p.actions),
              true, p.enforcement_mode, p.template_id, compiled, pkg,
              p.effect, p.priority, 'governance-setup']);
          results.push({ name: p.name, status: 'created', id: r.rows[0].id });
        } catch (e) {
          results.push({ name: p.name, status: 'error', error: e.message });
        }
      }

      res.json({ message: 'Agent governance policies seeded', results });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // Pre-built Governance Scenarios — real requests to test against real policies
  // ══════════════════════════════════════════════
  app.get('/api/v1/governance/scenarios', async (req, res) => {
    try {
      // Get actual workloads from DB for realistic scenarios
      const wR = await db(req).query('SELECT name, type, is_ai_agent, is_mcp_server, category FROM workloads LIMIT 50');
      const workloads = wR.rows;
      const agents = workloads.filter(w => w.is_ai_agent);
      const externals = workloads.filter(w => w.category === 'External APIs' || w.type === 'external-api');
      const credentials = workloads.filter(w => w.category === 'Credentials' || w.type === 'external-credential');
      const services = workloads.filter(w => w.type === 'cloud-run-service');

      const scenarios = [
        {
          id: 'agent-financial', category: 'AI Agent Governance',
          name: 'Agent → Financial API',
          description: 'AI agent attempts to access Stripe payment API to create a charge',
          risk: 'critical',
          source: agents[0]?.name || 'wid-demo-agents',
          destination: externals.find(w => /stripe/i.test(w.name))?.name || 'Stripe',
          method: 'POST', path: '/v1/charges',
          expected_verdict: 'deny',
          why: 'AI agents must not have direct access to financial APIs — requires human approval workflow',
        },
        {
          id: 'agent-pii', category: 'AI Agent Governance',
          name: 'Agent → CRM (PII Data)',
          description: 'AI agent queries Salesforce for customer contact records',
          risk: 'critical',
          source: agents[0]?.name || 'wid-demo-agents',
          destination: externals.find(w => /salesforce/i.test(w.name))?.name || 'Salesforce',
          method: 'GET', path: '/services/data/v62.0/sobjects/Contact',
          expected_verdict: 'deny',
          why: 'PII access requires data classification clearance — agents are not cleared by default',
        },
        {
          id: 'agent-lateral', category: 'AI Agent Governance',
          name: 'Agent → Credential Broker (Lateral Movement)',
          description: 'AI agent attempts to exchange credentials via the broker service',
          risk: 'high',
          source: agents[0]?.name || 'wid-demo-agents',
          destination: 'wid-dev-credential-broker',
          method: 'POST', path: '/api/v1/credentials/exchange',
          expected_verdict: 'deny',
          why: 'Agent-to-service credential exchange requires scope ceiling verification',
        },
        {
          id: 'agent-slack', category: 'MCP Tool Governance',
          name: 'MCP Tool → Slack (Message Post)',
          description: 'MCP server uses static bot token to post a message to Slack',
          risk: 'medium',
          source: agents[0]?.name || 'wid-demo-agents',
          destination: externals.find(w => /slack/i.test(w.name))?.name || 'Slack',
          method: 'POST', path: '/api/chat.postMessage',
          expected_verdict: 'deny',
          why: 'MCP servers using static credentials violate OAuth 2.1 requirements',
        },
        {
          id: 'internal-attested', category: 'Service Mesh',
          name: 'Attested Service → Policy Engine',
          description: 'Internal attested discovery service queries the policy engine',
          risk: 'low',
          source: 'wid-dev-discovery-service',
          destination: 'wid-dev-policy-engine',
          method: 'GET', path: '/api/v1/policies',
          expected_verdict: 'allow',
          why: 'Attested internal services should be able to communicate freely',
        },
        {
          id: 'shared-sa-access', category: 'Identity Hygiene',
          name: 'Shared SA Service → External API',
          description: 'Service using shared service account tries to reach external API',
          risk: 'high',
          source: 'wid-dev-token-service',
          destination: externals.find(w => /stripe/i.test(w.name))?.name || 'Stripe',
          method: 'GET', path: '/v1/balance',
          expected_verdict: 'deny',
          why: 'Services sharing a service account should not access sensitive external resources',
        },
      ];

      res.json({ scenarios, workloads_available: workloads.length, agents: agents.length, external_apis: externals.length });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // ══════════════════════════════════════════════
  // Proxy: Forward discovery-service endpoints
  // The UI hits /api/v1/* which routes to policy-sync.
  // Endpoints that live on discovery need proxying.
  // ══════════════════════════════════════════════
  const DISCOVERY_URL = process.env.DISCOVERY_URL || 'https://wid-dev-discovery-265663183174.us-central1.run.app';

  const proxyToDiscovery = async (req, res, path) => {
    try {
      const url = `${DISCOVERY_URL}${path}`;
      const resp = await fetch(url, { method: req.method, headers: { 'Content-Type': 'application/json' }, ...(req.method !== 'GET' ? { body: JSON.stringify(req.body) } : {}) });
      const data = await resp.json();
      res.status(resp.status).json(data);
    } catch (e) { res.status(502).json({ error: 'Discovery service unavailable', detail: e.message }); }
  };

  // AI enrichment endpoints
  app.get('/api/v1/workloads/:id/ai-enrichment', (req, res) => proxyToDiscovery(req, res, `/api/v1/workloads/${req.params.id}/ai-enrichment`));
  app.get('/api/v1/ai-enrichment/all', (req, res) => proxyToDiscovery(req, res, '/api/v1/ai-enrichment/all'));
  app.post('/api/v1/ai-enrichment/seed', (req, res) => proxyToDiscovery(req, res, '/api/v1/ai-enrichment/seed'));

  // Workload dedup
  app.post('/api/v1/workloads/dedup', (req, res) => proxyToDiscovery(req, res, '/api/v1/workloads/dedup'));

  // Workload audit log
  app.get('/api/v1/workloads/:id/audit-log', (req, res) => proxyToDiscovery(req, res, `/api/v1/workloads/${req.params.id}/audit-log`));

  // Attestation proxy routes
  app.get('/api/v1/attestation/status', (req, res) => proxyToDiscovery(req, res, '/api/v1/attestation/status'));
  app.get('/api/v1/attestation/providers', (req, res) => proxyToDiscovery(req, res, '/api/v1/attestation/providers'));
  app.get('/api/v1/attestation/scheduler/status', (req, res) => proxyToDiscovery(req, res, '/api/v1/attestation/scheduler/status'));
  app.post('/api/v1/attestation/scheduler/start', async (req, res) => {
    const body = JSON.stringify(req.body || {});
    try {
      const url = `${DISCOVERY_URL}/api/v1/attestation/scheduler/start`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });
  app.post('/api/v1/attestation/scheduler/stop', async (req, res) => {
    try {
      const url = `${DISCOVERY_URL}/api/v1/attestation/scheduler/stop`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });
  app.post('/api/v1/workloads/continuous-attest', async (req, res) => {
    const body = JSON.stringify(req.body || {});
    try {
      const url = `${DISCOVERY_URL}/api/v1/workloads/continuous-attest`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });

  // ── Token endpoints (proxy to discovery service) ──
  app.post('/api/v1/tokens/issue', async (req, res) => {
    const body = JSON.stringify(req.body || {});
    try {
      const url = `${DISCOVERY_URL}/api/v1/tokens/issue`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });
  app.post('/api/v1/tokens/introspect', async (req, res) => {
    const body = JSON.stringify(req.body || {});
    try {
      const url = `${DISCOVERY_URL}/api/v1/tokens/introspect`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });
  app.post('/api/v1/tokens/validate', async (req, res) => {
    const body = JSON.stringify(req.body || {});
    try {
      const url = `${DISCOVERY_URL}/api/v1/tokens/validate`;
      const resp = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const data = await resp.text();
      res.status(resp.status).set('Content-Type', resp.headers.get('content-type') || 'application/json').send(data);
    } catch (e) { res.status(502).json({ error: 'Proxy error', detail: e.message }); }
  });

  // =============================================================================
  // Compliance Framework Endpoints
  // =============================================================================

  const { COMPLIANCE_FRAMEWORKS } = require('./engine/compliance-frameworks');

  // GET /api/v1/compliance/frameworks — list all frameworks with coverage stats
  app.get('/api/v1/compliance/frameworks', async (req, res) => {
    try {
      // Ensure compliance_frameworks column exists
      try { await db(req).query('ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS compliance_frameworks JSONB DEFAULT \'[]\''); } catch (e) { /* ignore */ }

      const frameworks = [];
      for (const [fwId, fw] of Object.entries(COMPLIANCE_FRAMEWORKS)) {
        const totalControls = Object.keys(fw.controls).length;

        // Count templates mapped to this framework
        const tplResult = await db(req).query(
          `SELECT COUNT(*) as cnt FROM policy_templates
           WHERE compliance_frameworks @> $1::jsonb`,
          [JSON.stringify([{ framework: fwId }])]
        );
        const mappedTemplates = parseInt(tplResult.rows[0].cnt) || 0;

        // Count deployed policies from these templates
        const deployedResult = await db(req).query(
          `SELECT COUNT(DISTINCT p.id) as cnt FROM policies p
           JOIN policy_templates pt ON p.template_id = pt.id
           WHERE pt.compliance_frameworks @> $1::jsonb
             AND p.enabled = true`,
          [JSON.stringify([{ framework: fwId }])]
        );
        const deployedPolicies = parseInt(deployedResult.rows[0].cnt) || 0;

        const coveragePct = mappedTemplates > 0 ? Math.round((deployedPolicies / mappedTemplates) * 100) : 0;

        frameworks.push({
          id: fwId,
          name: fw.name,
          description: fw.description,
          icon: fw.icon,
          total_controls: totalControls,
          mapped_templates: mappedTemplates,
          deployed_policies: deployedPolicies,
          coverage_pct: Math.min(coveragePct, 100),
        });
      }
      res.json({ frameworks });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/compliance/frameworks/:id — framework detail with all mapped templates
  app.get('/api/v1/compliance/frameworks/:id', async (req, res) => {
    try {
      const fwId = req.params.id;
      const fw = COMPLIANCE_FRAMEWORKS[fwId];
      if (!fw) return res.status(404).json({ error: `Framework ${fwId} not found` });

      // Get all templates mapped to this framework
      const tplResult = await db(req).query(
        `SELECT pt.*,
          EXISTS(SELECT 1 FROM policies p WHERE p.template_id = pt.id AND p.enabled = true) as deployed,
          (SELECT p.enforcement_mode FROM policies p WHERE p.template_id = pt.id AND p.enabled = true LIMIT 1) as active_enforcement_mode
         FROM policy_templates pt
         WHERE pt.compliance_frameworks @> $1::jsonb
         ORDER BY pt.severity DESC, pt.name`,
        [JSON.stringify([{ framework: fwId }])]
      );

      const templates = tplResult.rows.map(t => {
        const cfEntry = (typeof t.compliance_frameworks === 'string'
          ? JSON.parse(t.compliance_frameworks)
          : (t.compliance_frameworks || [])
        ).find(cf => cf.framework === fwId);
        return {
          id: t.id,
          name: t.name,
          description: t.description,
          policy_type: t.policy_type,
          severity: t.severity,
          deployed: t.deployed,
          enforcement_mode: t.active_enforcement_mode || null,
          controls: cfEntry?.controls || [],
        };
      });

      res.json({
        framework: { id: fwId, name: fw.name, description: fw.description, icon: fw.icon, controls: fw.controls },
        templates,
        total: templates.length,
        deployed: templates.filter(t => t.deployed).length,
        coverage_pct: templates.length > 0 ? Math.round((templates.filter(t => t.deployed).length / templates.length) * 100) : 0,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/v1/compliance/frameworks/:id/deploy — deploy all undeployed templates for a framework
  app.post('/api/v1/compliance/frameworks/:id/deploy', async (req, res) => {
    try {
      const fwId = req.params.id;
      const fw = COMPLIANCE_FRAMEWORKS[fwId];
      if (!fw) return res.status(404).json({ error: `Framework ${fwId} not found` });

      // Get undeployed templates for this framework
      const tplResult = await db(req).query(
        `SELECT pt.* FROM policy_templates pt
         WHERE pt.compliance_frameworks @> $1::jsonb
           AND NOT EXISTS(SELECT 1 FROM policies p WHERE p.template_id = pt.id AND p.enabled = true)
         ORDER BY pt.name`,
        [JSON.stringify([{ framework: fwId }])]
      );

      let deployed = 0, skipped = 0;
      const errors = [];

      for (const tpl of tplResult.rows) {
        try {
          const conditions = typeof tpl.conditions === 'string' ? JSON.parse(tpl.conditions) : (tpl.conditions || []);
          const actions = typeof tpl.actions === 'string' ? JSON.parse(tpl.actions) : (tpl.actions || []);

          await db(req).query(
            `INSERT INTO policies (name, description, policy_type, severity, conditions, actions,
             enforcement_mode, enabled, template_id, template_version, scope_environment, effect, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
            [
              tpl.name, tpl.description, tpl.policy_type, tpl.severity,
              JSON.stringify(conditions), JSON.stringify(actions),
              'audit', true, tpl.id, tpl.version,
              tpl.scope_environment || null, tpl.effect || null, 'compliance-deploy'
            ]
          );
          deployed++;
        } catch (e) {
          errors.push(`${tpl.id}: ${e.message}`);
        }
      }

      skipped = (await db(req).query(
        `SELECT COUNT(*) as cnt FROM policy_templates pt
         WHERE pt.compliance_frameworks @> $1::jsonb
           AND EXISTS(SELECT 1 FROM policies p WHERE p.template_id = pt.id AND p.enabled = true)`,
        [JSON.stringify([{ framework: fwId }])]
      )).rows[0].cnt;

      res.json({ deployed, skipped: parseInt(skipped), errors, framework: fwId });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  // GET /api/v1/compliance/frameworks/:id/coverage — coverage breakdown by control
  app.get('/api/v1/compliance/frameworks/:id/coverage', async (req, res) => {
    try {
      const fwId = req.params.id;
      const fw = COMPLIANCE_FRAMEWORKS[fwId];
      if (!fw) return res.status(404).json({ error: `Framework ${fwId} not found` });

      // Get all templates with their deploy status
      const tplResult = await db(req).query(
        `SELECT pt.id, pt.name, pt.compliance_frameworks,
          EXISTS(SELECT 1 FROM policies p WHERE p.template_id = pt.id AND p.enabled = true) as deployed
         FROM policy_templates pt
         WHERE pt.compliance_frameworks @> $1::jsonb`,
        [JSON.stringify([{ framework: fwId }])]
      );

      const byControl = {};
      for (const controlId of Object.keys(fw.controls)) {
        byControl[controlId] = { name: fw.controls[controlId], total: 0, deployed: 0, templates: [] };
      }

      for (const tpl of tplResult.rows) {
        const cfArray = typeof tpl.compliance_frameworks === 'string'
          ? JSON.parse(tpl.compliance_frameworks)
          : (tpl.compliance_frameworks || []);
        const cfEntry = cfArray.find(cf => cf.framework === fwId);
        if (!cfEntry) continue;
        for (const ctrl of (cfEntry.controls || [])) {
          if (byControl[ctrl]) {
            byControl[ctrl].total++;
            if (tpl.deployed) byControl[ctrl].deployed++;
            byControl[ctrl].templates.push({ id: tpl.id, name: tpl.name, deployed: tpl.deployed });
          }
        }
      }

      const total = tplResult.rows.length;
      const deployedCount = tplResult.rows.filter(t => t.deployed).length;

      res.json({
        framework: fwId,
        total,
        deployed: deployedCount,
        coverage_pct: total > 0 ? Math.round((deployedCount / total) * 100) : 0,
        by_control: byControl,
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

}

module.exports = { mountPolicyRoutes };

// =============================================================================
// Admin: DB Migration for policy_templates (run once, then remove)
// =============================================================================
function mountAdminRoutes(app, pool) {
  const { POLICY_TEMPLATES, FINDING_REMEDIATION_MAP } = require('./engine/templates');

  app.post('/admin/migrate-templates', async (req, res) => {
    try {
      const results = { steps: [], errors: [] };

      // 1. Create policy_templates table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS policy_templates (
          id VARCHAR(100) PRIMARY KEY,
          name VARCHAR(255) NOT NULL,
          description TEXT DEFAULT '',
          policy_type VARCHAR(30) NOT NULL,
          severity VARCHAR(20) NOT NULL DEFAULT 'medium',
          conditions JSONB NOT NULL DEFAULT '[]',
          actions JSONB NOT NULL DEFAULT '[]',
          scope_environment VARCHAR(50) DEFAULT NULL,
          scope_types TEXT[] DEFAULT NULL,
          effect VARCHAR(20) DEFAULT NULL,
          tags TEXT[] DEFAULT '{}',
          enabled BOOLEAN DEFAULT true,
          version INTEGER DEFAULT 1,
          created_by VARCHAR(255) DEFAULT 'system',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        )
      `);
      await pool.query('CREATE INDEX IF NOT EXISTS idx_policy_templates_type ON policy_templates(policy_type)');
      await pool.query('CREATE INDEX IF NOT EXISTS idx_policy_templates_severity ON policy_templates(severity)');
      await pool.query('CREATE INDEX IF NOT EXISTS idx_policy_templates_enabled ON policy_templates(enabled)');
      results.steps.push('policy_templates table created');

      // 2. Create finding_remediation_map table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS finding_remediation_map (
          id SERIAL PRIMARY KEY,
          finding_type VARCHAR(100) NOT NULL,
          template_id VARCHAR(100) NOT NULL REFERENCES policy_templates(id) ON DELETE CASCADE,
          priority INTEGER DEFAULT 1,
          reason TEXT DEFAULT '',
          UNIQUE(finding_type, template_id)
        )
      `);
      await pool.query('CREATE INDEX IF NOT EXISTS idx_frm_finding ON finding_remediation_map(finding_type)');
      await pool.query('CREATE INDEX IF NOT EXISTS idx_frm_template ON finding_remediation_map(template_id)');
      results.steps.push('finding_remediation_map table created');

      // 3. Add template_version to policies
      try {
        await pool.query('ALTER TABLE policies ADD COLUMN IF NOT EXISTS template_version INTEGER DEFAULT NULL');
        results.steps.push('policies.template_version column added');
      } catch (e) { results.errors.push('template_version: ' + e.message); }

      // 4. Create auto-version trigger
      await pool.query(`
        CREATE OR REPLACE FUNCTION update_policy_template_updated_at()
        RETURNS TRIGGER AS $t$
        BEGIN
          NEW.updated_at = NOW();
          NEW.version = OLD.version + 1;
          RETURN NEW;
        END;
        $t$ LANGUAGE plpgsql
      `);
      await pool.query('DROP TRIGGER IF EXISTS trigger_policy_template_updated_at ON policy_templates');
      await pool.query(`
        CREATE TRIGGER trigger_policy_template_updated_at
        BEFORE UPDATE ON policy_templates
        FOR EACH ROW EXECUTE FUNCTION update_policy_template_updated_at()
      `);
      results.steps.push('Auto-version trigger created');

      // 5. Seed templates
      let seeded = 0;
      // Ensure tags + compliance_frameworks columns exist
      try { await pool.query('ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT \'{}\''); } catch (e) { /* ignore */ }
      try { await pool.query('ALTER TABLE policy_templates ADD COLUMN IF NOT EXISTS compliance_frameworks JSONB DEFAULT \'[]\''); } catch (e) { /* ignore */ }
      try { await pool.query('CREATE INDEX IF NOT EXISTS idx_policy_templates_compliance ON policy_templates USING GIN (compliance_frameworks)'); } catch (e) { /* ignore */ }
      for (const [id, tpl] of Object.entries(POLICY_TEMPLATES)) {
        try {
          await pool.query(`
            INSERT INTO policy_templates (id, name, description, policy_type, severity, conditions, actions, scope_environment, effect, tags, compliance_frameworks)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
            ON CONFLICT (id) DO UPDATE SET
              name = EXCLUDED.name, description = EXCLUDED.description,
              policy_type = EXCLUDED.policy_type, severity = EXCLUDED.severity,
              conditions = EXCLUDED.conditions, actions = EXCLUDED.actions,
              scope_environment = EXCLUDED.scope_environment, effect = EXCLUDED.effect,
              tags = EXCLUDED.tags,
              compliance_frameworks = EXCLUDED.compliance_frameworks
          `, [id, tpl.name, tpl.description, tpl.policy_type, tpl.severity,
              JSON.stringify(tpl.conditions), JSON.stringify(tpl.actions),
              tpl.scope_environment || null, tpl.effect || null, tpl.tags || [],
              JSON.stringify(tpl.compliance_frameworks || [])]);
          seeded++;
        } catch (e) { results.errors.push(`template ${id}: ${e.message}`); }
      }
      results.steps.push(`${seeded} templates seeded`);

      // 6. Seed remediation map
      let mapped = 0;
      for (const [findingType, templates] of Object.entries(FINDING_REMEDIATION_MAP)) {
        for (let i = 0; i < templates.length; i++) {
          try {
            await pool.query(`
              INSERT INTO finding_remediation_map (finding_type, template_id, priority, reason)
              VALUES ($1,$2,$3,$4)
              ON CONFLICT (finding_type, template_id) DO UPDATE SET priority = EXCLUDED.priority, reason = EXCLUDED.reason
            `, [findingType, templates[i].template_id, i + 1, templates[i].name]);
            mapped++;
          } catch (e) { results.errors.push(`map ${findingType}→${templates[i].template_id}: ${e.message}`); }
        }
      }
      results.steps.push(`${mapped} remediation mappings seeded`);

      // 7. Verify
      const tplCount = (await pool.query('SELECT COUNT(*) FROM policy_templates')).rows[0].count;
      const frmCount = (await pool.query('SELECT COUNT(*) FROM finding_remediation_map')).rows[0].count;
      const ftCount = (await pool.query('SELECT COUNT(DISTINCT finding_type) FROM finding_remediation_map')).rows[0].count;

      res.json({
        success: results.errors.length === 0,
        templates: parseInt(tplCount),
        remediation_entries: parseInt(frmCount),
        finding_types: parseInt(ftCount),
        steps: results.steps,
        errors: results.errors,
      });
    } catch (e) {
      res.status(500).json({ error: e.message, stack: e.stack });
    }
  });
}

module.exports.mountAdminRoutes = mountAdminRoutes;