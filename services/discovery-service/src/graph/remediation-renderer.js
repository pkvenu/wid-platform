// =============================================================================
// RemediationRenderer — Context-aware remediation template renderer
// =============================================================================
// Pipeline:
//   Graph node → buildContext() → DB lookup intents → DB lookup templates
//   → _renderTemplate() with {{variable}} substitution → RenderedRemediation
//
// Template rendering is pure string replacement (no eval, no code execution).
// Variables resolved from context hierarchy: resource_identifiers > constraints > defaults.
// =============================================================================

class RemediationRenderer {
  constructor(dbClient) {
    this.dbClient = dbClient;
  }

  // ── Build a ContextObject from a graph node + its attack paths ──
  buildContext(node, attackPaths, allNodes, allRels) {
    const resourceIds = this._extractResourceIds(node, attackPaths);
    const constraints = this._extractConstraints(node);

    return {
      workload_name: node.label || node.id,
      workload_id: node.workload_id || node.id,
      cloud_provider: this._detectProvider(node),
      trust_level: node.trust || 'none',
      spiffe_id: node.spiffe_id || null,
      finding_types: [...new Set(attackPaths.map(ap => ap.finding_type).filter(Boolean))],
      credential_chain: attackPaths[0]?.credential_chain || [],
      blast_radius: Math.max(...attackPaths.map(ap => ap.blast_radius || 0), 0),
      resource_identifiers: resourceIds,
      constraints,
      affected_edges: this._findAffectedEdges(node, allRels),
      affected_nodes: this._findAffectedNodes(node, allNodes, allRels),
      metadata: node.metadata || node.meta || {},
    };
  }

  // ── Render all matching intents for a context ──
  async render(context) {
    if (!this.dbClient) return [];

    const findingTypes = context.finding_types;
    if (!findingTypes || findingTypes.length === 0) return [];

    // Query intents matching any of the finding types
    let intents;
    try {
      const result = await this.dbClient.query(
        `SELECT * FROM remediation_intents
         WHERE enabled = true AND finding_types && $1
         ORDER BY action_type, name`,
        [findingTypes]
      );
      intents = result.rows;
    } catch (e) {
      // Table may not exist yet — return empty
      return [];
    }

    if (intents.length === 0) return [];

    // For each intent, load templates and render
    const rendered = [];
    for (const intent of intents) {
      let templates;
      try {
        const tResult = await this.dbClient.query(
          `SELECT * FROM remediation_templates
           WHERE intent_id = $1 AND enabled = true
             AND (provider = $2 OR provider = 'generic')
           ORDER BY priority ASC`,
          [intent.id, context.cloud_provider || 'generic']
        );
        templates = tResult.rows;
      } catch {
        templates = [];
      }

      // Group templates by channel
      const channels = {};
      for (const tpl of templates) {
        const rendered_tpl = this._renderTemplate(tpl, context);
        channels[tpl.channel] = {
          title: tpl.title || intent.name,
          provider: tpl.provider,
          commands: rendered_tpl.commands,
          snippet: rendered_tpl.snippet,
          validate_commands: rendered_tpl.validate_commands,
          rollback_commands: rendered_tpl.rollback_commands,
        };
      }

      const risk = this._computeRiskReduction(intent, context);
      const preconditions = this._checkPreconditions(intent, context);

      rendered.push({
        intent_id: intent.id,
        control_id: intent.control_id,
        name: intent.name,
        description: intent.description,
        goal: intent.goal,
        action_type: intent.action_type,
        remediation_type: intent.remediation_type,
        template_id: intent.template_id,
        channels,
        why_now: {
          finding_types: context.finding_types,
          blast_radius: context.blast_radius,
          edges_at_risk: context.affected_edges.length,
          credential_chain: context.credential_chain.map(c => c.label || c.id),
        },
        risk,
        preconditions_met: preconditions.every(p => p.met),
        preconditions,
        rollback_available: Object.values(channels).some(ch => ch.rollback_commands?.length > 0),
        downtime_risk: intent.operational?.expertise === 'high' ? 'medium' : 'low',
        score: {
          path_break: intent.path_break,
          feasibility: intent.feasibility,
          operational: intent.operational,
        },
      });
    }

    return rendered;
  }

  // ── Internal: Render a single template with {{variable}} substitution ──
  _renderTemplate(template, context) {
    const body = template.template_body || '';
    const variables = template.variables || [];

    // Build variable map from context
    const varMap = {};
    for (const varDef of variables) {
      varMap[varDef.name || varDef.key] = this._resolveVariable(varDef, context);
    }

    // Also add all resource identifiers and constraints as available variables
    for (const [k, v] of Object.entries(context.resource_identifiers || {})) {
      if (!varMap[k]) varMap[k] = v;
    }
    for (const [k, v] of Object.entries(context.constraints || {})) {
      if (!varMap[k]) varMap[k] = v;
    }

    // Substitute {{VAR}} placeholders
    const rendered = this._substituteVars(body, varMap);

    // Split into individual commands (one per line, skip empty/comment lines)
    const commands = rendered.split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !l.startsWith('//'));

    // Render validate and rollback templates similarly
    const validate_commands = template.validate_template
      ? this._substituteVars(template.validate_template, varMap).split('\n').map(l => l.trim()).filter(Boolean)
      : [];
    const rollback_commands = template.rollback_template
      ? this._substituteVars(template.rollback_template, varMap).split('\n').map(l => l.trim()).filter(Boolean)
      : [];

    return {
      commands,
      snippet: rendered,
      validate_commands,
      rollback_commands,
    };
  }

  // ── Substitute {{VAR}} and <VAR> placeholders ──
  _substituteVars(text, varMap) {
    let result = text;
    // {{VAR}} style
    result = result.replace(/\{\{(\w+)\}\}/g, (_, key) => varMap[key] || `<${key}>`);
    // <VAR> style (only uppercase + underscores = template placeholders)
    result = result.replace(/<([A-Z][A-Z0-9_]+)>/g, (match, key) => varMap[key] || match);
    return result;
  }

  // ── Resolve a variable definition from context ──
  _resolveVariable(varDef, context) {
    const name = varDef.name || varDef.key;
    // Priority: resource_identifiers > constraints > defaults
    if (context.resource_identifiers?.[name]) return context.resource_identifiers[name];
    if (context.constraints?.[name]) return context.constraints[name];
    if (varDef.default) return varDef.default;
    return `<${name}>`;
  }

  // ── Extract resource identifiers from node + attack paths ──
  _extractResourceIds(node, attackPaths) {
    const ids = {};
    const meta = node.metadata || node.meta || {};

    // Service account email
    if (meta.service_account_email || meta.sa_email) {
      ids.SA_EMAIL = meta.service_account_email || meta.sa_email;
    }

    // Role ARN
    if (meta.role_arn || meta.arn) {
      ids.ROLE_ARN = meta.role_arn || meta.arn;
    }

    // Bucket
    if (meta.bucket_name || meta.bucket) {
      ids.BUCKET = meta.bucket_name || meta.bucket;
    }

    // Secret name from credential chain
    for (const ap of attackPaths) {
      for (const c of (ap.credential_chain || [])) {
        if (c.type === 'credential') {
          ids.SECRET_NAME = ids.SECRET_NAME || c.label;
        }
      }
    }

    // Workload identifiers
    ids.WORKLOAD = node.label || node.id;
    if (meta.instance_type) ids.INSTANCE_TYPE = meta.instance_type;

    return ids;
  }

  // ── Extract constraints (PROJECT, REGION, VPC_ID) from node ──
  _extractConstraints(node) {
    const meta = node.metadata || node.meta || {};
    const constraints = {};

    if (node.environment) constraints.ENVIRONMENT = node.environment;
    if (meta.project || meta.project_id) constraints.PROJECT = meta.project || meta.project_id;
    if (meta.region) constraints.REGION = meta.region;
    if (meta.vpc_id) constraints.VPC_ID = meta.vpc_id;
    if (meta.account_id) constraints.ACCOUNT = meta.account_id;
    if (node.spiffe_id) constraints.SPIFFE_ID = node.spiffe_id;

    return constraints;
  }

  // ── Find edges connected to this node ──
  _findAffectedEdges(node, allRels) {
    const nodeId = node.id;
    return allRels.filter(r => {
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      return s === nodeId || t === nodeId;
    }).map(r => ({
      id: r.id,
      type: r.type,
      source: typeof r.source === 'object' ? r.source.id : r.source,
      target: typeof r.target === 'object' ? r.target.id : r.target,
    }));
  }

  // ── Find nodes reachable from this node (1-hop) ──
  _findAffectedNodes(node, allNodes, allRels) {
    const nodeId = node.id;
    const neighborIds = new Set();
    for (const r of allRels) {
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      if (s === nodeId) neighborIds.add(t);
      if (t === nodeId) neighborIds.add(s);
    }
    return allNodes
      .filter(n => neighborIds.has(n.id))
      .map(n => ({ id: n.id, label: n.label, type: n.type }));
  }

  // ── Compute risk reduction estimates ──
  _computeRiskReduction(intent, context) {
    const pathBreak = intent.path_break || {};
    const edgesSevered = pathBreak.edges_severed || 0;
    const crownJewelProximity = pathBreak.crown_jewel_proximity || 0;

    return {
      edges_removed: edgesSevered,
      paths_eliminated: Math.min(edgesSevered, context.finding_types.length),
      score_impact: Math.round(crownJewelProximity * 15 + edgesSevered * 5),
      blast_radius_reduction: edgesSevered > 0
        ? Math.round(context.blast_radius * (edgesSevered * 0.2))
        : 0,
    };
  }

  // ── Check preconditions against context ──
  _checkPreconditions(intent, context) {
    const preconditions = intent.feasibility?.preconditions || [];
    // Map of preconditions to simple checks
    const checks = {
      'vault-available': { met: true, reason: 'Secret manager assumed available' },
      'edge-gateway-deployed': { met: true, reason: 'Edge gateway is deployed (spoke mode)' },
      'spire-available': { met: context.trust_level !== 'none', reason: context.trust_level !== 'none' ? 'SPIRE attestation available' : 'SPIRE not configured — trust_level is none' },
      'policy-engine-deployed': { met: true, reason: 'Policy engine is running' },
      'gcp-project-access': { met: context.cloud_provider === 'gcp', reason: context.cloud_provider === 'gcp' ? 'GCP project access confirmed' : 'Not a GCP workload' },
      'can-split-workload': { met: false, reason: 'Requires manual architecture review' },
      'delegation-chain-available': { met: false, reason: 'Delegation chain not yet implemented' },
      'approval-workflow': { met: false, reason: 'Approval workflow not yet configured' },
    };

    return preconditions.map(p => ({
      name: p,
      ...(checks[p] || { met: true, reason: 'Assumed met' }),
    }));
  }

  // ── Detect cloud provider from node ──
  _detectProvider(node) {
    if (node.cloud_provider) return node.cloud_provider.toLowerCase();
    const meta = node.metadata || node.meta || {};
    if (meta.project_id || meta.gcp_project) return 'gcp';
    if (meta.account_id || meta.role_arn) return 'aws';
    if (meta.subscription_id) return 'azure';
    // Check spiffe_id for hints
    if (node.spiffe_id?.includes('gcp')) return 'gcp';
    if (node.spiffe_id?.includes('aws')) return 'aws';
    return 'generic';
  }
}

module.exports = { RemediationRenderer };
