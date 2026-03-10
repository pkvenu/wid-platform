// =============================================================================
// IETF AIMS Mapper — Derive IETF draft-klrc-aiagent-auth identity fields
// =============================================================================
// Maps WID's existing workload identity model to the 8-layer Agent Identity
// Management System (AIMS) defined in the IETF draft. Computes fields like
// delegation_type, attestation_type, scope_drift_score, and transaction token
// metrics from existing WID data (token_chain, ext_authz_decisions,
// attestation_data, wid_tokens).
//
// Results are attached to graph nodes as meta.ietf_aims and persisted to the
// workloads table (delegation_type column).
// =============================================================================

class IETFAimsMapper {
  constructor(dbClient) {
    this.dbClient = dbClient;
  }

  // ── Main entry point — enrich all nodes ────────────────────────────────────

  async enrichNodes(nodes) {
    if (!this.dbClient || !nodes?.length) return;

    // Batch-load supporting data
    const tokenChainData = await this._loadTokenChains();
    const decisionStats = await this._loadDecisionStats();
    const widTokens = await this._loadWidTokens();

    let enriched = 0;
    for (const node of nodes) {
      if (!node.wid && !node.spiffeId && !node.id?.startsWith('w:')) continue;

      const workloadName = node.label || node.wid || node.id?.replace('w:', '');
      const spiffeId = node.spiffeId || node.meta?.spiffe_id;

      const aims = {
        // Layer 1: Agent Identifier
        agent_identifier: spiffeId || null,
        agent_identifier_type: spiffeId?.startsWith('spiffe://') ? 'spiffe' : 'opaque',

        // Layer 3: Attestation
        attestation_type: this._deriveAttestationType(node),

        // Layer 6: Authorization / Delegation
        delegation_type: this._deriveDelegationType(workloadName, tokenChainData),
        delegation_depth: this._deriveDelegationDepth(workloadName, tokenChainData),

        // Layer 4: Credential Provisioning
        credential_provisioning: this._deriveCredentialProvisioning(workloadName, widTokens, node),

        // Layer 7: Observability
        scope_drift_score: this._deriveScopeDrift(workloadName, decisionStats, node),
        observable_risk_indicators: this._deriveRiskIndicators(workloadName, tokenChainData, decisionStats, node),

        // Layer 2: Scope Ceiling
        scope_ceiling: node.meta?.scope_ceiling || node.ai_enrichment?.scope_ceiling || null,
      };

      node.meta = node.meta || {};
      node.meta.ietf_aims = aims;

      // Persist delegation_type + ietf_aims to workloads table
      if (node.wid) {
        this._persistIETFData(node.wid, aims).catch(() => {});
      }

      enriched++;
    }

    if (enriched > 0) {
      console.log(`[IETFMapper] Enriched ${enriched} nodes with IETF AIMS fields`);
    }
  }

  // ── Layer 3: Attestation Type ──────────────────────────────────────────────

  _deriveAttestationType(node) {
    const attestation = node.meta?.attestation_data || node.attestationData;
    if (!attestation) return 'none';

    const method = attestation.primary_method || attestation.method || '';
    if (/tpm|tee|sgx|sev|trustzone/i.test(method)) return 'tee';
    if (/spire|svid|spiffe/i.test(method)) return 'platform';
    if (/oidc|jwt|federation/i.test(method)) return 'software';
    if (attestation.verified) return 'software';
    return 'none';
  }

  // ── Layer 6: Delegation Type ───────────────────────────────────────────────

  _deriveDelegationType(workloadName, tokenChainData) {
    const chains = tokenChainData.get(workloadName) || [];

    // Check for on-behalf-of (OBO) tokens — indicates user delegation
    const hasOBO = chains.some(c => c.actor && c.actor !== c.subject);
    if (hasOBO) return 'user_delegation';

    // Check for cross-domain trust
    const hasCrossDomain = chains.some(c => {
      if (!c.subject || !c.audience) return false;
      const subDomain = this._extractDomain(c.subject);
      const audDomain = this._extractDomain(c.audience);
      return subDomain && audDomain && subDomain !== audDomain;
    });
    if (hasCrossDomain) return 'cross_domain';

    // Default: self-authorization (client credentials)
    if (chains.length > 0) return 'self_auth';

    return null; // Unknown — no token chain data
  }

  _extractDomain(spiffeId) {
    if (!spiffeId) return null;
    const match = spiffeId.match(/spiffe:\/\/([^/]+)/);
    return match ? match[1] : null;
  }

  // ── Delegation Depth ───────────────────────────────────────────────────────

  _deriveDelegationDepth(workloadName, tokenChainData) {
    const chains = tokenChainData.get(workloadName) || [];
    if (!chains.length) return 0;
    return Math.max(...chains.map(c => c.chain_depth || 1));
  }

  // ── Layer 4: Credential Provisioning ───────────────────────────────────────

  _deriveCredentialProvisioning(workloadName, widTokens, node) {
    const tokens = widTokens.get(workloadName) || [];
    const hasJIT = tokens.length > 0;
    const hasStaticCreds = (node.ai_enrichment?.credential_count || 0) > 0;

    if (hasJIT) {
      // Calculate average TTL from token data
      const avgTTL = tokens.length > 0
        ? tokens.reduce((sum, t) => sum + (t.ttl_seconds || 900), 0) / tokens.length
        : 900;

      return {
        method: 'jit',
        rotation_interval_s: Math.round(avgTTL),
        active_tokens: tokens.filter(t => t.status === 'active').length,
        total_issued: tokens.length,
      };
    }

    if (hasStaticCreds) {
      return {
        method: 'static',
        rotation_interval_s: null,
        active_tokens: 0,
        total_issued: 0,
      };
    }

    return { method: 'unknown', rotation_interval_s: null };
  }

  // ── Layer 7: Scope Drift Score ─────────────────────────────────────────────

  _deriveScopeDrift(workloadName, decisionStats, node) {
    const stats = decisionStats.get(workloadName);
    if (!stats || !stats.destination_names?.length) return 0;

    // Build set of declared providers from AI enrichment metadata
    const declaredProviders = new Set();
    const enrichment = node.ai_enrichment || node.meta;
    if (enrichment?.llm_providers) {
      for (const p of enrichment.llm_providers) {
        declaredProviders.add((p.id || p.label || '').toLowerCase());
      }
    }
    // No declared providers means we can't measure drift
    if (declaredProviders.size === 0) return 0;

    // Count destinations that don't match any declared provider
    let undeclaredCount = 0;
    for (const dest of stats.destination_names) {
      const d = (dest || '').toLowerCase();
      const isDeclared = [...declaredProviders].some(p => d.includes(p) || p.includes(d));
      if (!isDeclared) undeclaredCount++;
    }

    if (stats.unique_destinations === 0) return 0;
    return Math.min(1.0, undeclaredCount / stats.unique_destinations);
  }

  // ── Observable Risk Indicators ─────────────────────────────────────────────

  _deriveRiskIndicators(workloadName, tokenChainData, decisionStats, node) {
    const indicators = [];

    // From existing risk flags
    const riskFlags = node.ai_enrichment?.risk_flags || node.meta?.risk_flags || [];
    indicators.push(...riskFlags);

    // Scope drift
    const driftScore = this._deriveScopeDrift(workloadName, decisionStats, node);
    if (driftScore > 0.3) indicators.push('scope-drift');

    // Delegation depth
    const depth = this._deriveDelegationDepth(workloadName, tokenChainData);
    if (depth >= 3) indicators.push('delegation-depth-3+');

    // Static credentials
    if ((node.ai_enrichment?.credential_count || 0) > 0) {
      indicators.push('static-credentials-present');
    }

    return [...new Set(indicators)]; // Deduplicate
  }

  // ── Batch data loading ─────────────────────────────────────────────────────

  async _loadTokenChains() {
    const map = new Map();
    try {
      const { rows } = await this.dbClient.query(`
        SELECT subject, actor, audience, chain_depth, status
        FROM token_chain
        ORDER BY created_at DESC
        LIMIT 1000
      `);
      for (const row of rows) {
        const key = this._workloadNameFromSpiffe(row.subject);
        if (!map.has(key)) map.set(key, []);
        map.get(key).push(row);
      }
    } catch {
      // token_chain table may not exist
    }
    return map;
  }

  async _loadDecisionStats() {
    const map = new Map();
    try {
      const { rows } = await this.dbClient.query(`
        SELECT source_name,
               COUNT(*) as total_calls,
               COUNT(DISTINCT destination_name) as unique_destinations,
               ARRAY_AGG(DISTINCT destination_name) FILTER (WHERE destination_name IS NOT NULL) as destination_names
        FROM ext_authz_decisions
        WHERE created_at > NOW() - INTERVAL '30 days'
        GROUP BY source_name
      `);
      for (const row of rows) {
        map.set(row.source_name, {
          total_calls: parseInt(row.total_calls),
          unique_destinations: parseInt(row.unique_destinations),
          destination_names: row.destination_names || [],
        });
      }
    } catch {
      // ext_authz_decisions table may not exist
    }
    return map;
  }

  async _loadWidTokens() {
    const map = new Map();
    try {
      const { rows } = await this.dbClient.query(`
        SELECT workload_name, status, ttl_seconds
        FROM wid_tokens
        WHERE created_at > NOW() - INTERVAL '7 days'
        ORDER BY created_at DESC
        LIMIT 500
      `);
      for (const row of rows) {
        if (!map.has(row.workload_name)) map.set(row.workload_name, []);
        map.get(row.workload_name).push(row);
      }
    } catch {
      // wid_tokens table may not exist
    }
    return map;
  }

  _workloadNameFromSpiffe(spiffeId) {
    if (!spiffeId) return '';
    // spiffe://domain/workload/billing-agent → billing-agent
    const parts = spiffeId.split('/');
    return parts[parts.length - 1] || '';
  }

  // ── Persist IETF data to workloads table ──────────────────────────────────

  async _persistIETFData(workloadId, aims) {
    try {
      await this.dbClient.query(`
        UPDATE workloads
        SET delegation_type = COALESCE($1, delegation_type),
            metadata = jsonb_set(COALESCE(metadata::jsonb, '{}'::jsonb), '{ietf_aims}', $2::jsonb)
        WHERE id = $3
      `, [aims.delegation_type || null, JSON.stringify(aims), workloadId]);
    } catch {
      // Non-critical — skip silently
    }
  }
}

module.exports = { IETFAimsMapper };
