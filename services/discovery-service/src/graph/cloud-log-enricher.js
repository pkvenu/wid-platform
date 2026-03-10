// =============================================================================
// Cloud Log Enricher — Batch-query cloud audit logs for AI API usage
// =============================================================================
// Post-discovery enrichment step that queries GCP Cloud Logging and AWS
// CloudTrail for AI-related API calls. Results are persisted to the
// cloud_log_enrichments table and merged onto graph nodes.
//
// Design: Batch queries on timer (every 5 min). Not a scanner — doesn't
// produce workloads. Annotates already-discovered workloads with observed
// API usage from cloud audit trails.
// =============================================================================

class CloudLogEnricher {
  constructor(dbClient, providerRegistry, config = {}) {
    this.dbClient = dbClient;
    this.registry = providerRegistry;
    this.windowMinutes = config.windowMinutes || 30;
    this.gcpProjectId = config.gcpProjectId || process.env.GCP_PROJECT_ID;
    this.awsRegion = config.awsRegion || process.env.AWS_REGION || 'us-east-1';
    this.maxResults = config.maxResults || 500;
  }

  // ── Main entry point ───────────────────────────────────────────────────────

  async enrichAll(workloads) {
    const results = { gcp: [], aws: [], errors: [] };

    // GCP Cloud Logging
    if (this.gcpProjectId) {
      try {
        const gcpEntries = await this.queryGCPAuditLogs();
        const matched = this.matchToWorkloads(gcpEntries, workloads, 'gcp');
        await this.persistEnrichments(matched);
        results.gcp = matched;
      } catch (err) {
        results.errors.push({ provider: 'gcp', error: err.message });
        console.warn('[CloudLogEnricher] GCP query failed:', err.message);
      }
    }

    // AWS CloudTrail
    if (process.env.AWS_ACCESS_KEY_ID || process.env.AWS_ROLE_ARN) {
      try {
        const awsEntries = await this.queryCloudTrailEvents();
        const matched = this.matchToWorkloads(awsEntries, workloads, 'aws');
        await this.persistEnrichments(matched);
        results.aws = matched;
      } catch (err) {
        results.errors.push({ provider: 'aws', error: err.message });
        console.warn('[CloudLogEnricher] AWS query failed:', err.message);
      }
    }

    return results;
  }

  // ── GCP Cloud Logging ──────────────────────────────────────────────────────

  async queryGCPAuditLogs() {
    let google;
    try {
      google = require('googleapis').google;
    } catch (e) {
      console.warn('[CloudLogEnricher] googleapis not available, skipping GCP logs');
      return [];
    }

    const auth = new google.auth.GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/logging.read'],
    });

    const logging = google.logging({ version: 'v2', auth: await auth.getClient() });
    const timestamp = new Date(Date.now() - this.windowMinutes * 60 * 1000).toISOString();

    const filter = [
      `timestamp >= "${timestamp}"`,
      'protoPayload.@type="type.googleapis.com/google.cloud.audit.v1.AuditLog"',
      '(protoPayload.serviceName="aiplatform.googleapis.com"',
      ' OR protoPayload.serviceName="generativelanguage.googleapis.com"',
      ' OR protoPayload.serviceName="ml.googleapis.com"',
      ' OR protoPayload.serviceName="run.googleapis.com")',
    ].join(' ');

    const response = await logging.entries.list({
      requestBody: {
        resourceNames: [`projects/${this.gcpProjectId}`],
        filter,
        orderBy: 'timestamp desc',
        pageSize: this.maxResults,
      },
    });

    return (response.data.entries || []).map(entry => ({
      timestamp: entry.timestamp,
      service: entry.protoPayload?.serviceName,
      method: entry.protoPayload?.methodName,
      caller: entry.protoPayload?.authenticationInfo?.principalEmail,
      resource: entry.resource?.labels,
      status: entry.protoPayload?.status,
      cloud_provider: 'gcp',
      log_source: this._gcpLogSource(entry.protoPayload?.serviceName),
    }));
  }

  _gcpLogSource(serviceName) {
    if (!serviceName) return 'cloud-audit';
    if (serviceName.includes('aiplatform')) return 'vertex-prediction';
    if (serviceName.includes('generativelanguage')) return 'generative-ai';
    if (serviceName.includes('ml.')) return 'ml-engine';
    return 'cloud-audit';
  }

  // ── AWS CloudTrail ─────────────────────────────────────────────────────────

  async queryCloudTrailEvents() {
    let CloudTrailClient, LookupEventsCommand;
    try {
      ({ CloudTrailClient, LookupEventsCommand } = require('@aws-sdk/client-cloudtrail'));
    } catch (e) {
      console.warn('[CloudLogEnricher] @aws-sdk/client-cloudtrail not available, skipping AWS logs');
      return [];
    }

    const client = new CloudTrailClient({ region: this.awsRegion });
    const startTime = new Date(Date.now() - this.windowMinutes * 60 * 1000);
    const results = [];

    // Query for Bedrock events
    for (const eventSource of ['bedrock.amazonaws.com', 'sagemaker.amazonaws.com']) {
      try {
        const response = await client.send(new LookupEventsCommand({
          StartTime: startTime,
          EndTime: new Date(),
          LookupAttributes: [
            { AttributeKey: 'EventSource', AttributeValue: eventSource },
          ],
          MaxResults: Math.min(50, this.maxResults),
        }));

        for (const event of (response.Events || [])) {
          let detail;
          try { detail = JSON.parse(event.CloudTrailEvent || '{}'); } catch { detail = {}; }

          results.push({
            timestamp: event.EventTime?.toISOString(),
            service: event.EventSource,
            method: event.EventName,
            caller: event.Username,
            resource: detail.requestParameters || {},
            status: detail.errorCode ? { code: detail.errorCode } : { code: 0 },
            cloud_provider: 'aws',
            log_source: eventSource.includes('bedrock') ? 'bedrock-invocation' : 'sagemaker',
          });
        }
      } catch (err) {
        console.warn(`[CloudLogEnricher] CloudTrail query for ${eventSource} failed:`, err.message);
      }
    }

    return results;
  }

  // ── Match log entries to workloads ─────────────────────────────────────────

  matchToWorkloads(entries, workloads, cloudProvider) {
    const enrichments = [];
    const providerDomains = this.registry.getProviderDomains();

    // Build service-account → workload map
    const saMap = new Map();
    for (const w of workloads) {
      const sa = w.metadata?.service_account || w.metadata?.serviceAccount
        || w.metadata?.iam_role || w.metadata?.taskRoleArn;
      if (sa) saMap.set(sa, w);

      // Also map by name for fuzzy matching
      if (w.name) saMap.set(w.name, w);
    }

    for (const entry of entries) {
      const workload = saMap.get(entry.caller) || null;
      const serviceHost = entry.service || '';

      // Match to provider registry
      let providerMatch = null;
      for (const [domain, meta] of Object.entries(providerDomains)) {
        if (serviceHost.includes(domain)) {
          providerMatch = meta.provider;
          break;
        }
      }

      enrichments.push({
        workload_id: workload?.id || null,
        workload_name: workload?.name || entry.caller,
        cloud_provider: cloudProvider,
        log_source: entry.log_source,
        api_called: `${entry.service}/${entry.method}`,
        destination_host: entry.service,
        method: entry.method,
        caller_identity: entry.caller,
        provider_match: providerMatch,
        timestamp: entry.timestamp,
        raw_metadata: {
          resource: entry.resource,
          status: entry.status,
        },
      });
    }

    return enrichments;
  }

  // ── Persist to cloud_log_enrichments ───────────────────────────────────────

  async persistEnrichments(enrichments) {
    if (!this.dbClient || !enrichments.length) return;

    let count = 0;
    for (const e of enrichments) {
      try {
        await this.dbClient.query(`
          INSERT INTO cloud_log_enrichments
            (workload_id, workload_name, cloud_provider, log_source, api_called,
             destination_host, method, caller_identity, provider_match,
             call_count, first_seen, last_seen, raw_metadata)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, $10, $11)
          ON CONFLICT DO NOTHING
        `, [
          e.workload_id, e.workload_name, e.cloud_provider, e.log_source,
          e.api_called, e.destination_host, e.method, e.caller_identity,
          e.provider_match, e.timestamp,
          JSON.stringify(e.raw_metadata),
        ]);
        count++;
      } catch (err) {
        // Skip individual failures
      }
    }

    if (count > 0) {
      console.log(`[CloudLogEnricher] Persisted ${count} cloud log enrichments`);
    }
  }

  // ── Query enrichments for a workload ───────────────────────────────────────

  static async getForWorkload(dbClient, workloadId) {
    if (!dbClient) return [];
    try {
      const { rows } = await dbClient.query(
        `SELECT * FROM cloud_log_enrichments
         WHERE workload_id = $1
         ORDER BY last_seen DESC LIMIT 100`,
        [workloadId]
      );
      return rows.map(r => ({
        provider: r.provider_match,
        api: r.api_called,
        call_count: r.call_count,
        last_seen: r.last_seen,
        source: r.log_source,
        cloud_provider: r.cloud_provider,
      }));
    } catch {
      return [];
    }
  }
}

module.exports = { CloudLogEnricher };
