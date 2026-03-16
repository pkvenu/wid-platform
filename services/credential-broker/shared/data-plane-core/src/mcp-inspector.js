// =============================================================================
// MCP Traffic Inspector — Zero-Copy Tee with Async Parse
// =============================================================================
//
// Detects MCP JSON-RPC traffic by Host header, tees the request body for async
// parsing, extracts structured fields (method, tool_name, arguments keys),
// and emits telemetry events through AuditBuffer.
//
// Mirrors AIInspector pattern exactly:
//   - Zero hot-path latency (PassThrough fork, async parse)
//   - Non-MCP traffic filtered at Host header check (O(1) Set lookup)
//   - Tool argument values NEVER logged (keys only — zero customer data)
//
// MCP JSON-RPC methods detected:
//   initialize, tools/call, tools/list, resources/read, resources/list,
//   prompts/get, prompts/list, completion/complete, ping
// =============================================================================

'use strict';

const { PassThrough } = require('stream');

// MCP JSON-RPC methods we recognize
const MCP_METHODS = new Set([
  'initialize',
  'tools/call',
  'tools/list',
  'resources/read',
  'resources/list',
  'prompts/get',
  'prompts/list',
  'completion/complete',
  'ping',
]);


class MCPInspector {
  /**
   * @param {object} opts
   * @param {object} opts.auditBuffer   - AuditBuffer instance for telemetry emission
   * @param {string} opts.workloadName  - Name of the workload this gateway fronts
   * @param {string} opts.spiffeId      - SPIFFE ID of the workload
   * @param {boolean} [opts.enabled=true]
   * @param {number} [opts.maxBodyBytes=65536] - Max bytes to buffer for parsing
   * @param {string[]} [opts.mcpHosts=[]]      - Known MCP server hostnames
   */
  constructor({ auditBuffer, workloadName, spiffeId, enabled = true, maxBodyBytes = 65536, mcpHosts = [] }) {
    this.auditBuffer = auditBuffer;
    this.workloadName = workloadName;
    this.spiffeId = spiffeId;
    this.enabled = enabled;
    this.maxBodyBytes = maxBodyBytes;
    // O(1) host lookup — strip ports from configured hosts
    this.mcpHostSet = new Set(mcpHosts.map(h => h.split(':')[0].toLowerCase()));
    this.stats = { inspected: 0, parseFailed: 0, byServer: {} };
  }

  /**
   * Fast check: is this host an MCP server?
   * O(1) Set lookup against configured MCP hosts.
   *
   * @param {string} hostHeader - The Host header value (may include port)
   * @returns {{ server: string } | null}
   */
  detectMCPEndpoint(hostHeader) {
    if (!this.enabled || !hostHeader) return null;
    const host = hostHeader.split(':')[0].toLowerCase();

    if (this.mcpHostSet.has(host)) {
      return { server: host };
    }
    return null;
  }

  /**
   * Create a PassThrough tee for the request body.
   * The caller pipes clientReq into both the tee (for inspection) and proxyReq
   * (for forwarding). The tee collects body chunks up to maxBodyBytes and
   * triggers async parsing when the stream ends.
   *
   * @param {import('http').IncomingMessage} clientReq
   * @param {{ server: string }} mcpMatch
   * @param {string} destHost
   * @param {string} method
   * @param {string} path
   * @param {string} decisionId
   * @returns {PassThrough}
   */
  teeRequest(clientReq, mcpMatch, destHost, method, path, decisionId) {
    const tee = new PassThrough();
    const chunks = [];
    let totalBytes = 0;
    let truncated = false;

    tee.on('data', (chunk) => {
      if (totalBytes < this.maxBodyBytes) {
        chunks.push(chunk);
        totalBytes += chunk.length;
      } else {
        truncated = true;
      }
    });

    tee.on('end', () => {
      const bodyBuffer = Buffer.concat(chunks, Math.min(totalBytes, this.maxBodyBytes));
      // Async — doesn't block the proxy
      this._processBody(bodyBuffer, mcpMatch, {
        destHost, method, path, decisionId, truncated, totalBytes,
      });
    });

    tee.on('error', () => {
      // Silently ignore tee errors — proxy must not break
    });

    return tee;
  }

  /**
   * Parse collected body, extract MCP JSON-RPC fields, emit telemetry via AuditBuffer.
   * @private
   */
  _processBody(bodyBuffer, mcpMatch, meta) {
    try {
      const text = bodyBuffer.toString('utf8');
      if (!text || text.length < 2) return;

      const parsed = JSON.parse(text);

      // Must be JSON-RPC
      if (parsed.jsonrpc !== '2.0' || !parsed.method) return;

      // Only inspect known MCP methods
      if (!MCP_METHODS.has(parsed.method)) return;

      const fields = this._extractFields(parsed);

      this.stats.inspected++;
      this.stats.byServer[mcpMatch.server] =
        (this.stats.byServer[mcpMatch.server] || 0) + 1;

      this.auditBuffer.push({
        event_type: 'mcp_tool_call',
        decision_id: meta.decisionId,
        source_name: this.workloadName,
        source_principal: this.spiffeId,
        destination_host: meta.destHost,
        mcp_server_name: mcpMatch.server,
        jsonrpc_method: fields.jsonrpc_method,
        jsonrpc_id: fields.jsonrpc_id,
        tool_name: fields.tool_name,
        tool_arguments: fields.tool_arguments,
        resource_uri: fields.resource_uri,
        prompt_name: fields.prompt_name,
        truncated: meta.truncated,
        body_bytes: meta.totalBytes,
        timestamp: new Date().toISOString(),
      });
    } catch {
      this.stats.parseFailed++;
      // JSON parse failure — not an error, could be binary/form data
    }
  }

  /**
   * Extract MCP-specific fields from parsed JSON-RPC request.
   * Tool argument values are REDACTED — only keys are kept.
   * @private
   */
  _extractFields(parsed) {
    const fields = {
      jsonrpc_method: parsed.method,
      jsonrpc_id: parsed.id != null ? String(parsed.id) : null,
      tool_name: null,
      tool_arguments: {},
      resource_uri: null,
      prompt_name: null,
    };

    const params = parsed.params || {};

    switch (parsed.method) {
      case 'tools/call':
        fields.tool_name = params.name || null;
        // Redact values — only keep keys
        if (params.arguments && typeof params.arguments === 'object') {
          fields.tool_arguments = Object.fromEntries(
            Object.keys(params.arguments).map(k => [k, '[redacted]'])
          );
        }
        break;

      case 'resources/read':
        fields.resource_uri = params.uri || null;
        break;

      case 'prompts/get':
        fields.prompt_name = params.name || null;
        // Redact prompt argument values
        if (params.arguments && typeof params.arguments === 'object') {
          fields.tool_arguments = Object.fromEntries(
            Object.keys(params.arguments).map(k => [k, '[redacted]'])
          );
        }
        break;

      case 'completion/complete':
        // Extract ref type (resource or prompt)
        if (params.ref?.type === 'ref/resource') {
          fields.resource_uri = params.ref.uri || null;
        } else if (params.ref?.type === 'ref/prompt') {
          fields.prompt_name = params.ref.name || null;
        }
        break;

      // initialize, tools/list, resources/list, prompts/list, ping
      // — no specific fields to extract beyond method
    }

    return fields;
  }

  /**
   * Capture MCP server response metadata.
   * Buffers response, extracts result_type/error_code/latency,
   * emits mcp_tool_response event.
   *
   * @param {import('http').IncomingMessage} proxyRes - Response from MCP server
   * @param {import('http').ServerResponse} clientRes - Response to the client
   * @param {{ server: string }} mcpMatch
   * @param {string} decisionId
   * @param {number} requestStart - Date.now() when request was received
   */
  captureResponse(proxyRes, clientRes, mcpMatch, decisionId, requestStart) {
    const statusCode = proxyRes.statusCode;
    const chunks = [];
    let totalBytes = 0;

    proxyRes.on('data', (chunk) => {
      if (totalBytes < this.maxBodyBytes) {
        chunks.push(chunk);
      }
      totalBytes += chunk.length;
    });

    proxyRes.on('end', () => {
      // Write to client
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      for (const chunk of chunks) {
        clientRes.write(chunk);
      }
      clientRes.end();

      // Parse response for telemetry
      const latencyMs = Date.now() - requestStart;
      let resultType = null;
      let resultSizeBytes = totalBytes;
      let errorCode = null;
      let errorMessage = null;

      try {
        const bodyBuffer = Buffer.concat(chunks, Math.min(totalBytes, this.maxBodyBytes));
        const parsed = JSON.parse(bodyBuffer.toString('utf8'));

        if (parsed.result) {
          resultType = typeof parsed.result === 'object'
            ? (Array.isArray(parsed.result) ? 'array' : 'object')
            : typeof parsed.result;
        }
        if (parsed.error) {
          errorCode = parsed.error.code || null;
          errorMessage = (parsed.error.message || '').slice(0, 500);
        }
      } catch {
        // Not JSON — leave fields null
      }

      this.auditBuffer.push({
        event_type: 'mcp_tool_response',
        decision_id: decisionId,
        source_name: this.workloadName,
        source_principal: this.spiffeId,
        mcp_server_name: mcpMatch.server,
        response_status: statusCode,
        result_type: resultType,
        result_size_bytes: resultSizeBytes,
        error_code: errorCode,
        error_message: errorMessage,
        latency_ms: latencyMs,
        timestamp: new Date().toISOString(),
      });
    });

    proxyRes.on('error', () => {
      // Don't break the pipe on errors
    });
  }

  /**
   * Stats for admin /metrics endpoint.
   */
  getStats() {
    return {
      enabled: this.enabled,
      inspected: this.stats.inspected,
      parseFailed: this.stats.parseFailed,
      byServer: { ...this.stats.byServer },
    };
  }
}

module.exports = { MCPInspector, MCP_METHODS };
