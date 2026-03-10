// =============================================================================
// RemediationExecutor — Execute, approve, and rollback remediation actions
// =============================================================================
// State machine: pending → approved → executing → completed | failed
//                                                         → rolled_back
//
// Channels:
//   policy  — POST to policy-engine /api/v1/policies/from-template (auto-approved)
//   api     — HTTP calls to credential-broker or cloud APIs
//   cli     — child_process.exec with timeout + sandbox (requires approval)
//
// Low-risk (policy-type) remediations auto-execute.
// High-risk (cli, api with destructive actions) require explicit approval.
// =============================================================================

const { exec } = require('child_process');
const http = require('http');
const https = require('https');

const POLICY_ENGINE_URL = process.env.POLICY_ENGINE_URL
  || process.env.POLICY_SYNC_URL
  || 'http://policy-sync-service:3001';

const CREDENTIAL_BROKER_URL = process.env.CREDENTIAL_BROKER_URL
  || 'http://credential-broker:3002';

const CLI_TIMEOUT_MS = 30000;

// Controls that are safe to auto-execute (no approval needed)
const AUTO_APPROVE_ACTION_TYPES = new Set(['policy', 'notify']);

class RemediationExecutor {
  constructor(dbClient) {
    this.db = dbClient;
  }

  // ── Request an execution (creates record, may auto-execute) ────────────

  async requestExecution(controlId, nodeId, channel, opts = {}) {
    if (!this.db) throw new Error('Database not connected');

    const {
      requestedBy = 'system',
      autoApprove = false,
      commands = null,
      rollbackCommands = null,
      context = {},
    } = opts;

    // Look up the intent to determine risk level
    let intent = null;
    try {
      const { rows } = await this.db.query(
        'SELECT * FROM remediation_intents WHERE id = $1 OR control_id = $1',
        [controlId]
      );
      intent = rows[0] || null;
    } catch { /* table may not exist */ }

    const isLowRisk = intent
      ? AUTO_APPROVE_ACTION_TYPES.has(intent.action_type)
      : false;

    const shouldAutoApprove = autoApprove || (isLowRisk && channel === 'policy');

    // Insert execution record
    const { rows } = await this.db.query(`
      INSERT INTO remediation_executions
        (control_id, node_id, channel, status, requested_by, commands, rollback_commands, requested_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *
    `, [
      controlId,
      nodeId,
      channel,
      shouldAutoApprove ? 'approved' : 'pending',
      requestedBy,
      commands ? JSON.stringify(commands) : null,
      rollbackCommands ? JSON.stringify(rollbackCommands) : null,
    ]);

    const execution = rows[0];
    console.log(`[Executor] Created execution #${execution.id}: ${controlId} → ${channel} (${execution.status})`);

    // Auto-execute if approved
    if (shouldAutoApprove) {
      return this._execute(execution.id, context);
    }

    return {
      id: execution.id,
      status: 'pending',
      message: `Execution #${execution.id} awaiting approval`,
      approve_url: `/api/v1/graph/remediation-executions/${execution.id}/approve`,
    };
  }

  // ── Approve and execute ────────────────────────────────────────────────

  async approveAndExecute(executionId, approvedBy = 'admin', context = {}) {
    if (!this.db) throw new Error('Database not connected');

    const { rows } = await this.db.query(
      'SELECT * FROM remediation_executions WHERE id = $1', [executionId]
    );
    if (!rows.length) throw new Error(`Execution #${executionId} not found`);

    const execution = rows[0];
    if (execution.status !== 'pending') {
      throw new Error(`Execution #${executionId} is ${execution.status}, expected pending`);
    }

    await this.db.query(
      `UPDATE remediation_executions
       SET status = 'approved', approved_by = $2, approved_at = NOW()
       WHERE id = $1`,
      [executionId, approvedBy]
    );

    return this._execute(executionId, context);
  }

  // ── Internal execute (dispatches to channel handler) ───────────────────

  async _execute(executionId, context = {}) {
    // Load execution
    const { rows } = await this.db.query(
      'SELECT * FROM remediation_executions WHERE id = $1', [executionId]
    );
    if (!rows.length) throw new Error(`Execution #${executionId} not found`);
    const execution = rows[0];

    // Mark executing
    await this.db.query(
      `UPDATE remediation_executions SET status = 'executing', executed_at = NOW() WHERE id = $1`,
      [executionId]
    );

    try {
      let result;
      const commands = typeof execution.commands === 'string'
        ? JSON.parse(execution.commands)
        : execution.commands;

      switch (execution.channel) {
        case 'policy':
          result = await this._executePolicy(execution, commands, context);
          break;
        case 'api':
          result = await this._executeAPI(execution, commands, context);
          break;
        case 'cli':
          result = await this._executeCLI(execution, commands, context);
          break;
        default:
          throw new Error(`Unsupported channel: ${execution.channel}`);
      }

      // Mark completed
      await this.db.query(
        `UPDATE remediation_executions
         SET status = 'completed', output = $2, completed_at = NOW()
         WHERE id = $1`,
        [executionId, typeof result === 'string' ? result : JSON.stringify(result)]
      );

      console.log(`[Executor] Execution #${executionId} completed (${execution.channel})`);
      return {
        id: executionId,
        status: 'completed',
        channel: execution.channel,
        output: result,
      };

    } catch (error) {
      // Mark failed
      await this.db.query(
        `UPDATE remediation_executions
         SET status = 'failed', error_message = $2, completed_at = NOW()
         WHERE id = $1`,
        [executionId, error.message]
      );

      console.error(`[Executor] Execution #${executionId} failed:`, error.message);
      return {
        id: executionId,
        status: 'failed',
        channel: execution.channel,
        error: error.message,
      };
    }
  }

  // ── Policy channel: create/update policy via policy-engine ──────────

  async _executePolicy(execution, commands, context) {
    const controlId = execution.control_id;

    // Look up template_id from intent
    let templateId = null;
    try {
      const { rows } = await this.db.query(
        'SELECT template_id FROM remediation_intents WHERE id = $1 OR control_id = $1',
        [controlId]
      );
      templateId = rows[0]?.template_id;
    } catch { /* skip */ }

    if (!templateId) {
      // Use control_id as template_id fallback
      templateId = controlId;
    }

    // Call policy-engine from-template endpoint
    const url = `${POLICY_ENGINE_URL}/api/v1/policies/from-template/${encodeURIComponent(templateId)}`;
    const body = {
      enforcement_mode: context.enforcement_mode || 'audit',
      created_by: execution.requested_by || 'remediation-executor',
      name: context.policy_name || `remediation-${controlId}`,
    };

    const response = await this._httpRequest('POST', url, body, 10000);

    return {
      policy_id: response.data?.id,
      template_id: templateId,
      enforcement_mode: body.enforcement_mode,
      message: `Policy created from template ${templateId}`,
      policy: response.data,
    };
  }

  // ── API channel: HTTP calls to internal services ────────────────────

  async _executeAPI(execution, commands, context) {
    if (!commands || !Array.isArray(commands) || commands.length === 0) {
      throw new Error('API channel requires commands array with {method, url, body} entries');
    }

    const results = [];
    for (const cmd of commands) {
      // Commands can be objects: { method, url, body, headers }
      // or strings: "POST http://service/path {body}"
      let method, url, body, headers;

      if (typeof cmd === 'object') {
        method = cmd.method || 'POST';
        url = cmd.url;
        body = cmd.body;
        headers = cmd.headers || {};
      } else if (typeof cmd === 'string') {
        const parts = cmd.trim().split(/\s+/);
        method = parts[0] || 'GET';
        url = parts[1];
        body = parts.slice(2).join(' ');
        if (body) {
          try { body = JSON.parse(body); } catch { /* leave as string */ }
        }
        headers = {};
      } else {
        continue;
      }

      // Only allow calls to internal services
      if (!this._isAllowedURL(url)) {
        results.push({ url, status: 'blocked', reason: 'URL not in allowed list' });
        continue;
      }

      try {
        const response = await this._httpRequest(method, url, body || undefined, 15000, headers);
        results.push({
          url,
          method,
          status: response.statusCode,
          data: response.data,
        });
      } catch (err) {
        results.push({ url, method, status: 'error', error: err.message });
      }
    }

    return results;
  }

  // ── CLI channel: execute shell commands with sandboxing ──────────────

  async _executeCLI(execution, commands, context) {
    if (!commands || !Array.isArray(commands) || commands.length === 0) {
      throw new Error('CLI channel requires commands array');
    }

    const results = [];
    for (const cmd of commands) {
      const cmdStr = typeof cmd === 'string' ? cmd : cmd.command || String(cmd);

      // Block dangerous commands
      if (this._isDangerous(cmdStr)) {
        results.push({ command: cmdStr, status: 'blocked', reason: 'Command blocked by safety filter' });
        continue;
      }

      try {
        const output = await this._execWithTimeout(cmdStr, CLI_TIMEOUT_MS);
        results.push({ command: cmdStr, status: 'success', output });
      } catch (err) {
        results.push({ command: cmdStr, status: 'failed', error: err.message });
      }
    }

    return results;
  }

  // ── Rollback an execution ──────────────────────────────────────────────

  async rollback(executionId) {
    if (!this.db) throw new Error('Database not connected');

    const { rows } = await this.db.query(
      'SELECT * FROM remediation_executions WHERE id = $1', [executionId]
    );
    if (!rows.length) throw new Error(`Execution #${executionId} not found`);

    const execution = rows[0];
    if (execution.status !== 'completed' && execution.status !== 'failed') {
      throw new Error(`Cannot rollback execution #${executionId} in status: ${execution.status}`);
    }

    const rollbackCommands = typeof execution.rollback_commands === 'string'
      ? JSON.parse(execution.rollback_commands)
      : execution.rollback_commands;

    if (!rollbackCommands || rollbackCommands.length === 0) {
      throw new Error(`No rollback commands for execution #${executionId}`);
    }

    // Execute rollback
    let result;
    try {
      switch (execution.channel) {
        case 'cli':
          result = await this._executeCLI(execution, rollbackCommands, {});
          break;
        case 'api':
          result = await this._executeAPI(execution, rollbackCommands, {});
          break;
        default:
          throw new Error(`Rollback not supported for channel: ${execution.channel}`);
      }
    } catch (err) {
      await this.db.query(
        `UPDATE remediation_executions SET error_message = $2 WHERE id = $1`,
        [executionId, `Rollback failed: ${err.message}`]
      );
      throw err;
    }

    await this.db.query(
      `UPDATE remediation_executions SET status = 'rolled_back', output = $2 WHERE id = $1`,
      [executionId, JSON.stringify(result)]
    );

    console.log(`[Executor] Execution #${executionId} rolled back`);
    return { id: executionId, status: 'rolled_back', output: result };
  }

  // ── Query helpers ──────────────────────────────────────────────────────

  async getExecution(executionId) {
    if (!this.db) return null;
    const { rows } = await this.db.query(
      'SELECT * FROM remediation_executions WHERE id = $1', [executionId]
    );
    return rows[0] || null;
  }

  async listExecutions(filters = {}) {
    if (!this.db) return [];
    let query = 'SELECT * FROM remediation_executions';
    const params = [];
    const conditions = [];

    if (filters.nodeId) {
      params.push(filters.nodeId);
      conditions.push(`node_id = $${params.length}`);
    }
    if (filters.status) {
      params.push(filters.status);
      conditions.push(`status = $${params.length}`);
    }
    if (filters.controlId) {
      params.push(filters.controlId);
      conditions.push(`control_id = $${params.length}`);
    }

    if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY requested_at DESC LIMIT 100';

    const { rows } = await this.db.query(query, params);
    return rows;
  }

  // ── HTTP helper (built-in http/https, no axios) ─────────────────────────

  _httpRequest(method, urlStr, body, timeoutMs = 10000, extraHeaders = {}) {
    return new Promise((resolve, reject) => {
      const parsed = new URL(urlStr);
      const transport = parsed.protocol === 'https:' ? https : http;
      const payload = body ? JSON.stringify(body) : null;

      const headers = { ...extraHeaders };
      if (payload) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = Buffer.byteLength(payload);
      }

      const req = transport.request({
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers,
        timeout: timeoutMs,
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          let parsed;
          try { parsed = JSON.parse(data); } catch { parsed = data; }
          resolve({ statusCode: res.statusCode, data: parsed });
        });
      });

      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
      if (payload) req.write(payload);
      req.end();
    });
  }

  // ── Safety helpers ─────────────────────────────────────────────────────

  _isAllowedURL(url) {
    if (!url) return false;
    // Allow internal service URLs
    const allowed = [
      'http://credential-broker', 'http://localhost:3002',
      'http://policy-sync-service', 'http://localhost:3001',
      'http://token-service', 'http://localhost:3000',
      POLICY_ENGINE_URL, CREDENTIAL_BROKER_URL,
    ];
    return allowed.some(prefix => url.startsWith(prefix));
  }

  _isDangerous(cmd) {
    // Block destructive or escape-prone commands
    const blocked = [
      /\brm\s+-rf\b/, /\brmdir\b/, /\bmkfs\b/, /\bdd\s+if=/, /\bformat\b/,
      /\bshutdown\b/, /\breboot\b/, /\bkill\s+-9\b/, /\bpkill\b/,
      /[;&|]\s*(curl|wget)\b.*\|.*sh/, // pipe to shell
      /\bsudo\b/, /\bsu\s+-\b/,
    ];
    return blocked.some(re => re.test(cmd));
  }

  _execWithTimeout(cmd, timeoutMs) {
    return new Promise((resolve, reject) => {
      const child = exec(cmd, { timeout: timeoutMs, maxBuffer: 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          reject(new Error(`${error.message}\n${stderr || ''}`));
        } else {
          resolve(stdout || stderr || '(no output)');
        }
      });
    });
  }
}

module.exports = { RemediationExecutor };
