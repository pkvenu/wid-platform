// =============================================================================
// MCP Inspector — Test Suite
// =============================================================================

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('stream');

const { MCPInspector, MCP_METHODS } = require('../src/mcp-inspector');

// ── Mock AuditBuffer ─────────────────────────────────────────────────────────

function createMockAuditBuffer() {
  const entries = [];
  return {
    push(entry) { entries.push(entry); },
    getEntries() { return entries; },
    flush() {},
    getStats() { return { pending: entries.length, flushed: 0, failed: 0 }; },
  };
}

// ── Helper: create a readable stream from a string ───────────────────────────

function stringToStream(str) {
  const readable = new Readable();
  readable.push(Buffer.from(str));
  readable.push(null);
  return readable;
}


// =============================================================================
// detectMCPEndpoint
// =============================================================================

describe('MCPInspector.detectMCPEndpoint', () => {
  let inspector;

  beforeEach(() => {
    inspector = new MCPInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/test-agent',
      mcpHosts: ['mcp-server', 'tools.internal.svc'],
    });
  });

  it('detects configured MCP host', () => {
    const match = inspector.detectMCPEndpoint('mcp-server');
    assert.deepEqual(match, { server: 'mcp-server' });
  });

  it('detects MCP host with port stripped', () => {
    const match = inspector.detectMCPEndpoint('mcp-server:3000');
    assert.deepEqual(match, { server: 'mcp-server' });
  });

  it('detects second configured host', () => {
    const match = inspector.detectMCPEndpoint('tools.internal.svc:8080');
    assert.deepEqual(match, { server: 'tools.internal.svc' });
  });

  it('returns null for non-MCP host', () => {
    const match = inspector.detectMCPEndpoint('api.openai.com');
    assert.equal(match, null);
  });

  it('returns null when disabled', () => {
    inspector.enabled = false;
    const match = inspector.detectMCPEndpoint('mcp-server');
    assert.equal(match, null);
  });

  it('returns null for empty host', () => {
    const match = inspector.detectMCPEndpoint('');
    assert.equal(match, null);
  });

  it('returns null for null host', () => {
    const match = inspector.detectMCPEndpoint(null);
    assert.equal(match, null);
  });

  it('is case-insensitive', () => {
    const match = inspector.detectMCPEndpoint('MCP-SERVER:3000');
    assert.deepEqual(match, { server: 'mcp-server' });
  });
});


// =============================================================================
// _extractFields
// =============================================================================

describe('MCPInspector._extractFields', () => {
  let inspector;

  beforeEach(() => {
    inspector = new MCPInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test-agent',
      spiffeId: 'spiffe://cluster.local/ns/default/sa/test-agent',
      mcpHosts: [],
    });
  });

  it('extracts tools/call fields with redacted arguments', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: '42',
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '/etc/passwd', encoding: 'utf8' },
      },
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_method, 'tools/call');
    assert.equal(fields.jsonrpc_id, '42');
    assert.equal(fields.tool_name, 'read_file');
    assert.deepEqual(fields.tool_arguments, { path: '[redacted]', encoding: '[redacted]' });
    assert.equal(fields.resource_uri, null);
    assert.equal(fields.prompt_name, null);
  });

  it('extracts resources/read fields', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: '2',
      method: 'resources/read',
      params: { uri: 'file:///tmp/data.json' },
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_method, 'resources/read');
    assert.equal(fields.resource_uri, 'file:///tmp/data.json');
    assert.equal(fields.tool_name, null);
  });

  it('extracts prompts/get fields', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: '3',
      method: 'prompts/get',
      params: {
        name: 'summarize',
        arguments: { text: 'secret data here' },
      },
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_method, 'prompts/get');
    assert.equal(fields.prompt_name, 'summarize');
    assert.deepEqual(fields.tool_arguments, { text: '[redacted]' });
  });

  it('handles initialize method (no specific fields)', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: '1',
      method: 'initialize',
      params: { protocolVersion: '2024-11-05' },
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_method, 'initialize');
    assert.equal(fields.tool_name, null);
    assert.equal(fields.resource_uri, null);
  });

  it('handles tools/call with no arguments', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: '5',
      method: 'tools/call',
      params: { name: 'list_files' },
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.tool_name, 'list_files');
    assert.deepEqual(fields.tool_arguments, {});
  });

  it('handles numeric jsonrpc id', () => {
    const parsed = {
      jsonrpc: '2.0',
      id: 7,
      method: 'ping',
      params: {},
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_id, '7');
  });

  it('handles null jsonrpc id (notification)', () => {
    const parsed = {
      jsonrpc: '2.0',
      method: 'tools/list',
      params: {},
    };
    const fields = inspector._extractFields(parsed);
    assert.equal(fields.jsonrpc_id, null);
  });
});


// =============================================================================
// _processBody + event emission
// =============================================================================

describe('MCPInspector._processBody', () => {
  let inspector, auditBuffer;

  beforeEach(() => {
    auditBuffer = createMockAuditBuffer();
    inspector = new MCPInspector({
      auditBuffer,
      workloadName: 'data-agent',
      spiffeId: 'spiffe://cluster.local/ns/prod/sa/data-agent',
      mcpHosts: ['mcp-server'],
    });
  });

  it('emits mcp_tool_call event for valid tools/call', () => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: '1',
      method: 'tools/call',
      params: { name: 'query_db', arguments: { sql: 'SELECT 1' } },
    });

    inspector._processBody(
      Buffer.from(body),
      { server: 'mcp-server' },
      { destHost: 'mcp-server', method: 'POST', path: '/', decisionId: 'dec_test', truncated: false, totalBytes: body.length }
    );

    const entries = auditBuffer.getEntries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].event_type, 'mcp_tool_call');
    assert.equal(entries[0].tool_name, 'query_db');
    assert.equal(entries[0].source_name, 'data-agent');
    assert.deepEqual(entries[0].tool_arguments, { sql: '[redacted]' });
    assert.equal(entries[0].decision_id, 'dec_test');
    assert.equal(entries[0].mcp_server_name, 'mcp-server');
  });

  it('ignores non-JSON-RPC body', () => {
    inspector._processBody(
      Buffer.from('{"hello":"world"}'),
      { server: 'mcp-server' },
      { destHost: 'mcp-server', method: 'POST', path: '/', decisionId: 'dec_test', truncated: false, totalBytes: 17 }
    );

    const entries = auditBuffer.getEntries();
    assert.equal(entries.length, 0);
  });

  it('ignores unknown JSON-RPC methods', () => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: '1',
      method: 'custom/unknown',
      params: {},
    });

    inspector._processBody(
      Buffer.from(body),
      { server: 'mcp-server' },
      { destHost: 'mcp-server', method: 'POST', path: '/', decisionId: 'dec_test', truncated: false, totalBytes: body.length }
    );

    assert.equal(auditBuffer.getEntries().length, 0);
  });

  it('increments stats on successful parse', () => {
    const body = JSON.stringify({
      jsonrpc: '2.0', id: '1', method: 'tools/list', params: {},
    });

    inspector._processBody(
      Buffer.from(body), { server: 'db-tools' },
      { destHost: 'db-tools', method: 'POST', path: '/', decisionId: 'dec_1', truncated: false, totalBytes: body.length }
    );

    const stats = inspector.getStats();
    assert.equal(stats.inspected, 1);
    assert.equal(stats.byServer['db-tools'], 1);
  });

  it('increments parseFailed on invalid JSON', () => {
    inspector._processBody(
      Buffer.from('not json at all'),
      { server: 'mcp-server' },
      { destHost: 'mcp-server', method: 'POST', path: '/', decisionId: 'dec_1', truncated: false, totalBytes: 15 }
    );

    const stats = inspector.getStats();
    assert.equal(stats.parseFailed, 1);
    assert.equal(stats.inspected, 0);
  });
});


// =============================================================================
// getStats
// =============================================================================

describe('MCPInspector.getStats', () => {
  it('returns initial stats', () => {
    const inspector = new MCPInspector({
      auditBuffer: createMockAuditBuffer(),
      workloadName: 'test',
      spiffeId: 'spiffe://test',
      mcpHosts: [],
    });

    const stats = inspector.getStats();
    assert.equal(stats.enabled, true);
    assert.equal(stats.inspected, 0);
    assert.equal(stats.parseFailed, 0);
    assert.deepEqual(stats.byServer, {});
  });
});
