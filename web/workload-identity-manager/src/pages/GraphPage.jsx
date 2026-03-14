import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import * as d3 from 'd3';
import {
  GitBranch, Shield, AlertTriangle, CheckCircle2, Zap, Lock, Eye, Activity,
  ChevronRight, RefreshCw, Loader, Maximize2, PanelRightClose, PanelRightOpen,
  Search, X, ChevronLeft,
} from 'lucide-react';

const API = (typeof __API_BASE__ !== 'undefined' && window.location.hostname !== 'localhost') ? (__API_BASE__ + '/api/v1') : '/api/v1';

/* ═══════════════════════════════════════════
   Visual Config
   ═══════════════════════════════════════════ */
const NODE_CFG = {
  // Human Users
  'user':              { color: '#22d3ee', icon: '👤', r: 20, label: 'Human User' },
  // Identity
  'service-account':   { color: '#a78bfa', icon: '🔑', r: 22, label: 'Service Account' },
  'managed-identity':  { color: '#0ea5e9', icon: '🆔', r: 17, label: 'Managed ID' },
  'iam-role':          { color: '#f59e0b', icon: '🛡️', r: 12, label: 'IAM Role' },
  'iam-policy':        { color: '#f59e0b', icon: '📋', r: 12, label: 'Policy' },
  // GCP Workloads
  'cloud-run':         { color: '#3b82f6', icon: '☁️', r: 17, label: 'Cloud Run' },
  'cloud-run-service': { color: '#3b82f6', icon: '☁️', r: 17, label: 'Cloud Run' },
  'gce-instance':      { color: '#3b82f6', icon: '🖥️', r: 17, label: 'VM' },
  'cloud-function':    { color: '#3b82f6', icon: '⚡', r: 14, label: 'Function' },
  'gke-cluster':       { color: '#3b82f6', icon: '☸', r: 18, label: 'GKE' },
  // AWS Workloads
  'lambda':            { color: '#f97316', icon: '⚡', r: 14, label: 'Lambda' },
  'ec2':               { color: '#f97316', icon: '🖥️', r: 17, label: 'EC2' },
  'ecs-task':          { color: '#f97316', icon: '📦', r: 14, label: 'ECS' },
  // Containers / K8s
  'container':         { color: '#8b5cf6', icon: '📦', r: 14, label: 'Container' },
  'pod':               { color: '#8b5cf6', icon: '📦', r: 13, label: 'Pod' },
  // AI Agents (special visual treatment)
  'a2a-agent':         { color: '#ec4899', icon: '🤖', r: 18, label: 'AI Agent' },
  'mcp-server':        { color: '#8b5cf6', icon: '🔌', r: 16, label: 'MCP Server' },
  // Resources & Credentials
  'resource':          { color: '#10b981', icon: '💾', r: 14, label: 'Resource' },
  'external-resource': { color: '#10b981', icon: '🌍', r: 14, label: 'Ext Resource' },
  'credential':        { color: '#f97316', icon: '🗝️', r: 12, label: 'Credential' },
  'external-api':      { color: '#06b6d4', icon: '🔗', r: 12, label: 'External API' },
  // Exposure
  'exposure':          { color: '#ef4444', icon: '🌐', r: 14, label: 'Exposure' },
  // SPIFFE
  'spiffe-id':         { color: '#a78bfa', icon: '🪪', r: 11, label: 'SPIFFE ID' },
};
const TRUST_COLORS = { cryptographic: '#10b981', 'very-high': '#22d3ee', high: '#3b82f6', medium: '#f59e0b', low: '#f97316', none: '#ef4444' };
const SEM = {
  good:    '#10b981', // green  — resolved, enforced, safe
  bad:     '#ef4444', // red    — critical, active threat
  warn:    '#f59e0b', // amber  — needs attention, audit mode
  neutral: '#64748b', // gray   — informational
  accent:  '#7c6ff0', // purple — WID brand actions only
};
const SEV = {
  critical: { color: '#ef4444', bg: '#ef444412', label: 'CRITICAL' },
  high:     { color: '#f97316', bg: '#f9731612', label: 'HIGH' },
  medium:   { color: '#f59e0b', bg: '#f59e0b12', label: 'MEDIUM' },
  low:      { color: '#3b82f6', bg: '#3b82f612', label: 'LOW' },
  info:     { color: '#64748b', bg: '#64748b12', label: 'INFO' },
};
const vis = (type, node) => {
  // If node is flagged as AI agent/MCP but has a generic type, use AI agent styling
  if (node) {
    if (node.is_ai_agent && !NODE_CFG[type]) return NODE_CFG['a2a-agent'];
    if (node.is_mcp_server && !NODE_CFG[type]) return NODE_CFG['mcp-server'];
  }
  return NODE_CFG[type] || { color: '#666', icon: '?', r: 13, label: type };
};

// ═══════════════════════════════════════════════════════════════════════════
// CONNECTION CATEGORIES — semantic grouping + color coding
// ═══════════════════════════════════════════════════════════════════════════
const CONNECTION_CATEGORIES = {
  'exposed-via':         { cat: 'exposure',  label: 'NETWORK EXPOSURE',  color: '#ef4444' },
  'allows-ingress-from': { cat: 'exposure',  label: 'NETWORK EXPOSURE',  color: '#ef4444' },
  'publicly-exposes':    { cat: 'exposure',  label: 'NETWORK EXPOSURE',  color: '#ef4444' },
  'runs-as':             { cat: 'identity',  label: 'IDENTITY BINDING',  color: '#a78bfa' },
  'shares-identity':     { cat: 'identity',  label: 'IDENTITY BINDING',  color: '#a78bfa' },
  'communicates-with':   { cat: 'identity',  label: 'IDENTITY BINDING',  color: '#a78bfa' },
  'identifies':          { cat: 'identity',  label: 'IDENTITY BINDING',  color: '#a78bfa' },
  'has-role':            { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'grants-access':       { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'holds-credential':    { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'accesses-api':        { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'has-policy':          { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'can-assume':          { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'can-escalate-to':     { cat: 'privilege',  label: 'PRIVILEGE CHAIN',   color: '#f59e0b' },
  'runs-as-protocol':    { cat: 'agent',      label: 'AGENT PROTOCOL',    color: '#ec4899' },
  'uses-mcp-server':     { cat: 'agent',      label: 'AGENT PROTOCOL',    color: '#ec4899' },
  'can-delegate-to':     { cat: 'agent',      label: 'AGENT PROTOCOL',    color: '#ec4899' },
};
const CAT_ORDER = ['exposure', 'identity', 'privilege', 'agent'];
const CAT_ICONS = { exposure: '🌐', identity: '🔑', privilege: '🛡️', agent: '🤖' };

const CONNECTION_MEANING = {
  'runs-as': (r, other) =>
    `This workload authenticates all API calls as ${other?.label || 'this identity'}. Compromising it gives the attacker these credentials.`,
  'shares-identity': (r, other) =>
    `${r.sharedCount || 'Multiple'} workloads share ${r.sharedSA ? `SA ${r.sharedSA.split('@')[0]}` : 'the same identity'}. Compromising any one gives lateral access to all.`,
  'has-role': (r, other) =>
    `This identity is bound to ${other?.label || 'an IAM role'}, inheriting all its permissions.`,
  'grants-access': (r, other) =>
    `This role grants permission to reach ${other?.label || 'a protected resource'} — contributes to blast radius.`,
  'exposed-via': (r, other) =>
    `This workload accepts traffic from the public internet — a potential entry point for external attackers.`,
  'allows-ingress-from': (r, other) =>
    `Firewall rule allows inbound traffic from ${other?.label || 'an external source'} to reach this workload.`,
  'publicly-exposes': (r, other) =>
    `Publicly exposes ${other?.label || 'this workload'} to the internet without access controls.`,
  'runs-as-protocol': (r, other) =>
    `Implements the ${(r.protocol || 'A2A').toUpperCase()} agent protocol — can receive tasks from other agents.`,
  'uses-mcp-server': (r, other) =>
    `Can invoke tools on ${other?.label || 'an MCP server'} — tool calls are an unmonitored API surface.`,
  'can-delegate-to': (r, other) =>
    `Can delegate tasks to ${other?.label || 'another agent'} via A2A protocol — creates a trust chain.`,
  'holds-credential': (r, other) =>
    `Holds credential ${other?.label || ''} — if this identity is compromised, the credential is exposed.`,
  'accesses-api': (r, other) =>
    `Uses this credential to access ${other?.label || 'an external API'}.`,
  'communicates-with': (r, other) =>
    `Can reach ${other?.label || 'this workload'} directly on the same network — no external routing required.`,
  'identifies': (r, other) =>
    `SPIFFE identity bound to ${other?.label || 'this workload'} for cryptographic attestation.`,
  'has-policy': (r, other) =>
    `IAM policy attached granting permissions defined in ${other?.label || 'the policy document'}.`,
  'can-assume': (r, other) =>
    `Can assume ${other?.label || 'this role'} via cross-account trust — grants external access.`,
  'can-escalate-to': (r, other) =>
    `Can escalate privileges to ${other?.label || 'an admin role'} — a privilege escalation path.`,
};

// ═══════════════════════════════════════════════════════════════════════════
// CONTROL SCORING — computed client-side from graph data
// FALLBACK only — primary source is backend DB via ranked_controls + /finding-types API
// ═══════════════════════════════════════════════════════════════════════════
const CONTROL_CATALOG_FALLBACK = {
  'static-external-credential': [
    { id: 'migrate-to-vault', name: 'Migrate to Secret Manager', description: 'Move credential from env var to secret manager (GCP Secret Manager, AWS Secrets Manager, HashiCorp Vault)', action_type: 'remediate', remediation_type: 'iac', path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: ['vault-available'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' }, template_id: 'secret-in-env-plaintext' },
    { id: 'jit-token-rotation', name: 'Replace with JIT Gateway Token', description: 'Route API access through WID Edge Gateway with short-lived JIT tokens (5min TTL, auto-rotated)', action_type: 'replace', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['edge-gateway-deployed', 'spire-available'], effort: 'days', automated: true }, operational: { implementation: 5, ongoing_toil: 0, expertise: 'medium' }, template_id: 'jit-credential-required' },
    { id: 'add-expiry-rotation', name: 'Add Expiry + Rotation Policy', description: 'Set credential expiry (90d) and enable automatic rotation schedule via cloud provider settings', action_type: 'harden', remediation_type: 'iac', path_break: { edge_position: 'credential', edges_severed: 0, crown_jewel_proximity: 0.4 }, feasibility: { preconditions: ['api-supports-rotation'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 2, expertise: 'low' }, template_id: 'long-lived-api-key' },
    { id: 'scope-reduction', name: 'Reduce Credential Scope', description: 'Limit credential permissions to minimum required (e.g., charges:write → charges:create only)', action_type: 'harden', remediation_type: 'iac', path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.6 }, feasibility: { preconditions: ['api-supports-scoping'], effort: 'hours', automated: false }, operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' }, template_id: null },
  ],
  'toxic-combo': [
    { id: 'identity-separation', name: 'Separate into Dedicated Identities', description: 'Split workload into 2 agents — one for financial (Stripe), one for CRM (Salesforce) — each with dedicated credentials', action_type: 'architecture', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['can-split-workload'], effort: 'weeks', automated: false }, operational: { implementation: 8, ongoing_toil: 2, expertise: 'high' }, template_id: 'toxic-combo-financial-crm' },
    { id: 'scope-ceiling', name: 'Agent Scope Ceiling', description: 'Enforce maximum scope per workload identity — prevent any single identity from holding financial + CRM access', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' }, template_id: 'agent-scope-ceiling' },
    { id: 'jit-with-approval', name: 'JIT Access with Human Approval', description: 'Replace static credentials with JIT tokens that require human approval for cross-domain access', action_type: 'replace', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.95 }, feasibility: { preconditions: ['edge-gateway-deployed', 'approval-workflow'], effort: 'days', automated: true }, operational: { implementation: 5, ongoing_toil: 3, expertise: 'medium' }, template_id: 'jit-credential-required' },
  ],
  'mcp-static-credentials': [
    { id: 'mcp-oauth', name: 'Migrate to OAuth 2.1', description: 'Replace static MCP server credentials with OAuth 2.1 client credentials flow', action_type: 'replace', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: ['mcp-server-supports-oauth'], effort: 'days', automated: true }, operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' }, template_id: 'mcp-oauth-required' },
    { id: 'mcp-static-ban', name: 'Ban Static Credentials', description: 'Enforce policy that denies any MCP server connection using static credentials', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.7 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'mcp-static-credential-ban' },
  ],
  'mcp-tool-poisoning': [
    { id: 'mcp-disconnect-poisoned', name: 'Disconnect Poisoned MCP Server', description: 'Immediately disconnect the MCP server with tool poisoning indicators. Audit all previous tool invocations.', action_type: 'contain', remediation_type: 'infra', path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: [], effort: 'hours', automated: false }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'medium' }, template_id: 'mcp-poisoning-containment' },
    { id: 'mcp-tool-description-audit', name: 'Enforce Tool Description Scanning', description: 'Deploy WID policy that scans MCP tool descriptions for prompt injection and exfiltration patterns.', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['edge-gateway-deployed'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'mcp-tool-poisoning-scan' },
  ],
  'mcp-unverified-server': [
    { id: 'mcp-pin-verified-version', name: 'Pin to Verified MCP Package', description: 'Replace unverified MCP server with a verified package from the known-good registry.', action_type: 'replace', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.6 }, feasibility: { preconditions: [], effort: 'hours', automated: false }, operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' }, template_id: 'mcp-integrity-verification' },
    { id: 'mcp-integrity-policy', name: 'Enforce Server Integrity Check', description: 'Deploy policy that denies connections to MCP servers not in the known-good registry.', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'mcp-server-integrity-required' },
  ],
  'mcp-outdated-version': [
    { id: 'mcp-update-version', name: 'Update MCP Server Version', description: 'Update MCP server to minimum recommended version. Outdated versions may have known vulnerabilities.', action_type: 'remediate', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.5 }, feasibility: { preconditions: [], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 1, expertise: 'low' }, template_id: 'mcp-version-update' },
    { id: 'mcp-version-policy', name: 'Enforce Minimum Version Policy', description: 'Block connections to MCP servers running below minimum recommended version.', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.6 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'mcp-minimum-version-required' },
  ],
  'a2a-no-auth': [
    { id: 'a2a-require-auth', name: 'Require Authentication', description: 'Enforce WID token authentication for all A2A agent-to-agent task delegations', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' }, template_id: 'a2a-authentication-required' },
    { id: 'a2a-delegator', name: 'Require Human Delegator', description: 'AI agents can only accept tasks with a verified human delegator in the token chain', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['delegation-chain-available'], effort: 'days', automated: true }, operational: { implementation: 4, ongoing_toil: 1, expertise: 'medium' }, template_id: 'agent-must-have-delegator' },
  ],
  'a2a-unsigned-card': [
    { id: 'require-signed-card', name: 'Require Signed Agent Cards', description: 'All A2A Agent Cards must be signed with JWS for authenticity verification', action_type: 'harden', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.5 }, feasibility: { preconditions: ['jws-signing-available'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' }, template_id: 'a2a-agent-card-signing' },
  ],
  'mcp-capability-drift': [
    { id: 'mcp-drift-investigate', name: 'Investigate Capability Change', description: 'MCP server capabilities changed since last scan. Investigate whether the change was authorized.', action_type: 'investigate', remediation_type: 'process', path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.5 }, feasibility: { preconditions: [], effort: 'hours', automated: false }, operational: { implementation: 3, ongoing_toil: 2, expertise: 'medium' }, template_id: null },
    { id: 'mcp-drift-pin-version', name: 'Pin MCP Server Version', description: 'Pin the MCP server to a specific known-good version to prevent unauthorized capability changes.', action_type: 'harden', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.7 }, feasibility: { preconditions: [], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 1, expertise: 'low' }, template_id: 'mcp-integrity-verification' },
  ],
  'a2a-invalid-signature': [
    { id: 'a2a-investigate-invalid-sig', name: 'Investigate Tampered Card', description: 'Agent Card signature is invalid — card content may have been tampered with.', action_type: 'investigate', remediation_type: 'process', path_break: { edge_position: 'entry', edges_severed: 0, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: [], effort: 'hours', automated: false }, operational: { implementation: 3, ongoing_toil: 1, expertise: 'medium' }, template_id: null },
    { id: 'a2a-block-invalid-sig', name: 'Block Invalid Signatures', description: 'Deploy policy to deny task delegation to agents with invalid signatures.', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'a2a-agent-card-signing' },
  ],
  'shared-sa': [
    { id: 'dedicated-sa', name: 'Assign Dedicated Service Account', description: 'Replace shared service account with per-workload dedicated SAs with least-privilege roles', action_type: 'architecture', remediation_type: 'iac', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: [], effort: 'days', automated: false }, operational: { implementation: 5, ongoing_toil: 1, expertise: 'medium' }, template_id: 'shared-service-account-deny' },
    { id: 'workload-identity-federation', name: 'Migrate to Workload Identity Federation', description: 'Use GCP Workload Identity Federation to eliminate service account keys entirely', action_type: 'replace', remediation_type: 'iac', path_break: { edge_position: 'entry', edges_severed: 3, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['gcp-project-access'], effort: 'days', automated: true }, operational: { implementation: 4, ongoing_toil: 0, expertise: 'medium' }, template_id: 'env-credential-isolation' },
  ],
  'key-leak': [
    { id: 'rotate-leaked-key', name: 'Rotate Leaked Credential', description: 'Immediately rotate the compromised key and revoke old credentials', action_type: 'remediate', remediation_type: 'iac', path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: [], effort: 'hours', automated: true }, operational: { implementation: 1, ongoing_toil: 0, expertise: 'low' }, template_id: 'credential-rotation-overdue' },
    { id: 'ban-user-managed-keys', name: 'Ban User-Managed Keys', description: 'Enforce policy that no user-managed service account keys are allowed — use Workload Identity instead', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' }, template_id: 'user-managed-key-prohibition' },
  ],
  'over-privileged': [
    { id: 'remove-wildcards', name: 'Remove Wildcard Permissions', description: 'Replace wildcard (*) IAM bindings with specific, least-privilege roles', action_type: 'harden', remediation_type: 'iac', path_break: { edge_position: 'resource', edges_severed: 0, crown_jewel_proximity: 0.8 }, feasibility: { preconditions: [], effort: 'days', automated: false }, operational: { implementation: 5, ongoing_toil: 2, expertise: 'medium' }, template_id: 'no-wildcard-permissions' },
    { id: 'crypto-attest-for-admin', name: 'Require Cryptographic Attestation for Admin', description: 'Admin-level access requires cryptographic workload attestation (SPIRE mTLS)', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true }, operational: { implementation: 3, ongoing_toil: 0, expertise: 'medium' }, template_id: 'admin-requires-crypto' },
  ],
  'public-internal-pivot': [
    { id: 'network-segmentation', name: 'Enforce Network Segmentation', description: 'Block public-facing services from reaching internal services directly — require gateway intermediary', action_type: 'architecture', remediation_type: 'infra', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: [], effort: 'days', automated: true }, operational: { implementation: 5, ongoing_toil: 1, expertise: 'medium' }, template_id: 'internal-service-isolation' },
    { id: 'zero-trust-identity', name: 'Zero Trust Identity Verification', description: 'Every internal service call requires WID token verification — no implicit trust based on network', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['spire-available'], effort: 'hours', automated: true }, operational: { implementation: 3, ongoing_toil: 0, expertise: 'low' }, template_id: 'weak-trust-in-prod' },
  ],
  'blended-identity-no-delegator': [
    { id: 'require-human-delegator', name: 'Require Human Delegator', description: 'AI agents must have a verified human delegator in the OBO token chain — no autonomous access to external services', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'entry', edges_severed: 2, crown_jewel_proximity: 1.0 }, feasibility: { preconditions: ['delegation-chain-available'], effort: 'days', automated: true }, operational: { implementation: 4, ongoing_toil: 1, expertise: 'medium' }, template_id: 'agent-must-have-delegator' },
    { id: 'scope-narrowing', name: 'Enforce Scope Narrowing', description: 'Each delegation hop must narrow scopes — agent cannot exceed delegator entitlements', action_type: 'policy', remediation_type: 'policy', path_break: { edge_position: 'credential', edges_severed: 1, crown_jewel_proximity: 0.9 }, feasibility: { preconditions: ['policy-engine-deployed'], effort: 'hours', automated: true }, operational: { implementation: 2, ongoing_toil: 0, expertise: 'low' }, template_id: 'obo-scope-must-narrow' },
    { id: 'blended-identity-attestation', name: 'Attest Blended Identity', description: 'Require cryptographic attestation of both the human principal and the agent identity before issuing blended tokens', action_type: 'harden', remediation_type: 'code_change', path_break: { edge_position: 'entry', edges_severed: 1, crown_jewel_proximity: 0.85 }, feasibility: { preconditions: ['spire-available', 'sso-provider'], effort: 'days', automated: true }, operational: { implementation: 5, ongoing_toil: 1, expertise: 'high' }, template_id: 'obo-human-root-required' },
  ],
};

const FINDING_LABELS_FALLBACK = {
  'static-external-credential': 'Static External Credential',
  'toxic-combo': 'Toxic Combination',
  'mcp-static-credentials': 'MCP Static Credentials',
  'a2a-no-auth': 'A2A No Authentication',
  'a2a-unsigned-card': 'A2A Unsigned Agent Card',
  'shared-sa': 'Shared Service Account',
  'key-leak': 'Key Leak',
  'over-privileged': 'Over-Privileged',
  'public-internal-pivot': 'Public-to-Internal Pivot',
  'blended-identity-no-delegator': 'Blended Identity (No Delegator)',
  'unbounded-admin': 'Admin Without Guardrails',
  'zombie-workload': 'Zombie Workload',
  'rogue-workload': 'Rogue Workload',
  'unused-iam-role': 'Unused IAM Role',
  'public-exposure-untagged': 'Public Exposure (Untagged)',
  'orphaned-asset': 'Orphaned Asset',
  'account-outside-org': 'Account Outside Organization',
  'public-data-exposure': 'Public Data Exposure',
  'mcp-tool-poisoning': 'MCP Tool Poisoning',
  'mcp-unverified-server': 'Unverified MCP Server',
  'mcp-outdated-version': 'Outdated MCP Server',
  'mcp-capability-drift': 'MCP Capability Drift',
  'a2a-invalid-signature': 'A2A Invalid Signature',
};

const FINDING_DESCRIPTIONS_FALLBACK = {
  'static-external-credential': 'Hardcoded API keys or secrets stored in env vars instead of a secret manager. Rotate and migrate to vault.',
  'toxic-combo': 'Identity has dangerous permission combinations (e.g., admin + no MFA + static credentials). Reduce scope or add guardrails.',
  'mcp-static-credentials': 'MCP server using static API keys. Replace with short-lived SPIFFE-bound tokens.',
  'a2a-no-auth': 'Agent-to-agent communication without mutual authentication. Enable mTLS or token-based auth.',
  'a2a-unsigned-card': 'A2A agent card not cryptographically signed. Require signed agent cards for trust.',
  'shared-sa': 'Multiple workloads sharing one service account. Create dedicated SAs per workload.',
  'key-leak': 'Credential exposed in logs, repos, or public endpoints. Revoke immediately and rotate.',
  'over-privileged': 'Identity has broader permissions than needed. Apply least-privilege scoping.',
  'public-internal-pivot': 'Public-facing service can reach internal resources. Add network segmentation.',
  'blended-identity-no-delegator': 'Blended human+agent identity without delegation chain. Require OBO token with human root.',
  'unbounded-admin': 'Admin identity with no permission boundary. Any compromised credential has unlimited blast radius. Apply a permission boundary to cap maximum permissions.',
  'zombie-workload': 'Identity inactive for 90+ days but still has active credentials. Quarantine or decommission to reduce attack surface.',
  'rogue-workload': 'Identity bypassing governance controls \u2014 cross-account trust without ExternalId, wildcard trust, or unapproved public exposure.',
  'unused-iam-role': 'IAM role/user with no recent activity. Detach permissions or schedule for deletion.',
  'public-exposure-untagged': 'Resource is publicly accessible without an explicit security team approval tag. Restrict access or add approved-public tag.',
  'orphaned-asset': 'Identity with no relationships in the graph \u2014 no consumers, no credentials, no policies. Assign an owner or decommission.',
  'account-outside-org': 'Cross-account trust to an account not in the organization allow-list. Verify account ownership.',
  'public-data-exposure': 'Storage bucket or database publicly accessible. Enable access blocks and encryption.',
  'mcp-tool-poisoning': 'MCP server tool descriptions contain hidden instructions (prompt injection, exfiltration, or unauthorized actions). Disconnect immediately and audit invocations.',
  'mcp-unverified-server': 'MCP server package is not in the known-good registry. Cannot confirm publisher identity or integrity. Pin to a verified package.',
  'mcp-outdated-version': 'MCP server is running below the minimum recommended version. Outdated versions may have known security vulnerabilities. Update immediately.',
  'mcp-capability-drift': 'MCP server capabilities changed since last scan — tools added, removed, or descriptions modified. Investigate for supply-chain tampering.',
  'a2a-invalid-signature': 'A2A Agent Card has an invalid cryptographic signature. Card may have been tampered with. Investigate immediately.',
};

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Module-level finding type metadata cache — populated from API, used by all components
// Prefer API data, fallback to hardcoded FINDING_LABELS_FALLBACK / FINDING_DESCRIPTIONS_FALLBACK
let _findingMetaCache = { labels: {}, descriptions: {} };
const FL = (ft) => _findingMetaCache.labels[ft] || FINDING_LABELS_FALLBACK[ft] || ft.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
const FD = (ft) => _findingMetaCache.descriptions[ft] || FINDING_DESCRIPTIONS_FALLBACK[ft] || '';

// ── Node detail constants & helpers (module-level, before all components) ──
const PHASE_META = {
  containment: { label: 'Quick Containment', color: '#10b981', desc: 'Low risk · hours–days · Safe to deploy now' },
  hardening:   { label: 'Hardening',          color: '#f59e0b', desc: 'Medium complexity · days · Attestation-gated' },
  structural:  { label: 'Structural Fix',      color: '#ef4444', desc: 'Architectural change · weeks · Requires design review' },
};

const ACTION_COLOR = {
  policy: '#7c6ff0', replace: '#3b82f6', remediate: '#10b981', harden: '#f59e0b', architecture: '#f97316',
  contain: '#ef4444', notify: '#8b5cf6', escalate: '#ef4444', decommission: '#ef4444', investigate: '#60a5fa',
};

const TYPE_ICONS_ND = {
  'cloud-run': '☁️', 'service-account': '🔑', 'external-resource': '🔗',
  'exposure': '🌐', credential: '🗝️', 'a2a-agent': '🤖', 'mcp-server': '🔌',
  identity: '🪪', resource: '🗃️',
};

function ndChip(text, color, size = 9) {
  return (
    <span style={{
      fontSize: size, fontWeight: 700, padding: '2px 6px', borderRadius: 3,
      background: color + '18', color, border: `1px solid ${color}28`,
      fontFamily: 'monospace', letterSpacing: '0.04em', whiteSpace: 'nowrap',
    }}>{text}</span>
  );
}

function ndLabel(text) {
  return (
    <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.12em', textTransform: 'uppercase', color: '#6a6a7a', marginBottom: 5, fontFamily: 'monospace' }}>{text}</div>
  );
}

function ndRow(label, value, color = '#bbb') {
  return (
    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
      <span style={{ fontSize: 10, color: '#777', fontFamily: 'monospace' }}>{label}</span>
      <span style={{ fontSize: 10, color, fontFamily: 'monospace', maxWidth: 180, textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{value}</span>
    </div>
  );
}

function scoreControl(ctrl, blastRadius, hasCrownJewel) {
  const pb = ctrl.path_break || {};
  // Support both backend field names (edge_position/edges_severed/crown_jewel_proximity) 
  // and any legacy names (position/severed/crown)
  const pos    = pb.edge_position || pb.position || 'credential';
  const severed = pb.edges_severed ?? pb.severed ?? 0;
  const crown  = pb.crown_jewel_proximity ?? pb.crown ?? 0.5;
  const op     = ctrl.operational || {};

  const posScore   = pos === 'entry' ? 100 : pos === 'credential' ? 70 : 40;
  const sevScore   = Math.min(severed * 35, 100);
  const crownScore = crown * (hasCrownJewel ? 100 : 50);
  const pathBreak  = Math.round(posScore * 0.4 + sevScore * 0.3 + crownScore * 0.3);

  // Effort from feasibility.effort (backend) or ctrl.effort (legacy)
  const effort = ctrl.feasibility?.effort || ctrl.effort || 'days';
  const effortScore = { hours: 90, days: 55, weeks: 20 }[effort] || 50;

  // Operational cost from backend fields
  const implScore = op.implementation ? Math.max(0, 100 - (op.implementation - 1) * 12) : effortScore;
  const opScore   = op.implementation
    ? (implScore * 0.5 + (op.ongoing_toil !== undefined ? Math.max(0, 100 - op.ongoing_toil * 25) : 75) * 0.25 + ({ low: 100, medium: 60, high: 25 }[op.expertise] || 50) * 0.25)
    : effortScore;

  const typeConf = { policy: 90, replace: 80, harden: 70, remediate: 85, architecture: 55 }[ctrl.action_type] || 70;
  const blastScore = Math.max(0, 100 - (blastRadius || 1) * 6);
  const composite  = Math.round(pathBreak * 0.40 + blastScore * 0.20 + opScore * 0.20 + typeConf * 0.20);
  return { composite, path_break: pathBreak, blast_radius: blastScore, cost: Math.round(opScore), confidence: typeConf };
}

function enrichAttackPath(ap, nodes, rels) {
  // Map raw finding_type OR title string → catalog key
  const TITLE_TO_KEY = {
    'shared-sa': 'shared-sa', 'shared sa': 'shared-sa', 'shared service account': 'shared-sa',
    'static-external-credential': 'static-external-credential', 'static external': 'static-external-credential', 'static credential': 'static-external-credential',
    'toxic-combo': 'toxic-combo', 'toxic combo': 'toxic-combo',
    'mcp-static-credentials': 'mcp-static-credentials', 'mcp static': 'mcp-static-credentials',
    'a2a-no-auth': 'a2a-no-auth', 'a2a no auth': 'a2a-no-auth', 'no auth': 'a2a-no-auth',
    'a2a-unsigned-card': 'a2a-unsigned-card', 'unsigned card': 'a2a-unsigned-card',
    'key-leak': 'key-leak', 'key leak': 'key-leak', 'leaked key': 'key-leak',
    'over-privileged': 'over-privileged', 'over privileged': 'over-privileged', 'overprivileged': 'over-privileged',
    'public-internal-pivot': 'public-internal-pivot', 'public internal': 'public-internal-pivot',
  };
  const rawType = (ap.finding_type || ap.type || '').toLowerCase().replace(/_/g, '-');
  const rawTitle = (ap.title || '').toLowerCase().replace(/_/g, '-');
  // Try exact match first, then prefix match from title
  let ft = TITLE_TO_KEY[rawType] || TITLE_TO_KEY[rawTitle] || rawType;
  // Fallback: check if any catalog key appears as substring of the title
  if (!CONTROL_CATALOG_FALLBACK[ft]) {
    for (const key of Object.keys(CONTROL_CATALOG_FALLBACK)) {
      if (rawTitle.includes(key.replace(/-/g, ' ')) || rawTitle.includes(key)) { ft = key; break; }
    }
  }
  const wName = (ap.workload || '').toLowerCase();

  // Compute blast radius from graph topology — directional traversal along trust propagation
  // runs-as edges go SA→workload; blast flows workload→SA (reverse). shares-identity excluded.
  const BLAST_EDGE_TYPES = new Set([
    'runs-as', 'has-role', 'grants-access',
    'holds-credential', 'accesses-api', 'can-delegate-to',
  ]);
  const WORKLOAD_TYPES = new Set([
    'cloud-run', 'cloud-run-service', 'a2a-agent', 'mcp-server',
    'lambda', 'ec2', 'container', 'pod', 'workload',
  ]);
  const connected = new Set();
  const affectedWorkloads = [];
  for (const n of nodes) {
    if ((n.label || '').toLowerCase().includes(wName) && wName) connected.add(n.id);
  }
  const queue = [...connected]; const visited = new Set(queue);
  while (queue.length > 0) {
    const c = queue.shift();
    for (const r of rels) {
      if (!BLAST_EDGE_TYPES.has(r.type)) continue;
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      if (r.type === 'runs-as') {
        // runs-as: SA(source)→workload(target). Blast goes reverse: workload→SA only.
        if (t === c && !visited.has(s)) { visited.add(s); queue.push(s); connected.add(s); }
      } else {
        // All other edges: follow forward (source→target) only
        if (s === c && !visited.has(t)) { visited.add(t); queue.push(t); connected.add(t); }
      }
    }
  }
  for (const nid of connected) {
    const n = nodes.find(nd => nd.id === nid);
    if (n && WORKLOAD_TYPES.has(n.type)) {
      affectedWorkloads.push(n.label || n.id);
    }
  }
  // Prefer backend blast_radius (already workload-filtered); fallback to local workload count
  const blastRadius = ap.blast_radius || affectedWorkloads.length || 1;
  const hasCrownJewel = nodes.some(n => connected.has(n.id) && (n.type === 'external-resource' || n.workload_type === 'external-resource'));

  // Credential chain: identity → credential → resource
  const chain = [];
  const identityNode = nodes.find(n => (n.label || '').toLowerCase() === wName && (n.type === 'workload' || n.type === 'a2a-agent' || n.type === 'mcp-server'));
  if (identityNode) {
    chain.push({ id: identityNode.id, label: identityNode.label, type: 'identity' });
    for (const r of rels) {
      const s = typeof r.source === 'object' ? r.source.id : r.source;
      const t = typeof r.target === 'object' ? r.target.id : r.target;
      if (s === identityNode.id && r.type === 'holds-credential') {
        const credNode = nodes.find(n => n.id === t);
        if (credNode) {
          chain.push({ id: credNode.id, label: credNode.label, type: 'credential' });
          for (const r2 of rels) {
            const s2 = typeof r2.source === 'object' ? r2.source.id : r2.source;
            const t2 = typeof r2.target === 'object' ? r2.target.id : r2.target;
            if (s2 === credNode.id && r2.type === 'accesses-api') {
              const resNode = nodes.find(n => n.id === t2);
              if (resNode) chain.push({ id: resNode.id, label: resNode.label, type: 'resource' });
            }
          }
        }
      }
    }
  }

  // Score controls — assign phase and derive kills_edges using correct backend field names
  const PHASE_MAP = { replace: 'containment', remediate: 'containment', contain: 'containment', escalate: 'containment', policy: 'hardening', harden: 'hardening', notify: 'hardening', investigate: 'hardening', architecture: 'structural', decommission: 'structural' };
  const candidates = CONTROL_CATALOG_FALLBACK[ft] || [];
  const scoredControls = candidates.map(c => ({
    ...c,
    phase: c.phase || PHASE_MAP[c.action_type] || 'hardening',
    feasibility: c.feasibility || { preconditions: [], automated: c.action_type === 'policy' },
    kills_edges: c.kills_edges || ((c.path_break?.edges_severed ?? c.path_break?.severed ?? 0) > 0
      ? [`${c.path_break.edge_position || c.path_break.position || 'entry'}-access`] : []),
    score: scoreControl(c, blastRadius, hasCrownJewel),
    cloud_provider: ap.cloud_provider || 'gcp',
  })).sort((a, b) => b.score.composite - a.score.composite);

  // Use backend ranked_controls only if they have real data (name + score), otherwise use catalog
  const PHASE_MAP2 = { replace: 'containment', remediate: 'containment', contain: 'containment', escalate: 'containment', policy: 'hardening', harden: 'hardening', notify: 'hardening', investigate: 'hardening', architecture: 'structural', decommission: 'structural' };
  const backendControls = (ap.ranked_controls || [])
    .filter(c => c.name && c.id)
    .map(c => ({
      ...c,
      score: c.score || scoreControl(c, blastRadius, hasCrownJewel),
      phase: c.phase || PHASE_MAP2[c.action_type] || 'hardening',
      feasibility: c.feasibility || { preconditions: [], automated: c.action_type === 'policy' },
      kills_edges: c.kills_edges || ((c.path_break?.edges_severed ?? 0) > 0
        ? [`${c.path_break.edge_position || 'entry'}-access`] : []),
      cloud_provider: c.cloud_provider || ap.cloud_provider || 'gcp',
    }));
  const finalControls = backendControls.length > 0 ? backendControls : scoredControls;

  // Debug: log when catalog is used so we can verify in console
  if (scoredControls.length > 0 && backendControls.length === 0) {
    console.debug(`[enrichAttackPath] ft="${ft}" → ${scoredControls.length} catalog controls for "${ap.title || ap.workload}"`);
  } else if (candidates.length === 0) {
    console.warn(`[enrichAttackPath] No catalog entry for ft="${ft}" (raw: "${rawType}", title: "${rawTitle}")`);
  }

  return {
    ...ap,
    blast_radius: blastRadius,
    affected_workloads: ap.affected_workloads || affectedWorkloads,
    credential_chain: ap.credential_chain?.length > 0 ? ap.credential_chain : chain,
    ranked_controls: finalControls,
    _resolved_ft: ft, // expose for diagnostics
  };
}

/* ═══════════════════════════════════════════
   Main Component — Two-Pane Layout
   ═══════════════════════════════════════════ */
export default function GraphPage() {
  const navigate = useNavigate();
  const [graphData, setGraphData] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  const [activeAttackPath, setActiveAttackPath] = useState(null);
  const [timelineFilter, setTimelineFilter] = useState('all');
  const [scanning, setScanning] = useState(false);
  const [panelOpen, setPanelOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [remPath, setRemPath] = useState(null); // Phase 3: remediation view
  const [simOverlay, setSimOverlay] = useState(null); // { violatingIds: Set, compliantIds: Set }
  const [enforceOverlay, setEnforceOverlay] = useState(new Set()); // node labels with enforced controls
  const [dismissedPaths, setDismissedPaths] = useState(new Set()); // attack path ids faded out after enforce
  const [activeFilter, setActiveFilter] = useState(null); // null = show all, else filter key
  const [edgeEnforceState, setEdgeEnforceState] = useState({}); // nodeLabel → 'audit' | 'enforce'
  const [enforceLogStream, setEnforceLogStream] = useState([]); // live DENY/ALLOW log entries
  const [expandedGroups, setExpandedGroups] = useState(new Set()); // Set<finding_type>
  const [remGroup, setRemGroup] = useState(null); // finding_type for group-level remediation
  const [chokeFilter, setChokeFilter] = useState(null); // node label to filter groups by choke point
  const [showLegend, setShowLegend] = useState(false); // graph legend toggle
  const [riskFilter, setRiskFilter] = useState(null); // severity filter: null, 'critical', 'high', 'medium', 'low'
  const [panelWidth, setPanelWidth] = useState(360); // resizable panel width
  const [contextMenu, setContextMenu] = useState(null); // { x, y, node } for right-click context menu
  const [searchIndex, setSearchIndex] = useState(-1); // keyboard nav index in search results
  const [collapsedSections, setCollapsedSections] = useState({
    threatBrief: false,   // open by default — most important
    remediation: true,    // collapsed — user expands when ready
    credentials: true,    // collapsed
    resource: true,       // collapsed
    identity: true,       // collapsed
    agent: true,          // collapsed
  });
  const location = useLocation();
  const focusParam = new URLSearchParams(location.search).get('focus');
  const [focusHandled, setFocusHandled] = useState(false);

  // Fetch finding type metadata from API (DB source of truth) into module-level cache
  const [, setFindingMetaVer] = useState(0); // trigger re-render when cache updates
  useEffect(() => {
    fetch(`${API}/graph/finding-types`)
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(data => {
        const labels = {}, descriptions = {};
        for (const ft of (data.finding_types || [])) {
          labels[ft.id] = ft.label;
          descriptions[ft.id] = ft.description;
        }
        _findingMetaCache = { labels, descriptions };
        setFindingMetaVer(v => v + 1); // trigger re-render so FL/FD use new data
      })
      .catch(() => {}); // fallback to hardcoded FINDING_LABELS_FALLBACK / FINDING_DESCRIPTIONS_FALLBACK
  }, []);

  const GRAPH_FILTERS = useMemo(() => [
    { key: 'agents',     label: 'AGENTS',     color: '#ec4899', match: n => n.type === 'a2a-agent' || n.type === 'mcp-server' || n.category === 'ai-agent' || n.is_ai_agent || n.is_mcp_server },
    { key: 'shadow',     label: 'SHADOW',     color: '#f97316', match: n => n.is_shadow },
    { key: 'zombie',     label: 'ZOMBIE',     color: '#6b7280', match: n => n.is_dormant },
    { key: 'rogue',      label: 'ROGUE',      color: '#ef4444', match: n => n.is_rogue },
    { key: 'public',     label: 'PUBLIC',     color: '#eab308', match: n => n.is_publicly_exposed },
    { key: 'unused-iam', label: 'UNUSED IAM', color: '#a855f7', match: n => n.is_unused_iam },
    { key: 'orphan',     label: 'ORPHAN',     color: '#8b5cf6', match: n => n.is_orphan },
    { key: 'identity',   label: 'IDENTITY',   color: '#a78bfa', match: n => ['user','service-account','managed-identity','iam-role','iam-user','iam-group','iam-policy','spiffe-id'].includes(n.type) },
    { key: 'workload',   label: 'WORKLOAD',   color: '#3b82f6', match: n => ['container','pod','cloud-run','cloud-run-service','lambda','ec2','ecs-task','gce-instance','cloud-function'].includes(n.type) },
    { key: 'resource',   label: 'RESOURCE',   color: '#10b981', match: n => ['resource','external-resource','external-api','secret-engine','s3-bucket','rds-instance','dynamodb-table','gcs-bucket','cloud-sql','storage-account','vpc','security-group','load-balancer','kms-key','key-vault','managed-secret'].includes(n.type) },
    { key: 'credential', label: 'CREDENTIAL', color: '#f97316', match: n => ['credential','external-credential'].includes(n.type) },
  ], []);

  // Reset focusHandled whenever the ?focus param changes (new navigation from Workloads)
  const prevFocusParam = useRef(null);
  useEffect(() => {
    if (focusParam && focusParam !== prevFocusParam.current) {
      prevFocusParam.current = focusParam;
      setFocusHandled(false);
    }
  }, [focusParam]);
  const svgRef = useRef(null);
  const graphRef = useRef(null);
  const zoomRef = useRef(null);
  const edgeEnforceRef = useRef({}); // mirrors edgeEnforceState — readable by D3 without stale closures
  const nodePositionsRef = useRef({}); // cache node positions across rebuilds
  const zoomTransformRef = useRef(null); // cache zoom transform across rebuilds
  const zoomLevelRef = useRef(1); // current zoom scale for label visibility
  const minimapRef = useRef(null); // minimap canvas ref
  const prevGraphDataRef = useRef(null); // detect refresh vs initial load
  const selectedNodeRef = useRef(null); // track selected node for re-highlight after rebuild

  // ─── Fetch ───
  const fetchAll = async () => {
    try {
      const [gRes, tRes] = await Promise.all([
        fetch(`${API}/graph`).then(r => r.json()),
        fetch(`${API}/graph/timeline?limit=50`).then(r => r.json()),
      ]);
      setGraphData(gRes);
      setTimeline(tRes.timeline || []);
    } catch (e) { console.error('Failed to load graph:', e); }
    finally { setLoading(false); }
  };

  const triggerScan = async () => {
    setScanning(true);
    try { await fetch(`${API}/graph/scan`, { method: 'POST' }); await fetchAll(); }
    catch (e) { console.error(e); }
    setScanning(false);
  };

  // Auto-refresh: skip while user is mid-remediation to avoid disruptive rebuilds
  const remediatingRef = useRef(false);
  useEffect(() => { remediatingRef.current = !!(remPath || remGroup || simOverlay); }, [remPath, remGroup, simOverlay]);
  useEffect(() => {
    fetchAll();
    const iv = setInterval(() => { if (!remediatingRef.current) fetchAll(); }, 60000);
    return () => clearInterval(iv);
  }, []);

  // Expose fetchAll for child components (e.g. rollback) to trigger re-fetch
  useEffect(() => { window.__widFetchAll = fetchAll; return () => { delete window.__widFetchAll; }; }, []);

  // Dismiss context menu on Escape
  useEffect(() => {
    if (!contextMenu) return;
    const handler = (e) => { if (e.key === 'Escape') setContextMenu(null); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [contextMenu]);

  // Keep selectedNodeRef in sync for D3 rebuild re-highlight
  useEffect(() => { selectedNodeRef.current = selectedNode; }, [selectedNode]);

  // ─── Auto-restore enforce state from backend remediation data ───
  // NOTE: We restore visual overlays (green rings, edge state) but do NOT auto-dismiss
  // attack paths. All paths always show in the right panel — enforced ones get a badge.
  useEffect(() => {
    if (!graphData?.attack_paths) return;
    const restoredOverlay = new Set();
    const restoredEdgeState = {};

    for (const ap of graphData.attack_paths) {
      if (!ap.remediation) continue;
      const status = ap.remediation.status; // 'enforced' or 'audit'
      if (status !== 'enforced' && status !== 'audit') continue;

      const nodeLabel = ap.workload || '';
      if (!nodeLabel) continue;

      restoredOverlay.add(nodeLabel);
      for (const w of (ap.affected_workloads || [])) restoredOverlay.add(w);
      for (const n of (ap.credential_chain || [])) {
        if (n.label) restoredOverlay.add(n.label);
      }

      restoredEdgeState[nodeLabel] = status === 'enforced' ? 'enforce' : 'audit';
    }

    if (restoredOverlay.size > 0) {
      setEnforceOverlay(prev => {
        const merged = new Set([...prev, ...restoredOverlay]);
        return merged.size === prev.size ? prev : merged;
      });
      setEdgeEnforceState(prev => {
        const merged = { ...prev, ...restoredEdgeState };
        return JSON.stringify(merged) === JSON.stringify(prev) ? prev : merged;
      });
    }
  }, [graphData]);


  const zoomFit = useCallback(() => {
    if (!zoomRef.current || !svgRef.current) return;
    d3.select(svgRef.current).transition().duration(400).call(zoomRef.current.transform, d3.zoomIdentity);
  }, []);
  const zoomIn = useCallback(() => {
    if (!zoomRef.current || !svgRef.current) return;
    d3.select(svgRef.current).transition().duration(200).call(zoomRef.current.scaleBy, 1.4);
  }, []);
  const zoomOut = useCallback(() => {
    if (!zoomRef.current || !svgRef.current) return;
    d3.select(svgRef.current).transition().duration(200).call(zoomRef.current.scaleBy, 0.7);
  }, []);

  // ─── D3 Graph ───
  useEffect(() => {
    if (!graphData?.nodes?.length || !svgRef.current) return;

    // Detect refresh vs initial load
    const isRefresh = prevGraphDataRef.current !== null;
    prevGraphDataRef.current = graphData;

    // Save current node positions and zoom before rebuild
    if (isRefresh && graphRef.current?.nodes) {
      const posMap = {};
      for (const n of graphRef.current.nodes) {
        if (isFinite(n.x) && isFinite(n.y)) posMap[n.id] = { x: n.x, y: n.y };
      }
      nodePositionsRef.current = posMap;
    }
    // Save zoom transform
    if (isRefresh && svgRef.current && zoomRef.current) {
      const currentTransform = d3.zoomTransform(svgRef.current);
      if (currentTransform.k !== 1 || currentTransform.x !== 0 || currentTransform.y !== 0) {
        zoomTransformRef.current = currentTransform;
      }
    }

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();
    const container = svgRef.current.parentElement;
    const width = container.clientWidth || 900;
    const height = container.clientHeight || 600;
    svg.attr('viewBox', `0 0 ${width} ${height}`);
    // SVG filter for selected node glow effect
    const defs = svg.append('defs');
    const glowFilter = defs.append('filter').attr('id', 'selectedGlow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
    glowFilter.append('feFlood').attr('flood-color', '#a78bfa').attr('flood-opacity', '0.6').attr('result', 'color');
    glowFilter.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
    const glowMerge = glowFilter.append('feMerge');
    glowMerge.append('feMergeNode').attr('in', 'glow');
    glowMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    const g = svg.append('g');
    const zoom = d3.zoom().scaleExtent([0.2, 5]).on('zoom', (e) => {
      g.attr('transform', e.transform);
      zoomTransformRef.current = e.transform;
      const k = e.transform.k;
      zoomLevelRef.current = k;
      // Zoom-dependent label visibility
      g.selectAll('text.node-label')
        .attr('opacity', k > 0.6 ? 1 : 0)
        .attr('font-size', k > 1.2 ? '9px' : '8px');
    });
    svg.call(zoom);
    zoomRef.current = zoom;

    // Restore zoom transform on refresh, auto-fit on initial
    if (isRefresh && zoomTransformRef.current) {
      svg.call(zoom.transform, zoomTransformRef.current);
    } else {
      // Auto-fit on initial load
      setTimeout(() => {
        if (!graphRef.current) return;
        const ns = graphRef.current.nodes;
        if (!ns?.length) return;
        const xs = ns.map(n => n.x), ys = ns.map(n => n.y);
        const [xMin, xMax] = [Math.min(...xs) - 40, Math.max(...xs) + 40];
        const [yMin, yMax] = [Math.min(...ys) - 40, Math.max(...ys) + 40];
        const scale = Math.min(width / (xMax - xMin), height / (yMax - yMin), 1.5) * 0.85;
        const tx = (width - (xMax - xMin) * scale) / 2 - xMin * scale;
        const ty = (height - (yMax - yMin) * scale) / 2 - yMin * scale;
        svg.transition().duration(800).call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
      }, 1500);
    }

    const gc = {
      identity: { x: width * 0.15, y: height * 0.35 }, workload: { x: width * 0.45, y: height * 0.30 },
      permission: { x: width * 0.25, y: height * 0.70 }, resource: { x: width * 0.65, y: height * 0.72 },
      exposure: { x: width * 0.80, y: height * 0.25 }, credential: { x: width * 0.08, y: height * 0.65 },
      cluster: { x: width * 0.50, y: height * 0.12 },
    };
    const nodes = graphData.nodes.map(d => {
      // Restore saved positions on refresh
      const saved = nodePositionsRef.current[d.id];
      if (isRefresh && saved) return { ...d, x: saved.x, y: saved.y };
      return { ...d };
    });
    const links = graphData.relationships.map(d => ({ ...d }));

    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(70).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => {
        const r = vis(d.type, d).r;
        return r < 14 ? r + 6 : r + 12;
      }))
      .force('gx', d3.forceX(d => gc[d.group]?.x || width / 2).strength(0.12))
      .force('gy', d3.forceY(d => gc[d.group]?.y || height / 2).strength(0.12));

    // Low alpha on refresh so nodes barely move; full alpha on initial
    if (isRefresh) sim.alpha(0.1).alphaDecay(0.05);

    const linkG = g.append('g');
    const link = linkG.selectAll('line').data(links).join('line')
      .attr('stroke', d => d.critical ? 'rgba(239,68,68,0.25)' : 'rgba(255,255,255,0.07)')
      .attr('stroke-width', d => d.critical ? 2 : 0.7)
      .attr('stroke-dasharray', d => d.type === 'grants-access' ? '4,3' : d.type === 'exposed-via' ? '2,2' : 'none');

    const edgeLabel = linkG.selectAll('text').data(links.filter(l => l.critical)).join('text')
      .text(d => d.type?.replace(/-/g, ' ')).attr('text-anchor', 'middle')
      .attr('fill', 'rgba(239,68,68,0.35)').attr('font-size', '6px').attr('font-family', 'monospace').attr('pointer-events', 'none');

    const node = g.append('g').selectAll('g').data(nodes).join('g').attr('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

    node.append('circle').attr('r', d => vis(d.type, d).r).attr('fill', d => `${vis(d.type, d).color}12`)
      .attr('stroke', d => vis(d.type, d).color).attr('stroke-width', 1.5).attr('class', 'gnode');
    node.filter(d => d.trust && d.trust !== 'none').append('circle')
      .attr('r', d => vis(d.type, d).r + 4).attr('fill', 'none')
      .attr('stroke', d => TRUST_COLORS[d.trust] || '#666').attr('stroke-width', 1).attr('stroke-dasharray', '2,2').attr('opacity', 0.4);
    node.append('text').text(d => vis(d.type, d).icon).attr('text-anchor', 'middle').attr('dy', 5)
      .attr('font-size', d => Math.max(9, vis(d.type, d).r * 0.6)).attr('pointer-events', 'none');
    node.append('text').text(d => d.label?.length > 22 ? d.label.slice(0, 20) + '..' : d.label)
      .attr('class', 'node-label')
      .attr('dy', d => vis(d.type, d).r + 12).attr('text-anchor', 'middle')
      .attr('fill', '#c0c0cc').attr('font-size', '8px').attr('font-family', 'monospace').attr('pointer-events', 'none');

    node.on('click', (e, d) => {
      e.stopPropagation();
      // Inject attack_paths that reference this node (by workload name or entry_point)
      const nodeLabel = (d.label || '').toLowerCase();
      const relatedPaths = (graphData?.attack_paths || []).filter(ap =>
        (ap.workload || '').toLowerCase() === nodeLabel ||
        (ap.entry_points || []).some(ep => ep.toLowerCase() === nodeLabel) ||
        (ap.affected_workloads || []).some(w => w.toLowerCase() === nodeLabel)
      ).map(ap => enrichAttackPath(ap, graphData?.nodes || [], graphData?.relationships || []));
      setSelectedNode({ ...d, attack_paths: relatedPaths });
      setActiveAttackPath(null); setRemPath(null); setRemGroup(null);
      if (!panelOpen) setPanelOpen(true);
      hlNode(d.id, node, link, links);
    });
    node.on('contextmenu', (e, d) => {
      e.preventDefault();
      setContextMenu({ x: e.pageX, y: e.pageY, node: d });
    });
    svg.on('click', () => { setSelectedNode(null); setActiveAttackPath(null); setContextMenu(null); resetHL(node, link); });

    graphRef.current = { node, link, links, nodes };

    // Expose re-apply function so enforce/edge useEffects can call it after graph rebuild
    graphRef.current.applyEnforceOverlay = (overlay, edgeState) => {
      if (!overlay || overlay.size === 0) return;
      node.each(function(d) {
        const isEnforced = overlay.has(d.id) || overlay.has(d.label);
        if (!isEnforced) return;
        // Determine if this node is in audit or enforce mode
        const nodeState = edgeState?.[d.label] || edgeState?.[d.id] || 'enforce';
        const isAudit = nodeState === 'audit';
        const ringColor = isAudit ? '#f59e0b' : '#10b981';
        const fillColor = isAudit ? 'rgba(245,158,11,0.10)' : 'rgba(16,185,129,0.12)';
        const g = d3.select(this);
        g.selectAll('.enforce-ring').remove();
        g.selectAll('.enforce-icon').remove();
        const r = vis(d.type, d).r;
        g.insert('circle', ':first-child')
          .attr('class', 'enforce-ring')
          .attr('r', r + 7).attr('fill', 'none')
          .attr('stroke', ringColor).attr('stroke-width', 2)
          .attr('stroke-dasharray', isAudit ? '4,2' : '3,2').attr('opacity', 0.8);
        g.append('text').attr('class', 'enforce-icon')
          .text(isAudit ? '\u26A1' : '\uD83D\uDEE1').attr('text-anchor', 'middle')
          .attr('dy', -(r + 2)).attr('font-size', '10px')
          .attr('pointer-events', 'none').attr('opacity', 1);
        g.select('circle.gnode')
          .attr('stroke', ringColor).attr('stroke-width', 2.5)
          .attr('fill', fillColor);
      });
      // Edge state: audit=amber-dashed+⚡, enforce=severed-gray-dashed+✂
      // After D3 force layout, d.source/d.target are node objects; check label, id, and name
      if (edgeState && Object.keys(edgeState).length > 0) {
        let edgesChanged = 0;
        const markerData = [];
        link.each(function(d) {
          // D3 replaces source/target string IDs with node objects after simulation starts
          const src = d.source, tgt = d.target;
          const srcLabel = (typeof src === 'object' ? (src.label || src.id || src.name || '') : (src || ''));
          const tgtLabel = (typeof tgt === 'object' ? (tgt.label || tgt.id || tgt.name || '') : (tgt || ''));
          const state = edgeState[srcLabel] || edgeState[tgtLabel];
          if (!state) return;
          const el = d3.select(this);
          if (state === 'enforce') {
            el.attr('stroke', 'rgba(107,114,128,0.5)').attr('stroke-dasharray', '6,4').attr('stroke-width', 1.2).attr('opacity', 0.5);
            markerData.push({ ...d, _markerType: 'enforce' });
            edgesChanged++;
          } else if (state === 'audit') {
            el.attr('stroke', 'rgba(245,158,11,0.6)').attr('stroke-dasharray', '4,2').attr('stroke-width', 1.4).attr('opacity', 0.75);
            markerData.push({ ...d, _markerType: 'audit' });
            edgesChanged++;
          }
        });
        // Add ✂ / ⚡ midpoint markers on affected edges
        linkG.selectAll('.edge-marker').remove();
        if (markerData.length > 0) {
          linkG.selectAll('.edge-marker').data(markerData).join('text')
            .attr('class', 'edge-marker')
            .text(d => d._markerType === 'enforce' ? '\u2702' : '\u26A1')
            .attr('font-size', '10px')
            .attr('text-anchor', 'middle').attr('dominant-baseline', 'central')
            .attr('fill', d => d._markerType === 'enforce' ? 'rgba(107,114,128,0.7)' : 'rgba(245,158,11,0.8)')
            .attr('pointer-events', 'none')
            .attr('x', d => {
              const sx = typeof d.source === 'object' ? (d.source.x || 0) : 0;
              const tx = typeof d.target === 'object' ? (d.target.x || 0) : 0;
              return (sx + tx) / 2;
            })
            .attr('y', d => {
              const sy = typeof d.source === 'object' ? (d.source.y || 0) : 0;
              const ty = typeof d.target === 'object' ? (d.target.y || 0) : 0;
              return (sy + ty) / 2;
            });
        }
        if (edgesChanged > 0) {
          console.debug(`[enforceOverlay] Updated ${edgesChanged} edges with markers`);
        }
      }
      // Dim credential nodes connected to enforced nodes to 40% opacity
      if (overlay && overlay.size > 0) {
        node.each(function(d) {
          const isCredNode = d.type === 'credential' || d.group === 'credential' ||
            /(_KEY|_TOKEN|_SECRET|_PASSWORD|_API_KEY)$/i.test(d.label || '');
          if (!isCredNode) return;
          const connectedToEnforced = links.some(l => {
            const s = typeof l.source === 'object' ? l.source : { id: l.source };
            const t = typeof l.target === 'object' ? l.target : { id: l.target };
            return ((s.id === d.id || s.label === d.label) && (overlay.has(t.id) || overlay.has(t.label))) ||
                   ((t.id === d.id || t.label === d.label) && (overlay.has(s.id) || overlay.has(s.label)));
          });
          if (connectedToEnforced) {
            d3.select(this).attr('opacity', 0.4);
          }
        });
      }
    };
    // Re-apply immediately if overlays already exist (graph rebuild case)
    // Will be called by useEffect below once graphRef is ready

    // Re-highlight selected node after refresh rebuild
    if (isRefresh && selectedNodeRef.current) {
      setTimeout(() => {
        if (graphRef.current) {
          hlNode(selectedNodeRef.current.id, graphRef.current.node, graphRef.current.link, graphRef.current.links);
        }
      }, 150);
    }

    // Fire focus once positions are stable (after enough ticks)
    // This is the only reliable trigger — timeouts race against variable simulation time
    let tickCount = 0;
    const FOCUS_TICK = isRefresh ? 5 : 30; // on refresh, positions are already set
    sim.on('tick', () => {
      const gx = d => isFinite(d.source.x) ? d.source.x : 0;
      const gy = d => isFinite(d.source.y) ? d.source.y : 0;
      const gx2 = d => isFinite(d.target.x) ? d.target.x : 0;
      const gy2 = d => isFinite(d.target.y) ? d.target.y : 0;
      link.attr('x1', gx).attr('y1', gy).attr('x2', gx2).attr('y2', gy2);
      edgeLabel.attr('x', d => ((isFinite(d.source.x) ? d.source.x : 0) + (isFinite(d.target.x) ? d.target.x : 0)) / 2)
               .attr('y', d => ((isFinite(d.source.y) ? d.source.y : 0) + (isFinite(d.target.y) ? d.target.y : 0)) / 2);
      // Update ✂/⚡ edge markers position
      linkG.selectAll('.edge-marker')
        .attr('x', d => ((isFinite(d.source.x) ? d.source.x : 0) + (isFinite(d.target.x) ? d.target.x : 0)) / 2)
        .attr('y', d => ((isFinite(d.source.y) ? d.source.y : 0) + (isFinite(d.target.y) ? d.target.y : 0)) / 2);
      node.attr('transform', d => `translate(${isFinite(d.x) ? d.x : 0},${isFinite(d.y) ? d.y : 0})`);
      tickCount++;
      // Signal focus effect that positions are ready
      if (tickCount === FOCUS_TICK) {
        graphRef.current.positionsReady = true;
        graphRef.current.onPositionsReady?.();
      }
    });
    return () => sim.stop();
  }, [graphData]); // eslint-disable-line react-hooks/exhaustive-deps

  // ─── Auto-focus node from URL param (?focus=node-name) ───
  // Uses useLocation() so re-fires on every navigation, even when graphData is cached.
  // Waits for D3 positions via onPositionsReady callback (set after FOCUS_TICK ticks).
  useEffect(() => {
    if (focusHandled || !focusParam || !graphData?.nodes) return;

    const applyFocus = () => {
      if (!graphRef.current) return false;
      const q = decodeURIComponent(focusParam).toLowerCase();
      const allNodes = graphRef.current.nodes;
      const allRels = graphData.relationships || [];

      // Find the target node — exact match first, then partial
      const targetNode =
        allNodes.find(n =>
          (n.label || '').toLowerCase() === q ||
          (n.name  || '').toLowerCase() === q ||
          (n.id    || '').toLowerCase() === q
        ) ||
        allNodes.find(n =>
          (n.label || '').toLowerCase().includes(q) ||
          (n.name  || '').toLowerCase().includes(q)
        );

      if (!targetNode || !isFinite(targetNode.x)) return false;

      // Full BFS — traverse ALL reachable nodes to show complete blast radius
      const connectedIds = new Set([targetNode.id]);
      const bfsQueue = [targetNode.id];
      while (bfsQueue.length > 0) {
        const nodeId = bfsQueue.shift();
        for (const r of allRels) {
          const s = typeof r.source === 'object' ? r.source.id : r.source;
          const t = typeof r.target === 'object' ? r.target.id : r.target;
          if (s === nodeId && !connectedIds.has(t)) { connectedIds.add(t); bfsQueue.push(t); }
          if (t === nodeId && !connectedIds.has(s)) { connectedIds.add(s); bfsQueue.push(s); }
        }
      }

      // Open panel on Inspector tab with this node selected
      // Inject attack_paths relevant to this node
      const nodeLabel = (targetNode.label || '').toLowerCase();
      const relatedPaths = (graphData?.attack_paths || []).filter(ap =>
        (ap.workload || '').toLowerCase() === nodeLabel ||
        (ap.entry_points || []).some(ep => ep.toLowerCase() === nodeLabel) ||
        (ap.affected_workloads || []).some(w => w.toLowerCase() === nodeLabel)
      );
      setSelectedNode({ ...targetNode, attack_paths: relatedPaths });
      setPanelOpen(true);

      // Dim everything outside the neighbourhood
      const { node, link } = graphRef.current;
      node.select('circle.gnode').transition().duration(300)
        .attr('opacity', d => connectedIds.has(d.id) ? 1 : 0.06)
        .attr('stroke', d => d.id === targetNode.id ? '#7c6ff0' : connectedIds.has(d.id) ? '#3b82f6' : vis(d.type, d).color)
        .attr('stroke-width', d => d.id === targetNode.id ? 3 : connectedIds.has(d.id) ? 2 : 1.5);
      node.selectAll('text').transition().duration(300)
        .attr('opacity', d => connectedIds.has(d.id) ? 1 : 0.06);
      link.transition().duration(300)
        .attr('opacity', l => {
          const s = typeof l.source === 'object' ? l.source.id : l.source;
          const t = typeof l.target === 'object' ? l.target.id : l.target;
          return connectedIds.has(s) && connectedIds.has(t) ? 1 : 0.03;
        })
        .attr('stroke', l => {
          const s = typeof l.source === 'object' ? l.source.id : l.source;
          const t = typeof l.target === 'object' ? l.target.id : l.target;
          return connectedIds.has(s) && connectedIds.has(t) ? 'rgba(124,111,240,0.6)' : 'rgba(255,255,255,0.04)';
        })
        .attr('stroke-width', l => {
          const s = typeof l.source === 'object' ? l.source.id : l.source;
          const t = typeof l.target === 'object' ? l.target.id : l.target;
          return connectedIds.has(s) && connectedIds.has(t) ? 2 : 0.5;
        });

      // Zoom to fit target + full neighbourhood with comfortable padding
      if (zoomRef.current && svgRef.current) {
        const neighbourNodes = allNodes.filter(n => connectedIds.has(n.id) && isFinite(n.x) && isFinite(n.y));
        if (neighbourNodes.length > 0) {
          const svgEl = d3.select(svgRef.current);
          const W = svgRef.current.clientWidth || 800;
          const H = svgRef.current.clientHeight || 600;
          const xs = neighbourNodes.map(n => n.x);
          const ys = neighbourNodes.map(n => n.y);
          // Generous padding so node labels aren't clipped
          const pad = Math.max(100, 60 * Math.sqrt(neighbourNodes.length));
          const xMin = Math.min(...xs) - pad, xMax = Math.max(...xs) + pad;
          const yMin = Math.min(...ys) - pad, yMax = Math.max(...ys) + pad;
          const scaleX = W / (xMax - xMin);
          const scaleY = H / (yMax - yMin);
          const scale = Math.min(scaleX, scaleY, 2.5) * 0.88;
          // Center the bounding box
          const midX = (xMin + xMax) / 2;
          const midY = (yMin + yMax) / 2;
          const tx = W / 2 - midX * scale;
          const ty = H / 2 - midY * scale;
          svgEl.transition().duration(700)
            .call(zoomRef.current.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
        }
      }

      setFocusHandled(true);
      return true;
    };

    // If positions already ready (returning to graph page with hot cache), apply immediately
    if (graphRef.current?.positionsReady) {
      applyFocus();
      return;
    }

    // Otherwise register callback for when simulation has ticked enough
    if (graphRef.current) {
      graphRef.current.onPositionsReady = applyFocus;
    }

    // Fallback: poll every 200ms for up to 5s (handles slow networks / large graphs)
    let attempts = 0;
    const poll = setInterval(() => {
      attempts++;
      if (applyFocus() || attempts > 25) clearInterval(poll);
    }, 200);
    return () => {
      clearInterval(poll);
      if (graphRef.current) graphRef.current.onPositionsReady = null;
    };
  }, [focusParam, focusHandled, graphData]);

  // ─── Attack path highlight ───
  useEffect(() => {
    if (!graphRef.current) return;
    const { node, link, links } = graphRef.current;
    if (!activeAttackPath) { resetHL(node, link); return; }

    // Build set of related node IDs from attack path data
    const pids = new Set(activeAttackPath.nodes || []);

    // If no explicit nodes, match by workload name + entry points
    if (pids.size === 0) {
      const apWorkload = (activeAttackPath.workload || '').toLowerCase();
      const apEntryPoints = (activeAttackPath.entry_points || []).map(e => e.toLowerCase());
      const searchTerms = [apWorkload, ...apEntryPoints].filter(Boolean);

      if (searchTerms.length > 0 && graphData?.nodes) {
        // Find matching nodes by label
        for (const n of graphData.nodes) {
          const label = (n.label || '').toLowerCase();
          if (searchTerms.some(t => label.includes(t) || t.includes(label))) {
            pids.add(n.id);
          }
        }
        // BFS: expand to connected nodes (credentials, resources in the path)
        if (pids.size > 0) {
          const queue = [...pids];
          const visited = new Set(queue);
          while (queue.length > 0) {
            const current = queue.shift();
            for (const r of (graphData.relationships || [])) {
              const s = sid(r.source), t = sid(r.target);
              if (s === current && !visited.has(t)) { visited.add(t); queue.push(t); pids.add(t); }
              if (t === current && !visited.has(s)) { visited.add(s); queue.push(s); pids.add(s); }
            }
          }
        }
      }
    }

    if (pids.size === 0) { resetHL(node, link); return; }

    node.select('circle.gnode').transition().duration(200)
      .attr('opacity', d => pids.has(d.id) ? 1 : 0.06)
      .attr('stroke', d => pids.has(d.id) ? '#ef4444' : vis(d.type, d).color)
      .attr('stroke-width', d => pids.has(d.id) ? 2.5 : 1.5);
    node.selectAll('text').transition().duration(200).attr('opacity', d => pids.has(d.id) ? 1 : 0.06);
    link.transition().duration(200)
      .attr('opacity', l => pids.has(sid(l.source)) && pids.has(sid(l.target)) ? 1 : 0.02)
      .attr('stroke', l => pids.has(sid(l.source)) && pids.has(sid(l.target)) ? '#ef4444' : 'rgba(255,255,255,0.08)')
      .attr('stroke-width', l => pids.has(sid(l.source)) && pids.has(sid(l.target)) ? 2.5 : 0.8);
  }, [activeAttackPath, graphData]);

  // ─── Simulation overlay on graph ───
  useEffect(() => {
    if (!graphRef.current) return;
    const { node, link } = graphRef.current;
    if (!simOverlay) return; // don't reset here — let attack path / click handlers do that
    const { violatingIds, compliantIds } = simOverlay;
    const allSim = new Set([...violatingIds, ...compliantIds]);

    node.select('circle.gnode').transition().duration(400)
      .attr('opacity', d => allSim.has(d.id) || allSim.has(d.label) ? 1 : 0.08)
      .attr('stroke', d => {
        const id = d.id, lbl = d.label;
        if (violatingIds.has(id) || violatingIds.has(lbl)) return '#ef4444';
        if (compliantIds.has(id) || compliantIds.has(lbl)) return '#10b981';
        return vis(d.type, d).color;
      })
      .attr('stroke-width', d => {
        const id = d.id, lbl = d.label;
        if (violatingIds.has(id) || violatingIds.has(lbl)) return 3;
        if (compliantIds.has(id) || compliantIds.has(lbl)) return 2.5;
        return 1.5;
      })
      .attr('fill', d => {
        const id = d.id, lbl = d.label;
        if (violatingIds.has(id) || violatingIds.has(lbl)) return 'rgba(239,68,68,0.15)';
        if (compliantIds.has(id) || compliantIds.has(lbl)) return 'rgba(16,185,129,0.12)';
        return `${vis(d.type, d).color}12`;
      });
    node.selectAll('text').transition().duration(400)
      .attr('opacity', d => allSim.has(d.id) || allSim.has(d.label) ? 1 : 0.08);
    link.transition().duration(400).attr('opacity', 0.03);
  }, [simOverlay]);

  // ─── Enforce overlay: green shield rings + edge state (amber=audit, gray=severed) ───
  // Runs when enforceOverlay or edgeEnforceState changes, AND after graph rebuild (graphData)
  useEffect(() => {
    // Always keep ref in sync — D3 closures read from ref, not state
    edgeEnforceRef.current = edgeEnforceState;
    if (!graphRef.current) return;
    if (enforceOverlay.size === 0 && Object.keys(edgeEnforceState).length === 0) return;
    // Delay to ensure D3 nodes exist after rebuild
    const t = setTimeout(() => {
      graphRef.current?.applyEnforceOverlay?.(enforceOverlay, edgeEnforceRef.current);
    }, 80);
    return () => clearTimeout(t);
  }, [enforceOverlay, edgeEnforceState, graphData]);

  // ─── Apply filter spotlight to D3 nodes ───
  useEffect(() => {
    if (!graphRef.current?.node || !graphRef.current?.link) return;
    const { node, link } = graphRef.current;
    const hasFilter = activeFilter || riskFilter;
    if (hasFilter) {
      const matchFn = activeFilter ? GRAPH_FILTERS.find(f => f.key === activeFilter)?.match : null;
      // Build set of node labels matching the risk filter
      const riskNodeLabels = new Set();
      if (riskFilter && graphData?.attack_paths) {
        for (const ap of graphData.attack_paths) {
          if (ap.severity === riskFilter) {
            if (ap.workload) riskNodeLabels.add(ap.workload.toLowerCase());
            for (const w of (ap.affected_workloads || [])) riskNodeLabels.add(w.toLowerCase());
            for (const ep of (ap.entry_points || [])) riskNodeLabels.add(ep.toLowerCase());
          }
        }
      }
      const matchesNode = (d) => {
        const matchesType = !matchFn || matchFn(d);
        const matchesRisk = !riskFilter || riskNodeLabels.has((d.label || '').toLowerCase());
        return matchesType && matchesRisk;
      };
      node.attr('opacity', d => matchesNode(d) ? 1 : 0.15);
      link.attr('opacity', d => {
        const src = typeof d.source === 'object' ? d.source : {};
        const tgt = typeof d.target === 'object' ? d.target : {};
        return (matchesNode(src) || matchesNode(tgt)) ? 0.8 : 0.08;
      });
    } else {
      node.attr('opacity', 1);
      link.attr('opacity', d => d.critical ? 0.8 : 0.6);
    }
  }, [activeFilter, riskFilter, graphData, GRAPH_FILTERS]);

  // ─── Minimap drawing ───
  useEffect(() => {
    const canvas = minimapRef.current;
    if (!canvas || !graphRef.current?.nodes) return;
    const ctx = canvas.getContext('2d');
    const nodes = graphRef.current.nodes;
    const W = 120, H = 80;
    canvas.width = W; canvas.height = H;
    const xs = nodes.map(n => n.x).filter(isFinite), ys = nodes.map(n => n.y).filter(isFinite);
    if (xs.length === 0) return;
    const [xMin, xMax] = [Math.min(...xs) - 30, Math.max(...xs) + 30];
    const [yMin, yMax] = [Math.min(...ys) - 30, Math.max(...ys) + 30];
    const sx = W / (xMax - xMin), sy = H / (yMax - yMin);
    ctx.clearRect(0, 0, W, H);
    for (const n of nodes) {
      if (!isFinite(n.x) || !isFinite(n.y)) continue;
      const px = (n.x - xMin) * sx, py = (n.y - yMin) * sy;
      const c = vis(n.type, n).color;
      ctx.fillStyle = c;
      ctx.globalAlpha = 0.7;
      ctx.beginPath(); ctx.arc(px, py, 2, 0, Math.PI * 2); ctx.fill();
    }
    // Viewport rectangle
    const t = zoomTransformRef.current || d3.zoomIdentity;
    const svgEl = svgRef.current;
    if (svgEl && t.k > 0) {
      const sw = svgEl.clientWidth, sh = svgEl.clientHeight;
      const vx1 = (-t.x / t.k - xMin) * sx, vy1 = (-t.y / t.k - yMin) * sy;
      const vw = (sw / t.k) * sx, vh = (sh / t.k) * sy;
      ctx.globalAlpha = 0.4; ctx.strokeStyle = '#a78bfa'; ctx.lineWidth = 1;
      ctx.strokeRect(vx1, vy1, vw, vh);
    }
    ctx.globalAlpha = 1;
  }, [graphData, activeFilter]); // redraw on data or filter change

  const filteredTimeline = useMemo(() =>
    timelineFilter === 'all' ? timeline : timeline.filter(t => t.type === timelineFilter), [timeline, timelineFilter]);

  const filteredNodes = useMemo(() => {
    if (!searchQuery || !graphData?.nodes) return [];
    const q = searchQuery.toLowerCase();
    return graphData.nodes.filter(n =>
      (n.label || '').toLowerCase().includes(q) ||
      (n.type || '').toLowerCase().includes(q) ||
      (n.workload_type || '').toLowerCase().includes(q) ||
      (n.spiffe_id || '').toLowerCase().includes(q)
    );
  }, [searchQuery, graphData]);

  // Find the first enforced node label for navigation (must be above early returns for hook ordering)
  const enforcedNodeLabel = useMemo(() => {
    for (const ap of (graphData?.attack_paths || [])) {
      if (ap.remediation?.status === 'enforced' && ap.workload) return ap.workload;
    }
    return null;
  }, [graphData]);

  // Centralized node selection — always injects attack_paths from graphData
  const selectNodeWithPaths = useCallback((nodeOrMatch) => {
    if (!nodeOrMatch) return;
    const nodeLabel = (nodeOrMatch.label || '').toLowerCase();
    const aps = (graphData?.attack_paths || []);
    const ns = graphData?.nodes || [];
    const rs = graphData?.relationships || [];
    const relatedPaths = aps.filter(ap =>
      (ap.workload || '').toLowerCase() === nodeLabel ||
      (ap.entry_points || []).some(ep => ep.toLowerCase() === nodeLabel) ||
      (ap.affected_workloads || []).some(w => w.toLowerCase() === nodeLabel)
    ).map(ap => enrichAttackPath(ap, ns, rs));
    setSelectedNode({ ...nodeOrMatch, attack_paths: relatedPaths });
  }, [graphData]);

  const selectEnforcedNode = useCallback(() => {
    if (!enforcedNodeLabel) return;
    const gNodes = graphData?.nodes || [];
    const match = gNodes.find(n => (n.label || '').toLowerCase() === enforcedNodeLabel.toLowerCase());
    if (match) selectNodeWithPaths(match);
  }, [enforcedNodeLabel, graphData, selectNodeWithPaths]);

  // ── Compute paths, groups, choke points, risk summary ──
  // All hooks MUST be above the early return to satisfy Rules of Hooks.
  const gNodes = graphData?.nodes || [];
  const gRels = graphData?.relationships || [];
  const allPaths = useMemo(() => (graphData?.attack_paths || [])
    .map(ap => enrichAttackPath(ap, gNodes, gRels))
    .sort((a, b) => {
      const sevDiff = (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4);
      if (sevDiff !== 0) return sevDiff;
      return (b.blast_radius || 0) - (a.blast_radius || 0);
    }), [graphData, gNodes, gRels]);

  // Filter attack paths to selected node's connections + activeFilter
  const paths = useMemo(() => {
    let filtered = allPaths;
    if (selectedNode) {
      const nodeLabel = (selectedNode.label || '').toLowerCase();
      const nodeId = selectedNode.id;
      const rels = graphData?.relationships || [];
      const gN = graphData?.nodes || [];
      const connectedIds = new Set([nodeId]);
      rels.forEach(r => {
        const s = typeof r.source === 'object' ? r.source.id : r.source;
        const t = typeof r.target === 'object' ? r.target.id : r.target;
        if (s === nodeId) connectedIds.add(t);
        if (t === nodeId) connectedIds.add(s);
      });
      const connectedLabels = new Set();
      gN.forEach(n => { if (connectedIds.has(n.id)) connectedLabels.add((n.label || '').toLowerCase()); });
      const nodeFiltered = filtered.filter(p => {
        const desc = (p.description || p.message || '').toLowerCase();
        const workload = (p.workload || '').toLowerCase();
        for (const lbl of connectedLabels) { if (desc.includes(lbl) || workload.includes(lbl) || lbl.includes(workload)) return true; }
        return desc.includes(nodeLabel) || workload.includes(nodeLabel) || nodeLabel.includes(workload);
      });
      filtered = nodeFiltered.length > 0 ? nodeFiltered : filtered;
    }
    // Step 8: when a graph filter is active, also filter right panel paths
    if (activeFilter) {
      const matchFn = GRAPH_FILTERS.find(f => f.key === activeFilter)?.match;
      if (matchFn) {
        const matchingLabels = new Set();
        gNodes.forEach(n => { if (matchFn(n)) matchingLabels.add((n.label || '').toLowerCase()); });
        const filterResult = filtered.filter(p => {
          return matchingLabels.has((p.workload || '').toLowerCase()) ||
            (p.affected_workloads || []).some(w => matchingLabels.has(w.toLowerCase()));
        });
        if (filterResult.length > 0) filtered = filterResult;
      }
    }
    return filtered;
  }, [allPaths, selectedNode, activeFilter, graphData, gNodes, GRAPH_FILTERS]);

  // ── Grouped view computed data ──
  const pathGroups = useMemo(() => {
    const groups = {};
    for (const p of paths) {
      const ft = p._resolved_ft || p.finding_type || 'unknown';
      if (!groups[ft]) {
        groups[ft] = { findingType: ft, paths: [], maxSeverity: 'info', totalBlast: 0, workloads: new Set(), enforcedCount: 0, auditCount: 0, linkedPolicies: [] };
      }
      const g = groups[ft];
      g.paths.push(p);
      if ((SEV_ORDER[p.severity] || 4) < (SEV_ORDER[g.maxSeverity] || 4)) g.maxSeverity = p.severity;
      g.totalBlast = Math.max(g.totalBlast, p.blast_radius || 0);
      if (p.workload) g.workloads.add(p.workload);
      (p.affected_workloads || []).forEach(w => g.workloads.add(w));
      if (p.remediation?.status === 'enforced') g.enforcedCount++;
      if (p.remediation?.status === 'audit') g.auditCount++;
      for (const pol of (p.remediation?.policies || [])) {
        if (pol.name && !g.linkedPolicies.some(lp => lp.name === pol.name)) g.linkedPolicies.push(pol);
      }
    }
    for (const g of Object.values(groups)) {
      // Prefer backend ranked_controls from any path in this group, fallback to frontend catalog
      const backendControls = g.paths.find(p => p.ranked_controls?.length > 0)?.ranked_controls;
      g.controls = backendControls || CONTROL_CATALOG_FALLBACK[g.findingType] || [];
    }
    return Object.values(groups).sort((a, b) => {
      const sevDiff = (SEV_ORDER[a.maxSeverity] || 4) - (SEV_ORDER[b.maxSeverity] || 4);
      if (sevDiff !== 0) return sevDiff;
      return b.paths.length - a.paths.length;
    });
  }, [paths]);

  const chokePoints = useMemo(() => {
    // Count how many paths each node is the PRIMARY workload source of,
    // plus a smaller weight for being in the credential chain (direct hop).
    // Exclude affected_workloads (BFS-reachable) to avoid inflating counts.
    const counts = {};
    for (const p of paths) {
      // Primary: this node is the attack path source
      if (p.workload) {
        const lbl = p.workload;
        if (!counts[lbl]) counts[lbl] = { label: lbl, primary: 0, chain: 0, node: null };
        counts[lbl].primary++;
      }
      // Chain: node appears in credential_chain (direct hop, not BFS reachable)
      for (const c of (p.credential_chain || [])) {
        if (c.label && c.label !== p.workload) {
          if (!counts[c.label]) counts[c.label] = { label: c.label, primary: 0, chain: 0, node: null };
          counts[c.label].chain++;
        }
      }
    }
    for (const cp of Object.values(counts)) {
      cp.node = gNodes.find(n => (n.label || '').toLowerCase() === cp.label.toLowerCase()) || null;
      // Weighted score: primary paths count fully, chain references count as 0.3
      cp.count = cp.primary + Math.round(cp.chain * 0.3);
      // Synthesize description from node type and related finding types
      const nodeType = (cp.node?.type || 'workload').replace(/-/g, ' ');
      const relatedGroups = pathGroups
        .filter(g => g.paths.some(p => (p.workload || '').toLowerCase() === cp.label.toLowerCase()))
        .map(g => g.findingType.replace(/-/g, ' '));
      const findingStr = relatedGroups.length > 0
        ? relatedGroups.slice(0, 2).join(', ') : 'risk exposure';
      cp.description = `${nodeType} \u2014 ${findingStr}`;
    }
    // Only show nodes that are primary source of at least 1 path
    return Object.values(counts)
      .filter(cp => cp.primary > 0)
      .sort((a, b) => b.count - a.count || b.primary - a.primary)
      .slice(0, 3);
  }, [paths, gNodes]);

  const riskSummary = useMemo(() => {
    const findingTypeCount = pathGroups.length;
    const pathCount = paths.length;
    const workloadsAtRisk = new Set();
    for (const p of paths) {
      if (p.workload) workloadsAtRisk.add(p.workload);
      (p.affected_workloads || []).forEach(w => workloadsAtRisk.add(w));
    }
    const enforcedCount = paths.filter(p => p.remediation?.status === 'enforced').length;
    const unmitigatedPct = pathCount > 0 ? Math.round(((pathCount - enforcedCount) / pathCount) * 100) : 0;
    return { findingTypeCount, pathCount, workloadsAtRisk: workloadsAtRisk.size, unmitigatedPct };
  }, [paths, pathGroups]);

  // Auto-expand the first (highest severity) group on initial load
  useEffect(() => {
    if (pathGroups.length > 0 && expandedGroups.size === 0) {
      setExpandedGroups(new Set([pathGroups[0].findingType]));
    }
  }, [pathGroups.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const summary = graphData?.summary || {};
  const unmitigatedCount = summary.unmitigated_paths ?? paths.filter(p => !p.remediation || p.remediation.status !== 'enforced').filter(p => p.severity === 'critical' || p.severity === 'high').length;

  if (loading) return (
    <div className="flex items-center justify-center h-screen gap-3">
      <Loader className="w-5 h-5 text-accent animate-spin" /><span className="text-sm text-nhi-muted">Loading identity graph...</span>
    </div>
  );

  // Empty state — no nodes discovered yet
  if (!graphData?.nodes?.length) return (
    <div className="flex items-center justify-center" style={{ height: 'calc(100vh - 52px)' }}>
      <div className="text-center max-w-md mx-auto px-6">
        <div className="w-20 h-20 rounded-2xl bg-accent/10 flex items-center justify-center mx-auto mb-6">
          <GitBranch className="w-10 h-10 text-accent" />
        </div>
        <h2 className="text-[18px] font-bold text-nhi-text mb-2">No Identity Graph Yet</h2>
        <p className="text-[13px] text-nhi-dim mb-6 leading-relaxed">
          Connect a cloud account and run a discovery scan to build your identity graph.
          Workloads, credentials, and attack paths will appear here.
        </p>
        <button
          onClick={() => navigate('/connectors')}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-accent text-white text-[13px] font-semibold hover:bg-accent/90 transition-all duration-200 shadow-lg shadow-accent/20"
        >
          <GitBranch className="w-4 h-4" /> Connect Cloud Account
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex flex-col" style={{ height: 'calc(100vh - 52px)' }}>
      {/* ─── Header ─── */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-white/[0.03]" style={{ background: 'var(--surface-2)' }}>
        <div className="flex items-center gap-3">
          <GitBranch className="w-4 h-4 text-accent" />
          <h1 className="text-sm font-bold text-nhi-text">Identity Graph</h1>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-white/[0.04] text-nhi-muted font-mono">{summary.total_nodes || 0} nodes · {summary.total_relationships || 0} edges</span>
          {unmitigatedCount > 0 && (
            <span className="text-[10px] px-2 py-0.5 rounded-full font-bold flex items-center gap-1"
              style={{ background: '#ef444418', color: '#ef4444' }}>
              <AlertTriangle className="w-2.5 h-2.5" />{unmitigatedCount} unmitigated
            </span>
          )}
          {summary.enforced_paths > 0 && (
            <button onClick={selectEnforcedNode} className="text-[10px] px-2 py-0.5 rounded-full font-bold flex items-center gap-1 cursor-pointer transition-all hover:brightness-125" style={{ background: '#10b98118', color: '#10b981', border: 'none' }}>
              <CheckCircle2 className="w-2.5 h-2.5" />{summary.enforced_paths} enforced
            </button>
          )}
          {summary.remediated_paths > 0 && summary.enforced_paths < summary.remediated_paths && (
            <span className="text-[10px] px-2 py-0.5 rounded-full font-bold flex items-center gap-1" style={{ background: '#f59e0b18', color: '#f59e0b' }}>
              {summary.remediated_paths - (summary.enforced_paths || 0)} auditing
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3 h-3 text-nhi-faint absolute left-2 top-1/2 -translate-y-1/2" />
            <input type="text" placeholder="Search nodes..." value={searchQuery}
              onChange={e => { setSearchQuery(e.target.value); setSearchIndex(-1); }}
              onKeyDown={e => {
                const max = Math.min(filteredNodes.length, 8);
                if (e.key === 'ArrowDown') { e.preventDefault(); setSearchIndex(i => Math.min(i + 1, max - 1)); }
                else if (e.key === 'ArrowUp') { e.preventDefault(); setSearchIndex(i => Math.max(i - 1, 0)); }
                else if (e.key === 'Enter' && searchIndex >= 0 && filteredNodes[searchIndex]) {
                  e.preventDefault();
                  const n = filteredNodes[searchIndex];
                  selectNodeWithPaths(n); setPanelOpen(true); setSearchQuery(''); setSearchIndex(-1); setRemPath(null); setRemGroup(null);
                  if (graphRef.current) hlNode(n.id, graphRef.current.node, graphRef.current.link, graphRef.current.links);
                }
                else if (e.key === 'Escape') { setSearchQuery(''); setSearchIndex(-1); }
              }}
              className="text-[10px] pl-6 pr-2 py-1.5 rounded-lg bg-white/[0.03] border border-white/[0.04] text-nhi-text placeholder-nhi-ghost w-40 focus:outline-none focus:border-accent/30" />
            {searchQuery && <button onClick={() => { setSearchQuery(''); setSearchIndex(-1); }} className="absolute right-1.5 top-1/2 -translate-y-1/2"><X className="w-2.5 h-2.5 text-nhi-faint" /></button>}
            {searchQuery && filteredNodes.length > 0 && (
              <div className="absolute top-full mt-1 left-0 right-0 rounded-lg border border-white/[0.06] z-50 max-h-48 overflow-y-auto" style={{ background: 'var(--surface-3)' }}>
                {filteredNodes.slice(0, 8).map((n, i) => {
                  const q = searchQuery.toLowerCase();
                  const label = n.label || '';
                  const matchIdx = label.toLowerCase().indexOf(q);
                  return (
                    <button key={n.id}
                      className={`w-full text-left px-3 py-1.5 text-[10px] flex items-center gap-2 ${i === searchIndex ? 'bg-white/[0.06]' : 'hover:bg-white/[0.04]'}`}
                      onClick={() => { selectNodeWithPaths(n); setPanelOpen(true); setSearchQuery(''); setSearchIndex(-1); setRemPath(null); setRemGroup(null);
                        if (graphRef.current) hlNode(n.id, graphRef.current.node, graphRef.current.link, graphRef.current.links); }}>
                      <span>{vis(n.type).icon}</span>
                      <span className="font-mono text-nhi-text">
                        {matchIdx >= 0 ? (
                          <>{label.slice(0, matchIdx)}<span style={{ background: '#7c6ff030', color: '#a78bfa' }}>{label.slice(matchIdx, matchIdx + q.length)}</span>{label.slice(matchIdx + q.length)}</>
                        ) : label}
                      </span>
                      <span className="text-nhi-faint text-[8px] ml-auto">{vis(n.type).label}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
          <button onClick={triggerScan} disabled={scanning}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold text-nhi-muted bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.04] transition-colors">
            <RefreshCw className={`w-3 h-3 ${scanning ? 'animate-spin' : ''}`} />{scanning ? 'Scanning...' : 'Rescan'}
          </button>
          <button onClick={() => {
            const svg = svgRef.current;
            if (!svg) return;
            const clone = svg.cloneNode(true);
            clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
            bg.setAttribute('width', '100%'); bg.setAttribute('height', '100%'); bg.setAttribute('fill', '#0a0a0f');
            clone.insertBefore(bg, clone.firstChild);
            const serializer = new XMLSerializer();
            const svgString = serializer.serializeToString(clone);
            const blob = new Blob([svgString], { type: 'image/svg+xml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = 'identity-graph.svg'; a.click();
            URL.revokeObjectURL(url);
          }}
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[10px] font-semibold text-nhi-muted bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.04] transition-colors"
            title="Export graph as SVG">
            Export
          </button>
          <button onClick={() => setPanelOpen(!panelOpen)}
            className="flex items-center px-2 py-1.5 rounded-lg text-nhi-muted bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.04] transition-colors">
            {panelOpen ? <PanelRightClose className="w-3.5 h-3.5" /> : <PanelRightOpen className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* ─── Two-Pane Body ─── */}
      <div className="flex flex-1 overflow-hidden">
        {/* LEFT: Graph */}
        <div className="flex-1 relative" style={{ background: 'var(--surface-1, #0a0a0f)' }}>
          <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block' }} />
          {/* Minimap */}
          <canvas ref={minimapRef} width={120} height={80}
            className="absolute bottom-12 left-3 rounded border border-white/[0.06]"
            style={{ background: 'rgba(10,10,15,0.8)', width: 120, height: 80 }} />
          <div className="absolute bottom-3 left-3 flex gap-1.5">
            <button onClick={zoomIn} className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] flex items-center justify-center text-nhi-muted transition-colors"><span className="text-sm font-bold">+</span></button>
            <button onClick={zoomOut} className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] flex items-center justify-center text-nhi-muted transition-colors"><span className="text-sm font-bold">−</span></button>
            <button onClick={zoomFit} className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] flex items-center justify-center text-nhi-muted transition-colors"><Maximize2 className="w-3 h-3" /></button>
            <button onClick={() => setShowLegend(l => !l)} className="w-7 h-7 rounded-lg bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.06] flex items-center justify-center text-nhi-muted transition-colors" title="Toggle legend"><span className="text-[9px] font-bold font-mono">L</span></button>
          </div>
          {/* Graph Legend */}
          {showLegend && (
            <div className="absolute bottom-12 right-3 rounded-lg border border-white/[0.06] p-2" style={{ background: 'rgba(10,10,15,0.92)', maxWidth: 170, zIndex: 10 }}>
              <div className="text-[8px] text-nhi-faint mb-1.5 uppercase tracking-wider font-bold font-mono">Legend</div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-1">
                {Object.entries(NODE_CFG).filter(([k]) =>
                  ['a2a-agent','service-account','cloud-run','container','credential','external-api','resource','exposure'].includes(k))
                .map(([key, cfg]) => (
                  <div key={key} className="flex items-center gap-1.5">
                    <span className="text-[10px]">{cfg.icon}</span>
                    <span className="text-[7px] font-mono" style={{ color: cfg.color }}>{cfg.label}</span>
                  </div>
                ))}
              </div>
              <div className="mt-1.5 pt-1 border-t border-white/[0.04]">
                <div className="text-[7px] text-nhi-faint mb-1 font-mono">Edges</div>
                <div className="flex items-center gap-1.5 mb-0.5">
                  <div className="w-3 h-0 border-t border-red-500/40 border-dashed" />
                  <span className="text-[7px] font-mono" style={{ color: '#888' }}>Critical path</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-0 border-t border-white/10" />
                  <span className="text-[7px] font-mono" style={{ color: '#888' }}>Relationship</span>
                </div>
              </div>
            </div>
          )}
          <div className="absolute top-2 left-2 flex flex-col gap-1">
            <div className="flex flex-wrap gap-1">
              {GRAPH_FILTERS.map(f => {
                const count = gNodes.filter(f.match).length;
                const isActive = activeFilter === f.key;
                return (
                  <button key={f.key} onClick={() => setActiveFilter(isActive ? null : f.key)}
                    className="text-[8px] px-2 py-0.5 rounded border transition-all cursor-pointer"
                    style={{
                      textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: isActive ? 600 : 400,
                      background: isActive ? `${f.color}20` : 'rgba(0,0,0,0.3)',
                      borderColor: isActive ? `${f.color}40` : 'rgba(255,255,255,0.03)',
                      color: isActive ? f.color : undefined,
                    }}>
                    {f.label} {count > 0 && <span className="ml-1" style={{ opacity: isActive ? 1 : 0.6, fontWeight: 700 }}>{count}</span>}
                  </button>
                );
              })}
            </div>
            {/* Risk severity filter */}
            <div className="flex gap-1">
              {['critical', 'high', 'medium', 'low'].map(sev => {
                const sc = SEV[sev];
                const isActive = riskFilter === sev;
                return (
                  <button key={sev} onClick={() => setRiskFilter(isActive ? null : sev)}
                    className="text-[7px] px-1.5 py-0.5 rounded border transition-all cursor-pointer"
                    style={{
                      textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: isActive ? 700 : 400,
                      background: isActive ? sc.bg : 'transparent',
                      borderColor: isActive ? sc.color + '40' : 'rgba(255,255,255,0.02)',
                      color: isActive ? sc.color : '#777',
                    }}>
                    {sc.label}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="absolute bottom-3 right-3 text-[7px] text-nhi-faint/30">scroll to zoom · drag to pan · click to inspect</div>
        </div>

        {/* RIGHT: Context-aware Panel — shows NodePanel when node selected, else Attack Paths grouped view */}
        {panelOpen && (
          <div className="flex" style={{ flexShrink: 0 }}>
          {/* Drag handle for panel resize */}
          <div className="w-1 cursor-col-resize hover:bg-accent/30 transition-colors flex-shrink-0"
            style={{ background: 'rgba(255,255,255,0.02)' }}
            onMouseDown={e => {
              e.preventDefault();
              const startX = e.clientX;
              const startW = panelWidth;
              const onMove = (me) => setPanelWidth(Math.max(280, Math.min(520, startW - (me.clientX - startX))));
              const onUp = () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp); };
              document.addEventListener('mousemove', onMove);
              document.addEventListener('mouseup', onUp);
            }} />
          <div className="flex flex-col border-l border-white/[0.04]" style={{ width: panelWidth, background: 'var(--surface-2)' }}>

            {/* ── Node selected → single scrollable NodePanel ── */}
            {selectedNode ? (
              <NodePanel
                node={selectedNode}
                rels={graphData?.relationships || []}
                nodes={graphData?.nodes || []}
                timeline={timeline}
                enforceLogStream={enforceLogStream}
                dismissedPaths={dismissedPaths}
                edgeEnforceState={edgeEnforceState}
                onSimResult={(overlay) => { setSimOverlay(overlay); }}
                onEnforced={(nodeLabel, pathIds, mode, affectedNodes) => {
                  const isAudit = mode === 'audit';
                  setEnforceOverlay(prev => new Set([...prev, nodeLabel, ...(affectedNodes || [])]));
                  if (!isAudit) setDismissedPaths(prev => new Set([...prev, ...pathIds]));
                  setEdgeEnforceState(prev => ({ ...prev, [nodeLabel]: isAudit ? 'audit' : 'enforce' }));

                  // Immediately sync enforcement state into graphData so the Attack Paths panel
                  // reflects the same state as NodePanel without waiting for fetchAll()
                  if (pathIds.length > 0) {
                    const pathIdSet = new Set(pathIds);
                    const newStatus = isAudit ? 'audit' : 'enforced';
                    setGraphData(prev => {
                      if (!prev?.attack_paths) return prev;
                      const updatedAPs = prev.attack_paths.map(ap =>
                        pathIdSet.has(ap.id)
                          ? { ...ap, remediation: { ...(ap.remediation || {}), status: newStatus } }
                          : ap
                      );
                      return { ...prev, attack_paths: updatedAPs };
                    });
                    // Also update selectedNode's attack_paths so NodePanel stays consistent
                    setSelectedNode(prev => {
                      if (!prev?.attack_paths) return prev;
                      const updatedAPs = prev.attack_paths.map(ap =>
                        pathIdSet.has(ap.id)
                          ? { ...ap, remediation: { ...(ap.remediation || {}), status: newStatus } }
                          : ap
                      );
                      return { ...prev, attack_paths: updatedAPs };
                    });
                  }

                  const now = new Date();
                  const logEntries = [
                    { ts: now.toISOString(), decision: isAudit ? 'WOULD_BLOCK' : 'DENY', workload: nodeLabel, action: 'credential.use', policy: 'shared-sa-prohibition', reason: 'Shared SA detected — token issuance blocked', ttl: null },
                    { ts: new Date(now - 800).toISOString(), decision: isAudit ? 'WOULD_BLOCK' : 'DENY', workload: nodeLabel, action: 'secret.read', policy: 'static-credential-ban', reason: 'Static key access blocked', ttl: null },
                    { ts: new Date(now - 1600).toISOString(), decision: 'ALLOW', workload: nodeLabel, action: 'token.request', policy: 'wif-jit-grant', reason: 'JIT WIF token issued via SPIFFE attestation', ttl: '15m' },
                  ];
                  setEnforceLogStream(prev => [...logEntries, ...prev]);
                  const evt = {
                    type: 'authorization', severity: 'info',
                    summary: `Policy ${isAudit ? 'audit' : 'enforced'} on ${nodeLabel} — ${isAudit ? 'logging only' : 'access control deployed'}`,
                    timestamp: now.toISOString(), workload: nodeLabel,
                    detail: { decision: isAudit ? 'audit' : 'enforced', policy: 'graph-control', blast_radius: selectedNode?.blast_radius || 0 },
                  };
                  setTimeline(prev => [evt, ...prev]);
                  setTimeout(() => fetchAll(), 1500);
                }}
                onNavigateAudit={(workload, policy, since, traceId) => {
                  const params = new URLSearchParams();
                  if (workload) params.set('workload', workload);
                  if (policy) params.set('policy', policy);
                  if (since) params.set('since', since);
                  if (traceId) params.set('trace', traceId);
                  navigate(`/access?${params.toString()}`);
                }}
                onAddCustomPolicy={() => {
                  const params = new URLSearchParams();
                  params.set('create', 'true');
                  if (selectedNode?.label) params.set('workload', selectedNode.label);
                  navigate(`/policies?${params.toString()}`);
                }}
                onClose={() => { setSelectedNode(null); setActiveAttackPath(null); if (graphRef.current) resetHL(graphRef.current.node, graphRef.current.link); }}
                collapsedSections={collapsedSections}
                setCollapsedSections={setCollapsedSections}
                setActiveAttackPath={setActiveAttackPath}
              />
            ) : (
              <>
                {/* Tab bar — grouped attack paths */}
                <div className="flex border-b border-white/[0.04] shrink-0">
                  {(() => {
                    const tabColor = paths.some(p => !p.remediation || p.remediation.status !== 'enforced') ? '#ef4444' : '#10b981';
                    return (
                      <button onClick={() => { setRemPath(null); setRemGroup(null); }}
                        className="flex-1 flex items-center justify-center gap-1.5 py-2.5 relative transition-colors"
                        style={{ fontSize: 11, fontWeight: 600, color: '#e8e8ee', background: 'transparent', border: 'none', cursor: 'pointer' }}>
                        <Zap className="w-3 h-3" style={{ color: tabColor }} />
                        Attack Paths
                        {paths.length > 0 && (
                          <span style={{ fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 8, marginLeft: 2, background: `${tabColor}18`, color: tabColor }}>
                            {pathGroups.length} groups · {paths.length}
                          </span>
                        )}
                        <div className="absolute bottom-0 left-2 right-2 h-[2px] rounded-full" style={{ background: tabColor }} />
                      </button>
                    );
                  })()}
                  {/* Hint */}
                  <div className="flex items-center px-3" style={{ fontSize: 9, color: '#666', borderLeft: '1px solid rgba(255,255,255,0.03)', whiteSpace: 'nowrap' }}>
                    <Eye className="w-3 h-3 mr-1" style={{ color: '#666' }} /> click node
                  </div>
                </div>

                {/* Attack Paths content — grouped view */}
                <div className="flex-1 overflow-y-auto p-3 space-y-2">
                  {/* Default: grouped view */}
                  {!remPath && !remGroup && paths.length > 0 && (() => {
                    // When a choke point is selected, filter groups to only those with matching paths
                    const chokeLabel = chokeFilter?.toLowerCase() || null;
                    const displayGroups = chokeLabel
                      ? pathGroups.map(g => {
                          // Only match paths where the choke point is the PRIMARY workload source.
                          // Excluding affected_workloads (BFS-reachable) to avoid showing all groups.
                          const filtered = g.paths.filter(p =>
                            (p.workload || '').toLowerCase() === chokeLabel
                          );
                          if (filtered.length === 0) return null;
                          return { ...g, paths: filtered, totalBlast: Math.max(0, ...filtered.map(p => p.blast_radius || 0)) };
                        }).filter(Boolean)
                      : pathGroups;

                    return (
                      <>
                        <RiskSummaryBar riskSummary={riskSummary} activeFilter={activeFilter} GRAPH_FILTERS={GRAPH_FILTERS} />

                        {/* Choke Points */}
                        {chokePoints.length > 0 && (
                          <div className="mb-2">
                            <div className="flex items-center justify-between px-1 mb-1">
                              <span className="text-[7px] font-bold uppercase tracking-wider text-nhi-faint">CHOKE POINTS</span>
                              {chokeFilter && (
                                <button onClick={() => {
                                  setChokeFilter(null);
                                  if (graphRef.current) resetHL(graphRef.current.node, graphRef.current.link);
                                }}
                                  className="text-[8px] font-mono text-accent hover:text-accent/80 transition-colors"
                                  style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
                                  clear filter
                                </button>
                              )}
                            </div>
                            <p className="text-[9px] text-nhi-ghost mb-1.5 px-1 leading-relaxed">
                              Identities that appear as the source of multiple attack paths. Remediating a choke point fixes multiple paths at once — highest leverage for risk reduction.
                            </p>
                            <div className="space-y-1">
                              {chokePoints.map(cp => (
                                <ChokePointCard key={cp.label} point={cp}
                                  isActive={chokeFilter === cp.label}
                                  onSelect={(pt) => {
                                    // Toggle: click again to clear
                                    if (chokeFilter === pt.label) {
                                      setChokeFilter(null);
                                      if (graphRef.current) resetHL(graphRef.current.node, graphRef.current.link);
                                      return;
                                    }
                                    setChokeFilter(pt.label);
                                    // Highlight node on graph
                                    if (pt.node && graphRef.current) {
                                      hlNode(pt.node.id, graphRef.current.node, graphRef.current.link, graphRef.current.links);
                                    }
                                    // Auto-expand all groups that have paths for this choke point
                                    const cLabel = pt.label.toLowerCase();
                                    const matching = new Set();
                                    for (const g of pathGroups) {
                                      if (g.paths.some(p =>
                                        (p.workload || '').toLowerCase() === cLabel
                                      )) matching.add(g.findingType);
                                    }
                                    setExpandedGroups(matching);
                                  }} />
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Choke filter banner */}
                        {chokeFilter && (
                          <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg mb-2"
                            style={{ background: 'rgba(124,111,240,0.06)', border: '1px solid rgba(124,111,240,0.12)' }}>
                            <span className="text-[9px] text-nhi-muted">Showing paths through</span>
                            <span className="text-[9px] font-bold font-mono text-accent">{chokeFilter}</span>
                            <span className="text-[9px] text-nhi-faint ml-auto">{displayGroups.reduce((s, g) => s + g.paths.length, 0)} paths</span>
                          </div>
                        )}

                        {/* Finding Type Groups */}
                        {displayGroups.map(g => (
                          <FindingGroup key={g.findingType} group={g}
                            expanded={expandedGroups.has(g.findingType)}
                            activeAttackPath={activeAttackPath}
                            onToggle={() => {
                              setExpandedGroups(prev => {
                                const next = new Set(prev);
                                if (next.has(g.findingType)) next.delete(g.findingType);
                                else next.add(g.findingType);
                                return next;
                              });
                            }}
                            onRemediate={() => { setRemGroup(g.findingType); setRemPath(null); }}
                            onPathClick={(ap) => { setActiveAttackPath(activeAttackPath?.id === ap.id ? null : ap); setSelectedNode(null); setRemPath(null); setRemGroup(null); }}
                            onPathRemediate={(ap) => { setRemPath(ap); setRemGroup(null); }}
                          />
                        ))}
                      </>
                    );
                  })()}

                  {/* Empty state */}
                  {!remPath && !remGroup && paths.length === 0 && (
                    <EmptyState icon={Shield} color="#10b981" title="No attack paths detected" sub="Your identity graph looks clean" />
                  )}

                  {/* Individual path remediation */}
                  {remPath && !remGroup && (() => {
                    // Count how many other paths share the same finding_type
                    const ft = remPath._resolved_ft || remPath.finding_type || '';
                    const sameTypePaths = paths.filter(p => (p._resolved_ft || p.finding_type) === ft);
                    const othersCount = sameTypePaths.length - 1;
                    return (
                      <>
                        {othersCount > 0 && (
                          <div className="rounded-lg px-3 py-2 mb-2 flex items-start gap-2"
                            style={{ background: 'rgba(245,158,11,0.06)', border: '1px solid rgba(245,158,11,0.15)' }}>
                            <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" style={{ color: '#f59e0b' }} />
                            <div>
                              <div className="text-[9px] font-semibold text-nhi-text">Policy applies to all {sameTypePaths.length} paths of this type</div>
                              <div className="text-[8px] text-nhi-faint mt-0.5">
                                Deploying this policy will also remediate {othersCount} other "{FL(ft)}" path{othersCount !== 1 ? 's' : ''}.
                                <button onClick={() => { setRemPath(null); setRemGroup(ft); }} className="text-accent ml-1 hover:underline" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 8 }}>
                                  Remediate All Instead
                                </button>
                              </div>
                            </div>
                          </div>
                        )}
                        <RemediationPanel path={remPath}
                          graphNodes={graphData?.nodes || []}
                          onSimResult={(overlay) => { setSimOverlay(overlay); setActiveAttackPath(null); }}
                          onEnforced={(nodeLabel, pathIds, mode, affectedNodes) => {
                            setEnforceOverlay(prev => new Set([...prev, nodeLabel, ...(affectedNodes || [])]));
                            if (mode !== 'audit') setDismissedPaths(prev => new Set([...prev, ...pathIds]));
                            setEdgeEnforceState(prev => ({ ...prev, [nodeLabel]: mode === 'audit' ? 'audit' : 'enforce' }));
                          }}
                          onClose={() => { setRemPath(null); setSimOverlay(null); if (graphRef.current) resetHL(graphRef.current.node, graphRef.current.link); }} />
                      </>
                    );
                  })()}

                  {/* Group-level remediation */}
                  {remGroup && !remPath && (() => {
                    const group = pathGroups.find(g => g.findingType === remGroup);
                    if (!group) return null;
                    // Prefer backend ranked_controls from any path in this group, fallback to frontend catalog
                    const backendControls = group.paths.find(p => p.ranked_controls?.length > 0)?.ranked_controls;
                    const syntheticPath = {
                      id: `group:${remGroup}`,
                      finding_type: remGroup,
                      title: FL(remGroup),
                      severity: group.maxSeverity,
                      description: FD(remGroup) || `Remediate all ${group.paths.length} paths of type "${FL(remGroup)}"`,
                      blast_radius: group.totalBlast,
                      ranked_controls: backendControls || CONTROL_CATALOG_FALLBACK[remGroup] || [],
                    };
                    const workloadList = [...group.workloads].slice(0, 4);
                    return (
                      <>
                        <div className="rounded-lg px-3 py-2 mb-2"
                          style={{ background: 'rgba(124,111,240,0.06)', border: '1px solid rgba(124,111,240,0.12)' }}>
                          <div className="text-[9px] font-semibold text-nhi-text mb-1">
                            Remediating {group.paths.length} paths across {group.workloads.size} workloads
                          </div>
                          <div className="text-[8px] text-nhi-faint font-mono">
                            {workloadList.join(', ')}{group.workloads.size > 4 ? ` +${group.workloads.size - 4} more` : ''}
                          </div>
                        </div>
                        <RemediationPanel path={syntheticPath}
                          graphNodes={graphData?.nodes || []}
                          onSimResult={(overlay) => { setSimOverlay(overlay); setActiveAttackPath(null); }}
                          onEnforced={(nodeLabel, pathIds, mode, affectedNodes) => {
                            setEnforceOverlay(prev => new Set([...prev, nodeLabel, ...(affectedNodes || [])]));
                            if (mode !== 'audit') setDismissedPaths(prev => new Set([...prev, ...pathIds]));
                            setEdgeEnforceState(prev => ({ ...prev, [nodeLabel]: mode === 'audit' ? 'audit' : 'enforce' }));
                          }}
                          onClose={() => { setRemGroup(null); setSimOverlay(null); if (graphRef.current) resetHL(graphRef.current.node, graphRef.current.link); }} />
                      </>
                    );
                  })()}
                </div>


              </>
            )}
          </div>
          </div>
        )}
      </div>

      {/* Context menu */}
      {contextMenu && (
        <div style={{ position: 'fixed', left: contextMenu.x, top: contextMenu.y, zIndex: 100, background: 'rgba(10,10,15,0.95)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 8, padding: 4, minWidth: 140 }}
          onClick={() => setContextMenu(null)}>
          <button className="w-full text-left px-3 py-1.5 text-[9px] font-mono hover:bg-white/[0.04] rounded flex items-center gap-2 text-nhi-text"
            onClick={() => { selectNodeWithPaths(contextMenu.node); setPanelOpen(true); if (graphRef.current) hlNode(contextMenu.node.id, graphRef.current.node, graphRef.current.link, graphRef.current.links); }}>
            <Eye className="w-3 h-3" /> Inspect
          </button>
          <button className="w-full text-left px-3 py-1.5 text-[9px] font-mono hover:bg-white/[0.04] rounded flex items-center gap-2 text-nhi-text"
            onClick={() => { const params = new URLSearchParams(); params.set('workload', contextMenu.node.label || ''); navigate(`/access?${params.toString()}`); }}>
            <Activity className="w-3 h-3" /> View Audit Logs
          </button>
          <button className="w-full text-left px-3 py-1.5 text-[9px] font-mono hover:bg-white/[0.04] rounded flex items-center gap-2 text-nhi-text"
            onClick={() => { if (graphRef.current) hlNode(contextMenu.node.id, graphRef.current.node, graphRef.current.link, graphRef.current.links); }}>
            <GitBranch className="w-3 h-3" /> Highlight Connections
          </button>
          <button className="w-full text-left px-3 py-1.5 text-[9px] font-mono hover:bg-white/[0.04] rounded flex items-center gap-2 text-nhi-text"
            onClick={() => { navigator.clipboard?.writeText(contextMenu.node.spiffe_id || contextMenu.node.label || contextMenu.node.id); }}>
            <Lock className="w-3 h-3" /> Copy SPIFFE ID
          </button>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   Risk Summary Bar
   ═══════════════════════════════════════════ */
function RiskSummaryBar({ riskSummary, activeFilter, GRAPH_FILTERS }) {
  const { findingTypeCount, pathCount, workloadsAtRisk, unmitigatedPct } = riskSummary;
  const barColor = unmitigatedPct > 70 ? '#ef4444' : unmitigatedPct > 40 ? '#f59e0b' : '#10b981';
  const filterLabel = activeFilter ? GRAPH_FILTERS.find(f => f.key === activeFilter)?.label : null;

  return (
    <div className="rounded-lg mb-3 p-3" style={{ background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.04)' }}>
      {filterLabel && (
        <div className="text-[8px] font-bold mb-1.5 px-1.5 py-0.5 rounded inline-block"
          style={{ background: 'rgba(124,111,240,0.1)', color: '#a78bfa', letterSpacing: '0.06em' }}>
          FILTERED: {filterLabel}
        </div>
      )}
      <div className="flex items-center gap-3 text-[9px] font-mono text-nhi-muted mb-2">
        <span><strong className="text-nhi-text">{findingTypeCount}</strong> finding types</span>
        <span style={{ color: '#666' }}>|</span>
        <span><strong className="text-nhi-text">{pathCount}</strong> paths</span>
        <span style={{ color: '#666' }}>|</span>
        <span><strong className="text-nhi-text">{workloadsAtRisk}</strong> at risk</span>
      </div>
      <div className="w-full h-2 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.04)' }}>
        <div className="h-full rounded-full transition-all" style={{ width: `${unmitigatedPct}%`, background: barColor }} />
      </div>
      <div className="flex items-center justify-between mt-1">
        <span className="text-[8px] font-mono font-bold" style={{ color: barColor }}>{unmitigatedPct}% unmitigated</span>
        <span className="text-[8px] font-mono text-nhi-faint">{100 - unmitigatedPct}% resolved</span>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════
   Choke Point Card
   ═══════════════════════════════════════════ */
function ChokePointCard({ point, onSelect, isActive }) {
  const nodeIcon = point.node ? vis(point.node.type, point.node).icon : '🔗';
  return (
    <button onClick={() => onSelect(point)}
      className="flex items-center gap-2 w-full px-2.5 py-2 rounded-lg transition-all"
      style={{
        background: isActive ? 'rgba(124,111,240,0.08)' : 'rgba(255,255,255,0.01)',
        border: isActive ? '1px solid rgba(124,111,240,0.25)' : '1px solid rgba(255,255,255,0.03)',
        cursor: 'pointer', textAlign: 'left',
      }}>
      <span className="text-sm flex-shrink-0">{nodeIcon}</span>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] font-semibold font-mono truncate" style={{ color: isActive ? '#a78bfa' : '#e8e8ee' }}>{point.label}</div>
        <div className="text-[8px] text-nhi-faint">{isActive ? 'Click to clear filter' : (point.description || `Source of ${point.primary} path${point.primary !== 1 ? 's' : ''}${point.chain > 0 ? `, in ${point.chain} chains` : ''}`)}</div>
      </div>
      <span className="text-[11px] font-bold font-mono flex-shrink-0 px-1.5 py-0.5 rounded"
        style={{ background: isActive ? 'rgba(124,111,240,0.15)' : 'rgba(239,68,68,0.1)', color: isActive ? '#a78bfa' : '#ef4444' }}>
        {point.primary}
      </span>
    </button>
  );
}

/* ═══════════════════════════════════════════
   Finding Group (accordion)
   ═══════════════════════════════════════════ */
function FindingGroup({ group, expanded, onToggle, onRemediate, onPathClick, onPathRemediate, activeAttackPath }) {
  const s = SEV[group.maxSeverity] || SEV.info;
  const allEnforced = group.paths.length > 0 && group.enforcedCount === group.paths.length;
  const topControl = (group.controls || [])[0];
  // Sort paths within group by severity then blast radius
  const sortedPaths = [...group.paths].sort((a, b) => {
    const sd = (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4);
    if (sd !== 0) return sd;
    return (b.blast_radius || 0) - (a.blast_radius || 0);
  });

  return (
    <div className="rounded-lg mb-2 overflow-hidden transition-all"
      style={{
        background: allEnforced ? 'rgba(16,185,129,0.02)' : 'rgba(255,255,255,0.015)',
        border: `1px solid ${allEnforced ? 'rgba(16,185,129,0.12)' : 'rgba(255,255,255,0.06)'}`,
      }}>
      {/* Accordion header */}
      <div className="px-3 py-2.5 cursor-pointer select-none hover:bg-white/[0.02] transition-colors" onClick={onToggle}>
        <div className="flex items-center gap-2 mb-1">
          <ChevronRight className="w-3.5 h-3.5 text-nhi-faint flex-shrink-0 transition-transform duration-200" style={{ transform: expanded ? 'rotate(90deg)' : 'none' }} />
          <span className="text-[11px] font-bold flex-1 min-w-0 truncate text-nhi-text">
            {FL(group.findingType)}
          </span>
          {/* Status badges */}
          {allEnforced && (
            <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full flex items-center gap-1 flex-shrink-0"
              style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
              ENFORCED
            </span>
          )}
          {group.auditCount > 0 && !allEnforced && (
            <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full flex-shrink-0"
              style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>
              {group.auditCount} AUDIT
            </span>
          )}
          <span className="text-[7px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider flex-shrink-0"
            style={{ background: allEnforced ? 'rgba(16,185,129,0.08)' : s.bg, color: allEnforced ? '#10b981' : s.color,
              textDecoration: allEnforced ? 'line-through' : 'none', opacity: allEnforced ? 0.6 : 1 }}>
            {s.label}
          </span>
        </div>
        {/* Stats row */}
        <div className="flex items-center gap-2 ml-5.5 text-[8px] font-mono text-nhi-faint" style={{ marginLeft: 22 }}>
          <span>{group.paths.length} path{group.paths.length !== 1 ? 's' : ''}</span>
          <span style={{ color: '#666' }}>·</span>
          <span>blast: {group.totalBlast}</span>
          <span style={{ color: '#666' }}>·</span>
          <span>{group.workloads.size} workload{group.workloads.size !== 1 ? 's' : ''}</span>
        </div>
        {/* Finding description */}
        {FD(group.findingType) && (
          <div className="text-[8px] text-nhi-faint mt-0.5 leading-relaxed" style={{ marginLeft: 22 }}>
            {FD(group.findingType)}
          </div>
        )}
        {/* Top control + Remediate All */}
        <div className="flex items-center gap-2 mt-1" style={{ marginLeft: 22 }}>
          {topControl && (
            <span className="text-[8px] text-nhi-muted truncate flex-1">
              {topControl.name}
            </span>
          )}
          {group.linkedPolicies.slice(0, 2).map((pol, i) => (
            <span key={i} className="text-[7px] font-mono px-1.5 py-0.5 rounded flex-shrink-0"
              style={{ background: pol.mode === 'enforce' ? 'rgba(16,185,129,0.08)' : 'rgba(245,158,11,0.08)',
                       color: pol.mode === 'enforce' ? '#10b981' : '#f59e0b' }}>
              {pol.name?.length > 16 ? pol.name.slice(0, 14) + '..' : pol.name}
            </span>
          ))}
          {!allEnforced && (
            <button onClick={(e) => { e.stopPropagation(); onRemediate(); }}
              className="text-[8px] font-bold px-2 py-1 rounded transition-colors flex-shrink-0"
              style={{ background: 'rgba(124,111,240,0.1)', border: '1px solid rgba(124,111,240,0.2)', color: '#7c6ff0', cursor: 'pointer' }}>
              Remediate All
            </button>
          )}
        </div>
      </div>

      {/* Expanded body */}
      {expanded && (
        <div className="border-t border-white/[0.04]">
          {/* Common Controls section */}
          {group.controls.length > 0 && (
            <div className="px-3 py-2 border-b border-white/[0.04]" style={{ background: 'rgba(124,111,240,0.02)', marginLeft: 0 }}>
              <div className="text-[7px] font-bold uppercase tracking-wider text-nhi-faint mb-1.5" style={{ marginLeft: 22 }}>Common Controls</div>
              {group.controls.slice(0, 2).map(ctrl => (
                <div key={ctrl.id} className="flex items-center gap-2 mb-1" style={{ marginLeft: 22 }}>
                  <span className="text-[7px] font-bold px-1.5 py-0.5 rounded flex-shrink-0"
                    style={{ background: (ACTION_COLOR[ctrl.action_type] || '#888') + '15', color: ACTION_COLOR[ctrl.action_type] || '#888' }}>
                    {ctrl.action_type}
                  </span>
                  <span className="text-[9px] text-nhi-muted truncate">{ctrl.name}</span>
                </div>
              ))}
            </div>
          )}
          {/* Individual attack path cards — compact style */}
          <div className="px-2 py-1.5 space-y-0.5" style={{ marginLeft: 12 }}>
            {sortedPaths.map(ap => (
              <AttackPathCard key={ap.id} path={ap} compact
                active={activeAttackPath?.id === ap.id}
                onClick={() => onPathClick(ap)}
                onRemediate={() => onPathRemediate(ap)} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   Attack Path Card (with Phase 3 Remediate button)
   ═══════════════════════════════════════════ */
function AttackPathCard({ path, active, onClick, onRemediate, compact }) {
  const s = SEV[path.severity] || SEV.info;
  const rem = path.remediation;
  const isEnforced = rem?.status === 'enforced';
  const isAudit = rem?.status === 'audit';

  // Compact mode: subtle nested row inside a FindingGroup
  if (compact) {
    return (
      <div className={`rounded transition-all cursor-pointer ${active ? 'bg-white/[0.03]' : 'hover:bg-white/[0.02]'}`}
        style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}
        onClick={onClick}>
        <div className="px-2.5 py-1.5">
          <div className="flex items-center gap-2">
            {/* Status dot: green=enforced, amber=audit, gray=open */}
            <span className="w-1.5 h-1.5 rounded-full flex-shrink-0"
              style={{ background: isEnforced ? '#10b981' : isAudit ? '#f59e0b' : 'rgba(255,255,255,0.15)' }} />
            <span className={`text-[9px] font-semibold truncate flex-1 ${isEnforced ? 'text-nhi-faint line-through' : 'text-nhi-text'}`}>
              {path.title?.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || path.workload || 'Unknown'}
            </span>
            {isAudit && (
              <span className="text-[6px] font-bold px-1 py-0.5 rounded-full flex-shrink-0"
                style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>AUDIT</span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5 text-[8px] text-nhi-faint font-mono" style={{ marginLeft: 14 }}>
            {path.workload && <span>{path.workload}</span>}
            {path.blast_radius > 0 && <span>blast: {path.blast_radius}</span>}
          </div>
        </div>
        {active && (
          <div className="px-2.5 pb-2 pt-1 border-t border-white/[0.03]">
            <p className="text-[9px] text-nhi-muted leading-relaxed mb-1.5">{path.description}</p>
            {!isEnforced && (
              <button onClick={(e) => { e.stopPropagation(); onRemediate(); }}
                className="w-full py-1.5 rounded text-[9px] font-bold transition-colors"
                style={{ background: 'rgba(124,111,240,0.08)', border: '1px solid rgba(124,111,240,0.15)', color: '#7c6ff0' }}>
                {isAudit ? 'Manage Remediation' : 'Remediate'}
              </button>
            )}
          </div>
        )}
      </div>
    );
  }

  // Full mode: standalone card (top-level flat list, not nested)
  return (
    <div className={`rounded-lg overflow-hidden transition-all border ${
      isEnforced ? 'border-emerald-500/15' : isAudit ? 'border-amber-500/15' : active ? 'border-white/[0.06]' : 'border-transparent hover:border-white/[0.03]'
    }`}
      style={{
        background: isEnforced ? 'rgba(16,185,129,0.03)' : isAudit ? 'rgba(245,158,11,0.03)' : active ? 'rgba(255,255,255,0.015)' : `${s.color}04`,
        borderLeftWidth: 3,
        borderLeftColor: isEnforced ? '#10b981' : isAudit ? '#f59e0b' : s.color,
      }}>
      <div className="px-3 py-2.5 cursor-pointer" onClick={onClick}>
        <div className="flex items-center justify-between mb-1">
          <span className="text-[11px] font-bold" style={{ color: isEnforced ? '#10b981' : isAudit ? '#f59e0b' : s.color }}>
            {path.title?.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || path.finding_type || 'Unknown'}
          </span>
          <div className="flex items-center gap-1.5">
            {isEnforced && (
              <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full flex items-center gap-1"
                style={{ background: 'rgba(16,185,129,0.12)', color: '#10b981' }}>
                <span className="w-1 h-1 rounded-full bg-emerald-400" /> ENFORCED
              </span>
            )}
            {isAudit && (
              <span className="text-[7px] font-bold px-1.5 py-0.5 rounded-full flex items-center gap-1"
                style={{ background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>
                <span className="w-1 h-1 rounded-full bg-amber-400" /> AUDIT
              </span>
            )}
            <span className="text-[7px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider"
              style={{ background: isEnforced ? 'rgba(16,185,129,0.08)' : s.bg, color: isEnforced ? '#10b981' : s.color,
                textDecoration: isEnforced ? 'line-through' : 'none', opacity: isEnforced ? 0.6 : 1 }}>
              {s.label}
            </span>
          </div>
        </div>
        <p className="text-[10px] text-nhi-muted leading-relaxed">{path.description}</p>
        <div className="flex items-center gap-3 mt-1.5">
          <span className="text-[9px] font-bold font-mono" style={{ color: isEnforced ? '#10b981' : s.color }}>
            {path.blast_radius ? `Blast: ${path.blast_radius} workloads` : ''}
          </span>
          {path.workload && (
            <span className="text-[9px] text-nhi-faint font-mono">{path.workload}</span>
          )}
          <span className="text-[9px] text-nhi-faint">{(path.entry_points || []).length > 0 ? `${path.entry_points.length} entry pts` : ''}</span>
          {rem && (
            <span className="text-[9px] text-nhi-faint ml-auto">
              {rem.enforcing_count > 0 && <span className="text-emerald-400">{rem.enforcing_count} enforcing</span>}
              {rem.enforcing_count > 0 && rem.audit_count > 0 && ' · '}
              {rem.audit_count > 0 && <span className="text-amber-400">{rem.audit_count} auditing</span>}
            </span>
          )}
        </div>
      </div>
      {active && (
        <div className="px-3 pb-3 pt-1 border-t border-white/[0.03]">
          {/* Enforcement evidence */}
          {rem?.policies?.length > 0 && (
            <div className="mb-2 space-y-1">
              <span className="text-[8px] text-nhi-faint uppercase tracking-wider">Active Policies</span>
              {rem.policies.map((p, i) => (
                <div key={i} className="flex items-center gap-2 text-[9px] px-2 py-1 rounded"
                  style={{ background: p.mode === 'enforce' ? 'rgba(16,185,129,0.05)' : 'rgba(245,158,11,0.05)' }}>
                  <span className={`w-1.5 h-1.5 rounded-full ${p.mode === 'enforce' ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                  <span className="text-nhi-text font-semibold flex-1 truncate">{p.name}</span>
                  <span className="text-[8px] font-bold" style={{ color: p.mode === 'enforce' ? '#10b981' : '#f59e0b' }}>
                    {p.mode.toUpperCase()}
                  </span>
                  {p.open_violations > 0 && (
                    <span className="text-[8px] font-bold text-red-400">{p.open_violations} violations</span>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Credential chain visualization */}
          {path.credential_chain?.length > 0 && (
            <div className="mb-2">
              <span className="text-[8px] text-nhi-faint uppercase tracking-wider">Attack Chain</span>
              <div className="flex items-center gap-1 mt-1.5 overflow-x-auto">
                {path.credential_chain.map((step, i) => (
                  <React.Fragment key={i}>
                    <div className={`flex items-center gap-1 px-2 py-1 rounded text-[8px] font-mono flex-shrink-0 ${
                      step.type === 'identity' ? 'bg-violet-500/10 text-violet-400' :
                      step.type === 'credential' ? 'bg-orange-500/10 text-orange-400' :
                      'bg-cyan-500/10 text-cyan-400'
                    }`}>
                      <span>{step.type === 'identity' ? '👤' : step.type === 'credential' ? '🔑' : '🔗'}</span>
                      <span className="truncate max-w-[80px]">{step.label}</span>
                    </div>
                    {i < path.credential_chain.length - 1 && (
                      <span className="text-[8px] text-nhi-ghost flex-shrink-0">→</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Blast radius */}
          {path.blast_radius > 0 && (
            <div className="mb-2">
              <span className="text-[8px] text-nhi-faint uppercase tracking-wider">Blast Radius</span>
              <div className="mt-1 flex items-center gap-2">
                <span className="text-[10px] font-bold font-mono" style={{ color: path.blast_radius > 5 ? '#ef4444' : path.blast_radius > 3 ? '#fb923c' : '#fbbf24' }}>
                  {path.blast_radius} nodes
                </span>
                {path.affected_workloads?.length > 0 && (
                  <span className="text-[8px] text-nhi-faint">{path.affected_workloads.slice(0, 3).join(', ')}{path.affected_workloads.length > 3 ? ` +${path.affected_workloads.length - 3}` : ''}</span>
                )}
              </div>
            </div>
          )}

          {/* Ranked controls — show top control inline, rest via Remediate */}
          {path.ranked_controls?.length > 0 && !rem && (
            <div className="mb-2">
              <span className="text-[8px] text-nhi-faint uppercase tracking-wider">Recommended Control</span>
              {(() => {
                const top = path.ranked_controls[0];
                return (
                  <div className="mt-1 rounded-lg p-2 border border-accent/10" style={{ background: 'rgba(124,111,240,0.03)' }}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-semibold text-nhi-text">{top.name}</span>
                      <span className="text-[9px] font-bold font-mono text-accent">{top.score.composite}</span>
                    </div>
                    <p className="text-[8px] text-nhi-muted leading-relaxed mb-1.5">{top.description}</p>
                    <div className="flex gap-1.5 flex-wrap">
                      <span className="text-[7px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(16,185,129,0.1)', color: '#10b981' }}>
                        Break: {top.score.path_break}
                      </span>
                      <span className="text-[7px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(59,130,246,0.1)', color: '#3b82f6' }}>
                        Blast: {top.score.blast_radius}
                      </span>
                      <span className="text-[7px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(251,191,36,0.1)', color: '#fbbf24' }}>
                        Cost: {top.score.operational_cost}
                      </span>
                      <span className="text-[7px] px-1.5 py-0.5 rounded bg-white/[0.03] text-nhi-faint">
                        {top.score.feasibility === 'met' ? '✓ Feasible' : '⚠ Partial'}
                      </span>
                    </div>
                    {path.ranked_controls.length > 1 && (
                      <div className="text-[7px] text-nhi-ghost mt-1">+{path.ranked_controls.length - 1} more controls available</div>
                    )}
                  </div>
                );
              })()}
            </div>
          )}

          <button onClick={(e) => { e.stopPropagation(); onRemediate(); }}
            className="w-full py-2 rounded-lg text-[10px] font-bold transition-colors"
            style={{ background: 'rgba(124,111,240,0.1)', border: '1px solid rgba(124,111,240,0.2)', color: '#7c6ff0' }}>
            {rem ? '🛡 Manage Remediation' : '🛡 Remediate'}
          </button>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   Phase 3+4: Remediation Panel
   - Loads real deployed policy state from backend (no reset)
   - Simulation results visualized on graph via onSimResult callback
   - Flow: Deploy (audit) → Simulate (visual) → Review → Enforce
   ═══════════════════════════════════════════ */
function StepIndicator({ currentStep }) {
  const steps = ['Deploy', 'Simulate', 'Review', 'Enforce'];
  return (
    <div className="flex items-center gap-1 mb-3 px-1">
      {steps.map((step, i) => (
        <React.Fragment key={step}>
          {i > 0 && <ChevronRight className="w-2.5 h-2.5 text-nhi-faint flex-shrink-0" />}
          <span className={`text-[8px] font-bold ${i < currentStep ? 'text-emerald-400' : i === currentStep ? 'text-accent' : 'text-nhi-faint'}`}>
            {i < currentStep ? '✓ ' : ''}{step}
          </span>
        </React.Fragment>
      ))}
    </div>
  );
}


function RemediationPanel({ path, onClose, graphNodes, onSimResult, onEnforced }) {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deploying, setDeploying] = useState(null);
  // tplId → { policyId, mode, simResult }  — loaded from backend, persists across re-renders
  const [policies, setPolicies] = useState({});
  const [simulating, setSimulating] = useState(null);
  const [promoting, setPromoting] = useState(null);
  const [showAllTemplates, setShowAllTemplates] = useState(false);
  const s = SEV[path.severity] || SEV.info;

  const findingType = path.finding_type || path.id?.split(':')[0]?.replace('over-priv', 'over-privileged') || '';

  // Load templates AND check which are already deployed
  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetch(`${API}/policies/remediation/${findingType}`).then(r => r.json()),
      fetch(`${API}/policies`).then(r => r.json()),
    ]).then(([remData, polData]) => {
      const tpls = remData.templates || [];
      setTemplates(tpls);
      // Match deployed policies by template_id
      const deployed = {};
      for (const tpl of tpls) {
        const tplId = tpl.template_id || tpl.id;
        const match = (polData.policies || []).find(p => p.template_id === tplId && p.enabled);
        if (match) {
          deployed[tplId] = { policyId: match.id, mode: match.enforcement_mode || 'audit', simResult: null };
        }
      }
      setPolicies(deployed);
    }).catch(() => setTemplates([]))
      .finally(() => setLoading(false));
  }, [findingType]);

  // Step 1: Deploy in audit mode
  const handleDeploy = async (tpl) => {
    const tplId = tpl.template_id || tpl.id;
    setDeploying(tplId);
    try {
      const r = await fetch(`${API}/policies/from-template/${tplId}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforcement_mode: 'audit' }),
      });
      if (r.ok) {
        const data = await r.json();
        const policyId = data.id || data.policy?.id;
        setPolicies(prev => ({ ...prev, [tplId]: { policyId, mode: 'audit', simResult: null } }));
      }
    } catch (e) { console.error('Deploy error:', e); }
    setDeploying(null);
  };

  // Step 2: Simulate — evaluate + push overlay to graph
  const handleSimulate = async (tpl) => {
    const tplId = tpl.template_id || tpl.id;
    const pol = policies[tplId];
    if (!pol?.policyId) return;
    setSimulating(tplId);
    try {
      const r = await fetch(`${API}/policies/${pol.policyId}/evaluate`, { method: 'POST' });
      if (r.ok) {
        const data = await r.json();
        const simResult = { violations: data.violations || 0, evaluated: data.evaluated || 0, results: data.results || [] };
        setPolicies(prev => ({ ...prev, [tplId]: { ...prev[tplId], simResult } }));

        // Build graph overlay: violating workload names/ids → red, rest → green
        const violatingIds = new Set();
        const compliantIds = new Set();
        for (const v of (data.results || [])) {
          if (v.workload_id) violatingIds.add(v.workload_id);
          if (v.workload_name) violatingIds.add(v.workload_name);
        }
        // All graph nodes that are workloads and not violating = compliant
        for (const n of (graphNodes || [])) {
          if (n.group === 'workload' || n.group === 'identity') {
            if (!violatingIds.has(n.id) && !violatingIds.has(n.label)) {
              compliantIds.add(n.id);
            }
          }
        }
        if (onSimResult) onSimResult({ violatingIds, compliantIds });
      }
    } catch (e) { console.error('Simulate error:', e); }
    setSimulating(null);
  };

  // Step 3: Promote audit → enforce
  const handlePromote = async (tpl) => {
    const tplId = tpl.template_id || tpl.id;
    const pol = policies[tplId];
    if (!pol?.policyId) return;
    setPromoting(tplId);
    try {
      const r = await fetch(`${API}/policies/${pol.policyId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforcement_mode: 'enforce' }),
      });
      if (r.ok) {
        setPolicies(prev => ({ ...prev, [tplId]: { ...prev[tplId], mode: 'enforce' } }));
        // Immediately update graph visuals
        if (onEnforced) {
          const affectedNodes = new Set();
          const pathIds = [];
          if (path.workload) affectedNodes.add(path.workload);
          for (const w of (path.affected_workloads || [])) affectedNodes.add(w);
          if (path.id) pathIds.push(path.id);
          // For group remediation, collect all workloads from graphNodes matching the finding
          if (!path.workload && graphNodes) {
            for (const n of graphNodes) {
              if (n.attack_paths?.some(ap => ap.finding_type === path.finding_type)) {
                affectedNodes.add(n.label);
              }
            }
          }
          const nodeLabel = path.workload || [...affectedNodes][0] || path.title;
          onEnforced(nodeLabel, pathIds, 'enforce', [...affectedNodes]);
        }
        // Refresh graph data so path counts, scores, and summary bar update
        setTimeout(() => {
          if (typeof window.__widFetchAll === 'function') window.__widFetchAll();
        }, 1500);
      }
    } catch (e) { console.error('Promote error:', e); }
    setPromoting(null);
  };

  // Rollback enforce → audit
  const handleDemote = async (tpl) => {
    const tplId = tpl.template_id || tpl.id;
    const pol = policies[tplId];
    if (!pol?.policyId) return;
    setPromoting(tplId);
    try {
      const r = await fetch(`${API}/policies/${pol.policyId}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enforcement_mode: 'audit' }),
      });
      if (r.ok) {
        setPolicies(prev => ({ ...prev, [tplId]: { ...prev[tplId], mode: 'audit' } }));
        // Refresh graph data so path counts and summary bar update
        setTimeout(() => {
          if (typeof window.__widFetchAll === 'function') window.__widFetchAll();
        }, 1500);
      }
    } catch (e) { console.error('Demote error:', e); }
    setPromoting(null);
  };

  // Render a single policy template card (deploy → simulate → review → enforce workflow)
  const renderTemplate = (tpl) => {
        const tplId = tpl.template_id || tpl.id;
        const pol = policies[tplId];
        const isDeployed = !!pol;
        const isAudit = pol?.mode === 'audit';
        const isEnforce = pol?.mode === 'enforce';
        const sim = pol?.simResult;
        const isDeploying = deploying === tplId;
        const isSimulating = simulating === tplId;
        const isPromoting = promoting === tplId;
        const tplSev = SEV[tpl.severity] || SEV.info;
        // Determine workflow step: 0=deploy, 1=simulate, 2=review, 3=enforce
        const step = isEnforce ? 3 : sim ? 2 : isDeployed ? 1 : 0;

        return (
          <div key={tplId} className="rounded-lg mb-3 overflow-hidden transition-all"
            style={{
              background: isEnforce ? 'rgba(16,185,129,0.04)' : isDeployed ? 'rgba(124,111,240,0.03)' : 'rgba(255,255,255,0.01)',
              border: `1px solid ${isEnforce ? 'rgba(16,185,129,0.15)' : isDeployed ? 'rgba(124,111,240,0.12)' : 'rgba(255,255,255,0.04)'}`,
            }}>

            {/* Template header */}
            <div className="px-3 pt-2.5 pb-1.5">
              <div className="flex items-center justify-between mb-1">
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-semibold text-nhi-text">{tpl.name}</div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-[7px] font-mono text-nhi-faint">{tplId}</span>
                    <span className="text-[7px] font-bold px-1 rounded" style={{ background: tplSev.bg, color: tplSev.color }}>{tpl.severity}</span>
                  </div>
                </div>
                {isDeployed && (
                  <span className="text-[8px] font-bold px-2 py-0.5 rounded-full flex-shrink-0 flex items-center gap-1"
                    style={isEnforce
                      ? { background: 'rgba(16,185,129,0.12)', color: '#10b981' }
                      : { background: 'rgba(245,158,11,0.12)', color: '#f59e0b' }}>
                    <span className={`w-1.5 h-1.5 rounded-full ${isEnforce ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                    {isEnforce ? 'ENFORCING' : 'AUDIT'}
                  </span>
                )}
              </div>
              {/* Step indicator */}
              <StepIndicator currentStep={step} />
            </div>

            {/* Action area */}
            <div className="px-3 pb-3">
              {/* ── Step 0: Not deployed → Deploy button ── */}
              {!isDeployed && (
                <button onClick={() => handleDeploy(tpl)} disabled={isDeploying}
                  className="w-full py-2.5 rounded-lg text-[10px] font-bold transition-all flex items-center justify-center gap-2"
                  style={{ background: 'rgba(124,111,240,0.1)', border: '1px solid rgba(124,111,240,0.2)', color: '#7c6ff0',
                    cursor: isDeploying ? 'wait' : 'pointer' }}>
                  {isDeploying ? <><Loader className="w-3 h-3 animate-spin" /> Deploying to audit mode...</> : '🛡 Deploy in Audit Mode'}
                </button>
              )}

              {/* ── Step 1: Deployed (audit), no sim yet → Simulate ── */}
              {isAudit && !sim && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg" style={{ background: 'rgba(245,158,11,0.06)' }}>
                    <Eye className="w-3.5 h-3.5 flex-shrink-0" style={{ color: '#f59e0b' }} />
                    <span className="text-[9px] text-nhi-muted">Policy deployed in <strong className="text-nhi-text">audit mode</strong> — violations logged, traffic allowed.</span>
                  </div>
                  <button onClick={() => handleSimulate(tpl)} disabled={isSimulating}
                    className="w-full py-2.5 rounded-lg text-[10px] font-bold transition-all flex items-center justify-center gap-2"
                    style={{ background: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)', color: '#3b82f6',
                      cursor: isSimulating ? 'wait' : 'pointer' }}>
                    {isSimulating ? <><Loader className="w-3 h-3 animate-spin" /> Evaluating workloads...</> : '▶ Simulate — Show Impact on Graph'}
                  </button>
                </div>
              )}

              {/* ── Step 2: Simulation results ── */}
              {isAudit && sim && (
                <div className="space-y-2">
                  {/* Results card */}
                  <div className={`rounded-lg p-3 ${
                    sim.violations > 0 ? 'bg-red-500/5 border border-red-500/10' : 'bg-emerald-500/5 border border-emerald-500/10'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-bold text-nhi-text">Impact Analysis</span>
                      <span className="text-[11px] font-bold font-mono" style={{ color: sim.violations > 0 ? '#ef4444' : '#10b981' }}>
                        {sim.violations}/{sim.evaluated} violate
                      </span>
                    </div>

                    {/* Visual progress bar */}
                    <div className="w-full h-2.5 rounded-full bg-white/[0.04] mb-2 overflow-hidden flex">
                      {sim.evaluated > 0 && <>
                        <div className="h-full bg-emerald-500 transition-all rounded-l-full"
                          style={{ width: `${((sim.evaluated - sim.violations) / sim.evaluated) * 100}%` }} />
                        {sim.violations > 0 && <div className="h-full bg-red-500 transition-all rounded-r-full"
                          style={{ width: `${(sim.violations / sim.evaluated) * 100}%` }} />}
                      </>}
                    </div>

                    <div className="flex items-center justify-between text-[9px] mb-2">
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" /> {sim.evaluated - sim.violations} compliant
                      </span>
                      {sim.violations > 0 && (
                        <span className="text-red-400 flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3" /> {sim.violations} would violate
                        </span>
                      )}
                    </div>

                    {/* Per-workload details */}
                    {sim.violations > 0 && sim.results?.slice(0, 6).map((v, i) => (
                      <div key={i} className="flex items-center gap-2 py-1.5 text-[9px]" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
                        <span className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
                        <span className="font-mono text-nhi-text font-semibold">{v.workload_name || v.workload_id}</span>
                        <span className="text-nhi-muted truncate flex-1">{v.message}</span>
                      </div>
                    ))}
                    {sim.results?.length > 6 && (
                      <div className="text-[8px] text-nhi-faint mt-1">+{sim.results.length - 6} more</div>
                    )}

                    {sim.violations === 0 && (
                      <div className="flex items-center gap-2 text-[10px] text-emerald-400 py-1">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>All workloads compliant — <strong>graph shows all green</strong>. Safe to enforce.</span>
                      </div>
                    )}
                  </div>

                  {/* Graph hint */}
                  <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg" style={{ background: 'rgba(59,130,246,0.05)' }}>
                    <Activity className="w-3 h-3 flex-shrink-0 text-blue-400" />
                    <span className="text-[8px] text-nhi-muted">
                      Graph is showing simulation: <span className="text-emerald-400 font-bold">green</span> = compliant,
                      <span className="text-red-400 font-bold"> red</span> = would violate
                    </span>
                  </div>

                  {/* Action buttons */}
                  <div className="flex gap-2">
                    <button onClick={() => handleSimulate(tpl)}
                      className="px-3 py-2 rounded-lg text-[9px] font-semibold transition-colors"
                      style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', color: '#b0abc8' }}>
                      ↻ Re-run
                    </button>
                    <button onClick={() => handlePromote(tpl)} disabled={isPromoting}
                      className="flex-1 py-2 rounded-lg text-[10px] font-bold transition-all flex items-center justify-center gap-1.5"
                      style={{
                        background: sim.violations > 0 ? 'rgba(249,115,22,0.12)' : 'rgba(16,185,129,0.12)',
                        border: `1px solid ${sim.violations > 0 ? 'rgba(249,115,22,0.2)' : 'rgba(16,185,129,0.2)'}`,
                        color: sim.violations > 0 ? '#f97316' : '#10b981',
                        cursor: isPromoting ? 'wait' : 'pointer',
                      }}>
                      {isPromoting ? '...' : sim.violations > 0 ? '⚠ Enforce Anyway' : '✓ Promote to Enforce'}
                    </button>
                  </div>
                  {sim.violations > 0 && (
                    <div className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg" style={{ background: 'rgba(249,115,22,0.05)' }}>
                      <AlertTriangle className="w-3 h-3 flex-shrink-0 text-orange-400" />
                      <span className="text-[8px] text-nhi-muted">{sim.violations} workload(s) will be <strong className="text-red-400">blocked</strong> in enforce mode.</span>
                    </div>
                  )}
                </div>
              )}

              {/* ── Step 3: Enforcing ── */}
              {isEnforce && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 px-2.5 py-2 rounded-lg" style={{ background: 'rgba(16,185,129,0.06)' }}>
                    <Lock className="w-3.5 h-3.5 flex-shrink-0 text-emerald-400" />
                    <span className="text-[10px] text-nhi-text font-semibold">Live — violations are <strong className="text-emerald-400">blocked</strong> at the edge.</span>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => handleDemote(tpl)} disabled={isPromoting}
                      className="flex-1 py-2 rounded-lg text-[9px] font-semibold transition-colors"
                      style={{ background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.15)', color: '#f59e0b' }}>
                      {isPromoting ? '...' : '◐ Rollback to Audit'}
                    </button>
                    <button onClick={() => handleSimulate(tpl)}
                      className="flex-1 py-2 rounded-lg text-[9px] font-semibold transition-colors"
                      style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.15)', color: '#3b82f6' }}>
                      ▶ Re-evaluate
                    </button>
                  </div>
                  {sim && (
                    <div className="text-[9px] text-nhi-faint px-1">
                      Last check: <span className="font-mono font-bold" style={{ color: sim.violations > 0 ? '#ef4444' : '#10b981' }}>{sim.violations}/{sim.evaluated}</span> violations
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
  };

  // Workflow step indicator

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4" style={{ color: '#7c6ff0' }} />
          <span className="text-[12px] font-bold text-nhi-text">Remediate</span>
        </div>
        <button onClick={onClose} className="text-[10px] text-nhi-faint hover:text-nhi-muted flex items-center gap-1">
          <ChevronLeft className="w-3 h-3" /> Back
        </button>
      </div>

      {/* Finding summary */}
      <div className="rounded-lg px-3 py-2.5 mb-3" style={{ background: s.bg, borderLeft: `3px solid ${s.color}` }}>
        <div className="text-[11px] font-bold text-nhi-text mb-0.5">{path.title}</div>
        <div className="text-[9px] text-nhi-muted">{path.description}</div>
      </div>

      <div className="text-[8px] text-nhi-faint uppercase tracking-wider font-semibold mb-2">Recommended Policy Templates</div>

      {loading ? (
        <div className="flex items-center justify-center py-8 gap-2">
          <Loader className="w-3 h-3 text-accent animate-spin" /><span className="text-[10px] text-nhi-muted">Loading...</span>
        </div>
      ) : templates.length === 0 ? (
        <div className="space-y-3">
          {(path.ranked_controls || []).length > 0 ? (
            <>
              <div className="text-[8px] text-nhi-faint uppercase tracking-wider font-semibold mb-1">Remediation Commands</div>
              <div className="text-[9px] text-nhi-muted mb-2">No policy templates available. Use these CLI commands to remediate directly, then re-scan.</div>
              {(path.ranked_controls || []).map((ctrl, idx) => {
                const cp = path.cloud_provider || 'aws';
                const guide = ctrl.remediation_guide?.[cp] || ctrl.remediation_guide?.aws || ctrl.remediation_guide?.gcp;
                return (
                  <div key={ctrl.id || idx} className="rounded-lg p-3" style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-bold text-nhi-text">{ctrl.name}</span>
                      <span className="text-[7px] px-1.5 py-0.5 rounded uppercase font-bold"
                        style={{ background: 'rgba(124,111,240,0.1)', color: '#7c6ff0' }}>{ctrl.action_type}</span>
                    </div>
                    <div className="text-[8px] text-nhi-muted mb-2">{ctrl.description}</div>
                    {guide ? (
                      <>
                        <div className="text-[8px] font-semibold mb-1" style={{ color: '#7c6ff0' }}>{guide.title} ({cp.toUpperCase()})</div>
                        <div className="bg-black/30 rounded p-2 font-mono text-[8px] space-y-1" style={{ color: '#4ade80' }}>
                          {guide.steps.map((cmd, i) => <div key={i} className="break-all">$ {cmd}</div>)}
                        </div>
                        {guide.terraform && (
                          <details className="mt-2">
                            <summary className="text-[8px] text-nhi-faint cursor-pointer hover:text-nhi-muted">Terraform snippet</summary>
                            <pre className="bg-black/30 rounded p-2 font-mono text-[8px] mt-1 whitespace-pre-wrap" style={{ color: '#60a5fa' }}>{guide.terraform}</pre>
                          </details>
                        )}
                      </>
                    ) : (
                      <div className="text-[8px] text-nhi-faint italic">Manual action required — see description above</div>
                    )}
                  </div>
                );
              })}
            </>
          ) : (
            <div className="text-[10px] text-nhi-faint text-center py-8">No templates or remediation guidance available for this finding type</div>
          )}
        </div>
      ) : (() => {
        // Rank templates: deployed first, then by severity (critical > high > medium > low)
        const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const ranked = [...templates].sort((a, b) => {
          const aDeployed = policies[a.template_id || a.id] ? -1 : 0;
          const bDeployed = policies[b.template_id || b.id] ? -1 : 0;
          if (aDeployed !== bDeployed) return aDeployed - bDeployed;
          return (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
        });
        const primary = ranked[0];
        const others = ranked.slice(1);

        return (
          <>
            {/* Primary recommendation — always visible */}
            {renderTemplate(primary)}

            {/* Other templates — collapsed */}
            {others.length > 0 && (
              <div className="mt-2">
                <button onClick={() => setShowAllTemplates?.(!showAllTemplates)}
                  className="w-full text-[9px] text-nhi-faint hover:text-nhi-muted py-1.5 flex items-center justify-center gap-1 rounded-lg bg-white/[0.02] border border-white/[0.04] transition-colors">
                  {showAllTemplates ? '▾ Hide' : '▸ Show'} {others.length} more template{others.length > 1 ? 's' : ''}
                </button>
                {showAllTemplates && (
                  <div className="mt-2 space-y-2">
                    {others.map(tpl => renderTemplate(tpl))}
                  </div>
                )}
              </div>
            )}
          </>
        );
      })()}


    </div>
  );
}

/* ═══════════════════════════════════════════
   RenderedRemediationPanel — Channel tabs (CLI/Terraform/OPA) from renderer API
   ═══════════════════════════════════════════ */
function RenderedRemediationPanel({ remediation }) {
  const [activeChannel, setActiveChannel] = useState(null);
  const channels = remediation?.channels || {};
  const channelKeys = Object.keys(channels);
  const channel = activeChannel || channelKeys[0];
  const ch = channels[channel];

  if (channelKeys.length === 0) return null;

  return (
    <div style={{ marginTop: 8, borderRadius: 7, border: '1px solid rgba(96,165,250,0.12)', overflow: 'hidden' }}>
      {/* Evidence block */}
      {remediation.why_now && (
        <div style={{ padding: '6px 10px', background: 'rgba(96,165,250,0.03)', borderBottom: '1px solid rgba(96,165,250,0.08)' }}>
          <div style={{ fontSize: 8, color: '#60a5fa', fontFamily: 'monospace', fontWeight: 700, marginBottom: 3 }}>Evidence</div>
          {remediation.why_now.credential_chain?.length > 0 && (
            <div style={{ fontSize: 8, color: '#aaa', fontFamily: 'monospace', lineHeight: 1.5 }}>
              This fix targets: {remediation.why_now.credential_chain.join(' → ')}
            </div>
          )}
          <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
            {remediation.risk?.edges_removed > 0 && (
              <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 8, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.15)', color: '#10b981', fontFamily: 'monospace', fontWeight: 700 }}>
                -{remediation.risk.edges_removed} edge{remediation.risk.edges_removed !== 1 ? 's' : ''}
              </span>
            )}
            {remediation.risk?.score_impact > 0 && (
              <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 8, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.15)', color: '#10b981', fontFamily: 'monospace', fontWeight: 700 }}>
                +{remediation.risk.score_impact} score
              </span>
            )}
            {remediation.why_now.blast_radius > 0 && (
              <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 8, background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.15)', color: '#ef4444', fontFamily: 'monospace', fontWeight: 700 }}>
                blast: {remediation.why_now.blast_radius}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Channel tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.04)', background: 'rgba(0,0,0,0.15)' }}>
        {channelKeys.map(k => (
          <button key={k} onClick={() => setActiveChannel(k)} style={{
            padding: '5px 10px', fontSize: 8, fontWeight: 700, fontFamily: 'monospace',
            textTransform: 'uppercase', letterSpacing: '0.05em', cursor: 'pointer',
            background: channel === k ? 'rgba(96,165,250,0.08)' : 'transparent',
            color: channel === k ? '#60a5fa' : '#888',
            border: 'none', borderBottom: channel === k ? '2px solid #60a5fa' : '2px solid transparent',
            transition: 'all 0.2s',
          }}>{k}</button>
        ))}
      </div>

      {/* Active channel content */}
      {ch && (
        <div style={{ padding: '8px 10px' }}>
          {ch.title && (
            <div style={{ fontSize: 8, fontWeight: 700, color: '#60a5fa', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
              {ch.provider && (
                <span style={{ fontSize: 7, padding: '1px 5px', borderRadius: 8, background: 'rgba(96,165,250,0.1)', border: '1px solid rgba(96,165,250,0.2)', color: '#60a5fa', fontFamily: 'monospace', textTransform: 'uppercase' }}>
                  {ch.provider}
                </span>
              )}
              {ch.title}
            </div>
          )}
          {ch.commands?.length > 0 && (
            <div style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 5, padding: '8px 10px', fontFamily: 'monospace', fontSize: 8 }}>
              {ch.commands.map((cmd, i) => (
                <div key={i} style={{ color: '#4ade80', marginBottom: i < ch.commands.length - 1 ? 5 : 0, lineHeight: 1.5, wordBreak: 'break-all' }}>
                  <span style={{ color: '#888', marginRight: 4 }}>$</span> {cmd}
                </div>
              ))}
            </div>
          )}
          {ch.snippet && !ch.commands?.length && (
            <pre style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 5, padding: '8px 10px', fontFamily: 'monospace', fontSize: 8, color: '#60a5fa', whiteSpace: 'pre-wrap', margin: 0 }}>
              {ch.snippet}
            </pre>
          )}

          {/* Validate commands (collapsible) */}
          {ch.validate_commands?.length > 0 && (
            <details style={{ marginTop: 6 }}>
              <summary style={{ fontSize: 8, color: '#888', cursor: 'pointer', fontFamily: 'monospace' }}>Validate commands</summary>
              <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 4, padding: '6px 8px', marginTop: 4, fontFamily: 'monospace', fontSize: 7.5 }}>
                {ch.validate_commands.map((cmd, i) => (
                  <div key={i} style={{ color: '#06b6d4', marginBottom: i < ch.validate_commands.length - 1 ? 3 : 0 }}>
                    <span style={{ color: '#777', marginRight: 4 }}>$</span> {cmd}
                  </div>
                ))}
              </div>
            </details>
          )}

          {/* Rollback commands (collapsible) */}
          {ch.rollback_commands?.length > 0 && (
            <details style={{ marginTop: 4 }}>
              <summary style={{ fontSize: 8, color: '#888', cursor: 'pointer', fontFamily: 'monospace' }}>Rollback commands</summary>
              <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 4, padding: '6px 8px', marginTop: 4, fontFamily: 'monospace', fontSize: 7.5 }}>
                {ch.rollback_commands.map((cmd, i) => (
                  <div key={i} style={{ color: '#f97316', marginBottom: i < ch.rollback_commands.length - 1 ? 3 : 0 }}>
                    <span style={{ color: '#777', marginRight: 4 }}>$</span> {cmd}
                  </div>
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   ControlCard + Playbook — used by NodePanel
   ═══════════════════════════════════════════ */
// ── ImpactDelta: before→after grid, lights up green post-simulate ──────────
function ImpactDelta({ simResult, scoreNum, maxBlast }) {
  const items = [
    { label: 'Score', before: simResult?.impact?.score_before ?? scoreNum, after: simResult?.impact?.score_after ?? scoreNum, lowerBetter: false },
    { label: 'Blast',  before: simResult?.impact?.blast_before  ?? maxBlast, after: simResult?.impact?.blast_after  ?? maxBlast, lowerBetter: true  },
    { label: 'Paths',  before: simResult?.impact?.blast_before  ?? 0,        after: simResult?.impact?.attack_paths_eliminated > 0 ? 0 : (simResult?.impact?.blast_before ?? 0), lowerBetter: true },
  ];
  const active = !!simResult;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 4 }}>
      {items.map(({ label, before, after, lowerBetter }) => {
        const improved = lowerBetter ? after < before : after > before;
        const c = active ? (improved ? '#10b981' : '#f59e0b') : '#666';
        const bg = active ? (improved ? 'rgba(16,185,129,0.06)' : 'rgba(245,158,11,0.06)') : 'rgba(255,255,255,0.02)';
        const border = active ? (improved ? 'rgba(16,185,129,0.18)' : 'rgba(245,158,11,0.18)') : 'rgba(255,255,255,0.04)';
        return (
          <div key={label} style={{ textAlign: 'center', padding: '6px 4px', background: bg, border: `1px solid ${border}`, borderRadius: 6, transition: 'all 0.35s' }}>
            <div style={{ fontSize: active ? 11 : 10, fontWeight: 800, color: c, fontFamily: 'monospace', transition: 'all 0.35s', lineHeight: 1.2 }}>
              {active ? <>{before} <span style={{ fontSize: 12, opacity: 0.6 }}>→</span> {after}</> : before}
            </div>
            <div style={{ fontSize: 8, color: '#777', marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</div>
          </div>
        );
      })}
    </div>
  );
}

function ControlCard({ ctrl, rank, isTop, onSimulate, onEnforce, onAudit, simState, isEnforced, enforceRecord, scoreNum, maxBlast, recentDecisions, onNavigateAudit, renderedRemediation }) {
  const [expanded, setExpanded] = useState(isTop); // top control starts open
  const ac = ACTION_COLOR[ctrl.action_type] || '#888';
  const isMySimRunning = simState.running === ctrl.id;
  const simResult = simState.results?.[ctrl.id];
  const isMySimDone = !!simResult;
  const phase = PHASE_META[ctrl.phase || 'hardening'];
  const composite = ctrl.score?.composite ?? 0;
  const feasBg = ctrl.score?.feasibility_status === 'met' ? '#10b981'
    : ctrl.score?.feasibility_status === 'partial' ? '#f59e0b' : '#ef4444';

  // Score ring via conic-gradient
  const ringColor = composite >= 80 ? '#10b981' : composite >= 60 ? '#f59e0b' : '#ef4444';
  const ringBg = `conic-gradient(${ringColor} ${composite}%, #1a1a28 0)`;

  // Post-enforce: decisions for this workload
  const myDecisions = (recentDecisions || []).slice(0, 3);
  const decColor = { DENY: '#ef4444', ALLOW: '#10b981', WOULD_BLOCK: '#f59e0b' };

  return (
    <div style={{
      border: isEnforced ? '1px solid rgba(16,185,129,0.25)' : isTop ? '1px solid rgba(167,139,250,0.15)' : '1px solid rgba(255,255,255,0.04)',
      borderRadius: 9,
      background: isEnforced ? 'rgba(16,185,129,0.03)' : isTop ? 'rgba(167,139,250,0.02)' : 'rgba(255,255,255,0.008)',
      marginBottom: 6, overflow: 'hidden',
      transition: 'all 0.3s',
    }}>
      {/* ── Header row ── */}
      <div style={{ padding: '9px 10px', cursor: 'pointer', display: 'flex', gap: 9, alignItems: 'flex-start' }}
        onClick={() => setExpanded(e => !e)}>

        {/* Score ring */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          <div style={{ fontSize: 7, color: '#888', fontFamily: 'monospace' }}>#{rank}</div>
          <div style={{ width: 30, height: 30, borderRadius: '50%', background: ringBg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ width: 22, height: 22, borderRadius: '50%', background: '#0d0d16', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 8, fontWeight: 900, color: ringColor, fontFamily: 'monospace' }}>{composite}</span>
            </div>
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: isEnforced ? '#10b981' : '#ddd' }}>{ctrl.name}</span>
            {isEnforced && <span style={{ fontSize: 7, color: '#10b981', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', padding: '1px 6px', borderRadius: 10, fontWeight: 700 }}>● ENFORCED</span>}
          </div>
          {/* Phase + remediation type badges */}
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
            {phase && (
              <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 10, background: phase.color + '15', color: phase.color, fontWeight: 700, border: `1px solid ${phase.color}25` }}>
                {phase.label}
              </span>
            )}
            {(() => {
              const rt = ctrl.remediation_type || 'policy';
              const badges = {
                policy: { label: 'policy', color: '#7c6ff0' },
                iac: { label: 'IAM / CLI', color: '#60a5fa' },
                infra: { label: 'infra', color: '#f59e0b' },
                code_change: { label: 'code change', color: '#ec4899' },
                vendor: { label: 'vendor', color: '#f97316' },
                process: { label: 'process', color: '#8b5cf6' },
                direct: { label: 'CLI', color: '#60a5fa' },
                notify: { label: 'process', color: '#8b5cf6' },
              };
              const b = badges[rt] || badges.policy;
              return <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 10, background: b.color + '18', color: b.color, fontWeight: 700, border: `1px solid ${b.color}30` }}>{b.label}</span>;
            })()}
            {ctrl.feasibility?.automated && <span style={{ fontSize: 7, padding: '2px 6px', borderRadius: 10, background: 'rgba(16,185,129,0.06)', color: '#10b981', fontWeight: 700 }}>⚡ auto</span>}
          </div>
          <p style={{ fontSize: 9, color: '#666', lineHeight: 1.45, margin: '0 0 6px' }}>{ctrl.description}</p>

          {/* Impact delta (always visible in header) */}
          <ImpactDelta simResult={simResult} scoreNum={scoreNum} maxBlast={maxBlast} />
        </div>

        <span style={{ fontSize: 8, color: '#888', flexShrink: 0, marginTop: 4, transition: 'transform 0.15s', transform: expanded ? 'rotate(180deg)' : 'none' }}>▾</span>
      </div>

      {/* ── Expanded detail ── */}
      {expanded && (
        <div style={{ padding: '0 10px 10px', borderTop: '1px solid rgba(255,255,255,0.025)' }}>

          {/* Kills Edges */}
          {(ctrl.kills_edges || []).length > 0 && (
            <div style={{ marginTop: 8, marginBottom: 8 }}>
              {ndLabel('Severs Edges')}
              <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                {ctrl.kills_edges.map(e => (
                  <span key={e} style={{ fontSize: 8, color: '#ef4444', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.15)', padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace' }}>✂ {e}</span>
                ))}
              </div>
            </div>
          )}

          {/* Preconditions */}
          <div style={{ marginBottom: 8 }}>
            {ndLabel('Preconditions')}
            <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
              {(ctrl.feasibility?.preconditions || []).length === 0
                ? <span style={{ fontSize: 8, color: '#10b981', fontFamily: 'monospace' }}>✓ None required</span>
                : (ctrl.feasibility.preconditions).map(p => (
                  <span key={p} style={{ fontSize: 8, color: feasBg, background: feasBg + '10', border: `1px solid ${feasBg}25`, padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace' }}>
                    {ctrl.score?.feasibility_status === 'met' ? '✓' : '○'} {p}
                  </span>
                ))
              }
            </div>
          </div>

          {/* Evidence required */}
          {ctrl.evidence_requirements?.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              {ndLabel('Evidence Required')}
              <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                {ctrl.evidence_requirements.map(e => (
                  <span key={e} style={{ fontSize: 8, color: '#888', background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.04)', padding: '1px 6px', borderRadius: 3, fontFamily: 'monospace' }}>📋 {e.replace(/_/g, ' ')}</span>
                ))}
              </div>
            </div>
          )}

          {/* Rollback command */}
          {ctrl.rollback && (
            <div style={{ marginBottom: 8, padding: '6px 8px', background: 'rgba(255,255,255,0.012)', borderRadius: 4, border: '1px solid rgba(255,255,255,0.03)' }}>
              {ndLabel('Rollback')}
              <p style={{ fontSize: 9, color: '#888', lineHeight: 1.4, margin: 0, fontFamily: 'monospace' }}>{ctrl.rollback}</p>
            </div>
          )}

          {/* Rollout plan from simulate result */}
          {isMySimDone && simResult?.rollout_plan?.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              {ndLabel('Rollout Plan')}
              <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap', marginTop: 4 }}>
                {simResult.rollout_plan.map((s, i) => {
                  const isLast = i === simResult.rollout_plan.length - 1;
                  return (
                    <React.Fragment key={i}>
                      <span style={{ fontSize: 8, padding: '2px 7px', borderRadius: 10, fontFamily: 'monospace',
                        background: isLast ? 'rgba(16,185,129,0.1)' : 'rgba(167,139,250,0.08)',
                        color: isLast ? '#10b981' : '#a78bfa',
                        border: `1px solid ${isLast ? 'rgba(16,185,129,0.2)' : 'rgba(167,139,250,0.15)'}` }}>
                        {s.label || s}
                      </span>
                      {i < simResult.rollout_plan.length - 1 && <span style={{ fontSize: 8, color: '#888', alignSelf: 'center' }}>→</span>}
                    </React.Fragment>
                  );
                })}
              </div>
              {simResult.safe_to_enforce
                ? <p style={{ fontSize: 8, color: '#10b981', margin: '5px 0 0', fontFamily: 'monospace' }}>✓ 0 predicted denies — safe to enforce immediately</p>
                : <p style={{ fontSize: 8, color: '#f59e0b', margin: '5px 0 0', fontFamily: 'monospace' }}>⚠ {simResult.predicted_denies} predicted denies — review before enforcing</p>
              }
            </div>
          )}

          {/* ── Simulated WOULD_BLOCK decisions preview ── */}
          {isMySimDone && !isEnforced && simResult?.predicted_denies > 0 && (
            <div style={{ marginTop: 6, marginBottom: 4 }}>
              {ndLabel('Simulated Decisions (WOULD_BLOCK)')}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 3 }}>
                {(ctrl.kills_edges || ['credential.use']).slice(0, 3).map((edge, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 7px', borderRadius: 4, borderLeft: '2px solid #f59e0b', background: 'rgba(245,158,11,0.03)' }}>
                    <span style={{ fontSize: 7, fontWeight: 700, color: '#f59e0b', fontFamily: 'monospace', minWidth: 60 }}>WOULD_BLOCK</span>
                    <span style={{ fontSize: 7.5, color: '#666', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, fontFamily: 'monospace' }}>{typeof edge === 'string' ? edge.split(/\s*[-→]+\s*/)[0] : edge}</span>
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 7, color: '#888', margin: '3px 0 0', fontFamily: 'monospace', textAlign: 'center' }}>Deploy in AUDIT mode to see real traffic decisions</p>
            </div>
          )}

          {/* ── Post-enforce: inline proof record ── */}
          {isEnforced && enforceRecord ? (
            <div style={{ marginTop: 8 }}>
              {/* Impact delta */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 4, marginBottom: 8 }}>
                {[
                  { label: 'SCORE', before: enforceRecord.simResult?.impact?.score_before ?? scoreNum, after: enforceRecord.simResult?.impact?.score_after ?? scoreNum, up: true },
                  { label: 'BLAST', before: enforceRecord.simResult?.impact?.blast_before ?? maxBlast, after: enforceRecord.simResult?.impact?.blast_after ?? maxBlast, up: false },
                  { label: 'PATHS', before: enforceRecord.pathsKilled + (0), after: 0, up: false },
                  { label: 'DENIES', before: '—', after: myDecisions.filter(d => d.decision === 'DENY').length, up: false },
                ].map(({ label, before, after, up }) => {
                  const improved = up ? after > before : after < before;
                  const color = improved ? '#10b981' : after === before ? '#888' : '#f59e0b';
                  return (
                    <div key={label} style={{ background: 'rgba(16,185,129,0.04)', border: '1px solid rgba(16,185,129,0.1)', borderRadius: 5, padding: '5px 0', textAlign: 'center' }}>
                      <div style={{ fontSize: 7, color: '#888', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.06em', fontFamily: 'monospace' }}>{label}</div>
                      <div style={{ fontSize: 9, fontFamily: 'monospace', color }}>
                        <span style={{ color: '#777' }}>{before}</span>
                        <span style={{ color: '#666', margin: '0 2px' }}>→</span>
                        <span style={{ fontWeight: 700 }}>{after}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Severed edges diagram */}
              {(ctrl.kills_edges || []).length > 0 && (
                <div style={{ marginBottom: 8, padding: '7px 9px', background: 'rgba(239,68,68,0.03)', border: '1px solid rgba(239,68,68,0.1)', borderRadius: 6 }}>
                  {ndLabel('✂ Severed Access Paths')}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginTop: 4 }}>
                    {ctrl.kills_edges.slice(0, 4).map((e, i) => {
                      const parts = e.split(/\s*[-→]+\s*/);
                      const src = parts[0] || e;
                      const dst = parts[1] || '';
                      return (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 8, fontFamily: 'monospace' }}>
                          <span style={{ color: '#666', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90 }}>{src}</span>
                          <span style={{ color: '#ef4444', flexShrink: 0, fontSize: 9, fontWeight: 700 }}>──✂──</span>
                          <span style={{ color: '#888', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{dst || 'access blocked'}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Last 3 decisions inline */}
              {myDecisions.length > 0 ? (
                <div style={{ marginBottom: 6 }}>
                  {ndLabel('🔴 Recent Decisions')}
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 4 }}>
                    {myDecisions.map((entry, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 7px', borderRadius: 4, borderLeft: `2px solid ${decColor[entry.decision] || '#64748b'}`, background: entry.decision === 'DENY' ? 'rgba(239,68,68,0.03)' : 'rgba(16,185,129,0.03)' }}>
                        <span style={{ fontSize: 6.5, color: '#777', flexShrink: 0, fontFamily: 'monospace' }}>{new Date(entry.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                        <span style={{ fontSize: 7.5, fontWeight: 700, color: decColor[entry.decision] || '#64748b', flexShrink: 0, fontFamily: 'monospace', minWidth: 30 }}>{entry.decision}</span>
                        <span style={{ fontSize: 7.5, color: '#666', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{entry.action}</span>
                        {entry.ttl && <span style={{ fontSize: 6.5, color: '#10b981', flexShrink: 0 }}>TTL:{entry.ttl}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ marginBottom: 6, padding: '6px 8px', borderRadius: 5, background: 'rgba(255,255,255,0.015)', border: '1px solid rgba(255,255,255,0.04)', textAlign: 'center' }}>
                  <p style={{ fontSize: 8, color: '#888', fontFamily: 'monospace', margin: 0 }}>Policy live — waiting for first request</p>
                </div>
              )}

              {/* Access Events deep link */}
              <button onClick={() => onNavigateAudit && onNavigateAudit(enforceRecord.workload, ctrl.name, enforceRecord.ts, enforceRecord.traceId)}
                style={{ width: '100%', padding: '5px 0', fontSize: 8, fontFamily: 'monospace', fontWeight: 600, background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 5, color: '#60a5fa', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                <span>→ Full audit log in Access Events</span>
                {myDecisions.length > 0 && <span style={{ fontSize: 7, color: '#3b82f6', background: 'rgba(59,130,246,0.1)', padding: '1px 5px', borderRadius: 8 }}>{myDecisions.length} events</span>}
              </button>
            </div>
          ) : ['iac', 'infra', 'direct'].includes(ctrl.remediation_type) ? (
            /* ── IAM/Infrastructure action: show cloud-specific CLI/Terraform commands ── */
            <div style={{ marginTop: 6 }}>
              {/* Type-specific header */}
              <div style={{ fontSize: 8, color: ctrl.remediation_type === 'infra' ? '#f59e0b' : '#60a5fa', fontWeight: 600, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ fontSize: 9 }}>{ctrl.remediation_type === 'infra' ? '\u{1F3D7}' : '\u{1F527}'}</span>
                {ctrl.remediation_type === 'infra' ? 'Infrastructure change required — run via Terraform or cloud console' : 'IAM change required — run via CLI or Terraform'}
              </div>
              {/* Prefer rendered remediation (DB-backed with channel tabs) if available */}
              {renderedRemediation && Object.keys(renderedRemediation.channels || {}).length > 0 ? (
                <RenderedRemediationPanel remediation={renderedRemediation} />
              ) : (() => {
                const cp = ctrl.cloud_provider || 'gcp';
                const guide = ctrl.remediation_guide?.[cp] || ctrl.remediation_guide?.aws || ctrl.remediation_guide?.gcp;
                if (!guide) return (
                  <div style={{ padding: '8px', background: 'rgba(96,165,250,0.04)', border: '1px solid rgba(96,165,250,0.12)', borderRadius: 6, textAlign: 'center' }}>
                    <span style={{ fontSize: 8, color: '#60a5fa', fontFamily: 'monospace' }}>{ctrl.remediation_type === 'infra' ? 'Infrastructure change' : 'IAM change'} — run in your cloud console</span>
                  </div>
                );
                return (
                  <>
                    <div style={{ fontSize: 8, fontWeight: 700, color: '#60a5fa', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ fontSize: 7, padding: '1px 5px', borderRadius: 8, background: 'rgba(96,165,250,0.1)', border: '1px solid rgba(96,165,250,0.2)', color: '#60a5fa', fontFamily: 'monospace', textTransform: 'uppercase' }}>{cp}</span>
                      {guide.title}
                    </div>
                    <div style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 5, padding: '8px 10px', fontFamily: 'monospace', fontSize: 8 }}>
                      {guide.steps.map((cmd, i) => (
                        <div key={i} style={{ color: '#4ade80', marginBottom: i < guide.steps.length - 1 ? 5 : 0, lineHeight: 1.5, wordBreak: 'break-all' }}>
                          <span style={{ color: '#888', marginRight: 4 }}>$</span> {cmd}
                        </div>
                      ))}
                    </div>
                    {guide.terraform && (
                      <details style={{ marginTop: 6 }}>
                        <summary style={{ fontSize: 8, color: '#888', cursor: 'pointer', fontFamily: 'monospace' }}>Terraform</summary>
                        <pre style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 5, padding: '8px 10px', fontFamily: 'monospace', fontSize: 8, color: '#60a5fa', whiteSpace: 'pre-wrap', marginTop: 4 }}>{guide.terraform}</pre>
                      </details>
                    )}
                  </>
                );
              })()}
            </div>
          ) : ctrl.remediation_type === 'code_change' ? (
            /* ── Code change: developer must modify application ── */
            <div style={{ marginTop: 6 }}>
              <div style={{ fontSize: 8, color: '#ec4899', fontWeight: 600, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ fontSize: 9 }}>{'\u{1F4BB}'}</span> Application code change required
              </div>
              {renderedRemediation && Object.keys(renderedRemediation.channels || {}).length > 0 ? (
                <RenderedRemediationPanel remediation={renderedRemediation} />
              ) : (() => {
                const cp = ctrl.cloud_provider || 'gcp';
                const guide = ctrl.remediation_guide?.[cp] || ctrl.remediation_guide?.aws || ctrl.remediation_guide?.gcp;
                if (!guide) return (
                  <div style={{ padding: '8px', background: 'rgba(236,72,153,0.04)', border: '1px solid rgba(236,72,153,0.12)', borderRadius: 6, textAlign: 'center' }}>
                    <span style={{ fontSize: 8, color: '#ec4899', fontFamily: 'monospace' }}>Developer must implement changes in the application</span>
                  </div>
                );
                return (
                  <>
                    <div style={{ fontSize: 8, fontWeight: 700, color: '#ec4899', marginBottom: 4 }}>{guide.title}</div>
                    <div style={{ background: 'rgba(0,0,0,0.35)', borderRadius: 5, padding: '8px 10px', fontFamily: 'monospace', fontSize: 8 }}>
                      {guide.steps.map((step, i) => (
                        <div key={i} style={{ color: '#f9a8d4', marginBottom: i < guide.steps.length - 1 ? 5 : 0, lineHeight: 1.5, wordBreak: 'break-all' }}>
                          <span style={{ color: '#888', marginRight: 4 }}>{i + 1}.</span> {step}
                        </div>
                      ))}
                    </div>
                  </>
                );
              })()}
            </div>
          ) : ctrl.remediation_type === 'vendor' ? (
            /* ── Vendor: external party must take action ── */
            <div style={{ marginTop: 6, padding: '8px 10px', background: 'rgba(249,115,22,0.04)', border: '1px solid rgba(249,115,22,0.12)', borderRadius: 6 }}>
              <span style={{ fontSize: 8, color: '#f97316', fontFamily: 'monospace', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ fontSize: 10 }}>{'\u{1F3E2}'}</span> Vendor action required — contact the service provider to rotate or reconfigure credentials
              </span>
            </div>
          ) : ['process', 'notify'].includes(ctrl.remediation_type) ? (
            /* ── Process: human triage / organizational action required ── */
            <div style={{ marginTop: 6, padding: '8px 10px', background: 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.12)', borderRadius: 6 }}>
              <span style={{ fontSize: 8, color: '#8b5cf6', fontFamily: 'monospace', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ fontSize: 10 }}>{'\u{1F4CB}'}</span> Organizational process — assign owner, create ticket, or conduct access review
              </span>
              {ctrl.remediation_guide && (() => {
                const cp = ctrl.cloud_provider || 'gcp';
                const guide = ctrl.remediation_guide?.[cp] || ctrl.remediation_guide?.aws || ctrl.remediation_guide?.gcp;
                if (!guide) return null;
                return (
                  <div style={{ marginTop: 6, background: 'rgba(0,0,0,0.25)', borderRadius: 5, padding: '6px 8px', fontFamily: 'monospace', fontSize: 8 }}>
                    {guide.steps.map((step, i) => (
                      <div key={i} style={{ color: '#a78bfa', marginBottom: i < guide.steps.length - 1 ? 4 : 0, lineHeight: 1.5 }}>
                        <span style={{ color: '#888', marginRight: 4 }}>{i + 1}.</span> {step}
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          ) : (
            <>
              {/* Action buttons — 3-stage flow: Simulate → Audit → Enforce */}
              <div style={{ display: 'flex', gap: 5, marginTop: 6 }}>
                <button onClick={() => onSimulate(ctrl)} disabled={isMySimRunning || isEnforced}
                  style={{ flex: 1, padding: '7px 0', fontSize: 9, fontWeight: 700, fontFamily: 'monospace',
                    background: isMySimRunning ? 'rgba(124,111,240,0.03)' : 'rgba(124,111,240,0.08)',
                    border: '1px solid rgba(124,111,240,0.2)', borderRadius: 6,
                    color: (isMySimRunning || isEnforced) ? '#666' : '#a78bfa',
                    cursor: (isMySimRunning || isEnforced) ? 'default' : 'pointer', transition: 'all 0.2s' }}>
                  {isMySimRunning ? '⏳ …' : isMySimDone ? '↺ SIM' : '▶ SIM'}
                </button>
                <button onClick={() => onAudit && onAudit(ctrl)} disabled={!isMySimDone || isEnforced}
                  title="Deploy in audit mode — logs violations, traffic still flows"
                  style={{ flex: 1, padding: '7px 0', fontSize: 9, fontWeight: 700, fontFamily: 'monospace',
                    background: isMySimDone ? 'rgba(245,158,11,0.1)' : 'rgba(245,158,11,0.02)',
                    border: `1px solid rgba(245,158,11,${isMySimDone ? '0.3' : '0.06'})`,
                    borderRadius: 6, color: isMySimDone ? '#f59e0b' : '#665a30',
                    cursor: isMySimDone ? 'pointer' : 'default', transition: 'all 0.2s' }}>
                  ◐ AUDIT
                </button>
                <button onClick={() => onEnforce(ctrl)} disabled={!isMySimDone || isEnforced}
                  style={{ flex: 1, padding: '7px 0', fontSize: 9, fontWeight: 700, fontFamily: 'monospace',
                    background: isMySimDone ? 'rgba(16,185,129,0.1)' : 'rgba(16,185,129,0.02)',
                    border: `1px solid rgba(16,185,129,${isMySimDone ? '0.3' : '0.06'})`,
                    borderRadius: 6, color: isMySimDone ? '#10b981' : '#306a4a',
                    cursor: isMySimDone ? 'pointer' : 'default', transition: 'all 0.2s' }}>
                  ⚡ ENFORCE
                </button>
              </div>
              {!isMySimDone && (
                <p style={{ fontSize: 7, color: '#666', margin: '4px 0 0', textAlign: 'center', fontFamily: 'monospace' }}>▶ SIM → ◐ AUDIT → ⚡ ENFORCE</p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// ── Playbook: split into Policy Remediations vs IAM/CLI Remediations ──────
function Playbook({ controls, simState, onSimulate, onEnforce, onAudit, enforced, enforceLog, scoreNum, maxBlast, recentDecisions, onNavigateAudit, renderedRemediations, onAddCustomPolicy }) {
  // Split controls into policy-deployable vs infrastructure/manual
  const policyControls = controls.filter(c => c.remediation_type === 'policy' && c.template_id);
  const cliControls = controls.filter(c => c.remediation_type !== 'policy' || !c.template_id);

  let globalRank = 0;

  const renderSection = (items, isPolicy) => {
    if (!items.length) return null;
    // Within each section, group by phase
    const byPhase = { containment: [], hardening: [], structural: [] };
    for (const c of items) byPhase[c.phase || 'hardening'].push(c);

    return Object.entries(byPhase).map(([phase, phaseItems]) => {
      if (!phaseItems.length) return null;
      const meta = PHASE_META[phase];
      return (
        <div key={`${isPolicy ? 'pol' : 'cli'}-${phase}`} style={{ marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 7, padding: '5px 8px', background: meta.color + '08', border: `1px solid ${meta.color}15`, borderRadius: 5 }}>
            <div style={{ width: 18, height: 18, borderRadius: 4, background: meta.color + '18', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
              <span style={{ fontSize: 9, fontWeight: 900, color: meta.color, fontFamily: 'monospace' }}>{phase === 'containment' ? '🚨' : phase === 'hardening' ? '🔒' : '🏗'}</span>
            </div>
            <div>
              <div style={{ fontSize: 10, fontWeight: 700, color: meta.color }}>{meta.label}</div>
              <div style={{ fontSize: 8, color: '#777' }}>{meta.desc}</div>
            </div>
            <span style={{ marginLeft: 'auto', fontSize: 9, color: '#666', fontFamily: 'monospace' }}>{phaseItems.length}</span>
          </div>
          {phaseItems.map((ctrl) => {
            globalRank++;
            const matchedRemediation = (renderedRemediations || []).find(r => r.intent_id === ctrl.id);
            return (
              <ControlCard
                key={ctrl.id}
                ctrl={ctrl}
                rank={globalRank}
                isTop={globalRank === 1}
                simState={simState}
                onSimulate={onSimulate}
                onEnforce={onEnforce}
                onAudit={onAudit}
                isEnforced={!!enforced[ctrl.id]}
                enforceRecord={(enforceLog || []).find(r => r.ctrl?.id === ctrl.id)}
                recentDecisions={recentDecisions}
                onNavigateAudit={onNavigateAudit}
                scoreNum={scoreNum}
                maxBlast={maxBlast}
                renderedRemediation={matchedRemediation}
              />
            );
          })}
        </div>
      );
    });
  };

  return (
    <div>
      {/* Policy Remediations — enforceable via WID */}
      {policyControls.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, padding: '6px 10px', background: 'rgba(124,111,240,0.06)', border: '1px solid rgba(124,111,240,0.15)', borderRadius: 6 }}>
            <span style={{ fontSize: 11 }}>⚡</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#a78bfa' }}>Policy Remediations</div>
              <div style={{ fontSize: 8, color: '#888' }}>Deploy as live policies — WID will monitor or block traffic</div>
            </div>
            <span style={{ fontSize: 9, color: '#a78bfa', fontFamily: 'monospace', fontWeight: 700, marginRight: 4 }}>{policyControls.length}</span>
            {onAddCustomPolicy && (
              <button onClick={onAddCustomPolicy}
                style={{ fontSize: 8, fontWeight: 700, fontFamily: 'monospace', color: '#a78bfa', background: 'rgba(124,111,240,0.12)', border: '1px solid rgba(124,111,240,0.25)', borderRadius: 5, padding: '3px 8px', cursor: 'pointer', whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 3 }}>
                + Custom Policy
              </button>
            )}
          </div>
          {renderSection(policyControls, true)}
        </div>
      )}

      {/* IAM/CLI Remediations — manual infrastructure changes */}
      {cliControls.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, padding: '6px 10px', background: 'rgba(96,165,250,0.06)', border: '1px solid rgba(96,165,250,0.15)', borderRadius: 6 }}>
            <span style={{ fontSize: 11 }}>🔧</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#60a5fa' }}>IAM / CLI Remediations</div>
              <div style={{ fontSize: 8, color: '#888' }}>Require infrastructure changes — follow steps or export to IaC</div>
            </div>
            <span style={{ fontSize: 9, color: '#60a5fa', fontFamily: 'monospace', fontWeight: 700 }}>{cliControls.length}</span>
          </div>
          {renderSection(cliControls, false)}
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════
   Empty State
   ═══════════════════════════════════════════ */
function EmptyState({ icon: Icon, color, title, sub, children }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <Icon className="w-8 h-8 mb-3" style={{ color: color, opacity: 0.2 }} />
      <p className="text-[11px] text-nhi-muted font-semibold">{title}</p>
      <p className="text-[9px] text-nhi-faint mt-1">{sub}</p>
      {children}
    </div>
  );
}

/* ═══════════════════════════════════════════
   CollapsibleSection
   ═══════════════════════════════════════════ */
function CollapsibleSection({ id, title, icon, badge, collapsed, onToggle, accentColor, children }) {
  return (
    <div style={{ marginBottom: 2, borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
      <div onClick={onToggle}
        style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 10px', cursor: 'pointer', userSelect: 'none' }}
        onMouseEnter={e => e.currentTarget.style.background = 'rgba(255,255,255,0.02)'}
        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
        <ChevronRight className="w-3 h-3 flex-shrink-0 transition-transform duration-150"
          style={{ color: accentColor || '#888', transform: collapsed ? 'none' : 'rotate(90deg)' }} />
        {icon && <span style={{ fontSize: 11, flexShrink: 0 }}>{icon}</span>}
        <span style={{ fontSize: 11, fontWeight: 700, color: '#e8e8ee', flex: 1, fontFamily: 'monospace', letterSpacing: '0.02em' }}>{title}</span>
        {badge && <span style={{ fontSize: 8, fontWeight: 700, padding: '1px 5px', borderRadius: 8, background: (accentColor || '#666') + '15', color: accentColor || '#666', fontFamily: 'monospace' }}>{badge}</span>}
      </div>
      {!collapsed && <div style={{ padding: '0 10px 10px' }}>{children}</div>}
    </div>
  );
}

/* ═══════════════════════════════════════════
   NodePanel — Single Scrollable Inspector
   Replaces the old dual-tab NodeDetail
   ═══════════════════════════════════════════ */
function NodePanel({ node, rels, nodes, timeline = [], enforceLogStream = [], dismissedPaths,
  onSimResult, onEnforced, onNavigateAudit, onAddCustomPolicy, onClose,
  collapsedSections, setCollapsedSections, edgeEnforceState, setActiveAttackPath: setActiveAttackPathProp }) {

  const [enforced, setEnforced] = useState({});
  const [simState, setSimState] = useState({ running: null, results: {} });
  const [enforceFlash, setEnforceFlash] = useState(null);
  const [enforceLog, setEnforceLog] = useState([]);
  const cumulativeScoreBonusRef = useRef(0);
  const [rollbackLoading, setRollbackLoading] = useState(false);
  const [renderedRemediations, setRenderedRemediations] = useState([]);

  const toggleSection = (key) => setCollapsedSections(prev => ({ ...prev, [key]: !prev[key] }));

  // Fetch rendered remediation from backend (Phase 2: renderer API)
  useEffect(() => {
    const nodeId = node.workload_id || node.label || node.id;
    if (!nodeId || !(node.attack_paths?.length > 0)) {
      setRenderedRemediations([]);
      return;
    }
    let cancelled = false;
    fetch(`/api/v1/graph/remediation/${encodeURIComponent(nodeId)}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (!cancelled && data?.remediations) setRenderedRemediations(data.remediations);
      })
      .catch(() => { if (!cancelled) setRenderedRemediations([]); });
    return () => { cancelled = true; };
  }, [node.id, node.workload_id, node.label, node.attack_paths?.length]);

  // Derive node display props
  const v = vis(node.type, node);
  const isCredential = node.nhi_bucket === 'credential' || node.workload_type === 'credential';
  const isResource = node.nhi_bucket === 'resource' || node.workload_type === 'external-resource';
  const connected = rels.filter(r => sid(r.source) === node.id || sid(r.target) === node.id);

  // Connection display: runtime traffic + attack path correlation
  const [expandedCats, setExpandedCats] = useState(new Set());
  const [expandedEvidence, setExpandedEvidence] = useState(new Set());
  const [runtimeMap, setRuntimeMap] = useState({});
  useEffect(() => {
    if (!node.label) return;
    let cancelled = false;
    setExpandedCats(new Set());
    setExpandedEvidence(new Set());
    fetch(`/api/v1/access/decisions/live?workload=${encodeURIComponent(node.label)}&limit=500`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (cancelled || !data?.decisions) return;
        const map = {};
        for (const d of data.decisions) {
          const s = (d.source_name || '').toLowerCase();
          const t = (d.destination_name || '').toLowerCase();
          const key = `${s}::${t}`;
          if (!map[key]) map[key] = { total: 0, allow: 0, deny: 0 };
          map[key].total++;
          if (d.verdict === 'allow' || d.verdict === 'granted') map[key].allow++;
          else if (d.verdict === 'deny' || d.verdict === 'denied') map[key].deny++;
        }
        setRuntimeMap(map);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [node.id, node.label]);

  // Attack paths
  const _rawAttackPaths = node.attack_paths || [];
  const _dismissedSet = dismissedPaths instanceof Set ? dismissedPaths : new Set(dismissedPaths || []);
  const attackPaths = _rawAttackPaths.filter(ap => !ap.id || !_dismissedSet.has(ap.id));

  // Attack path node labels — for connection badges
  const attackPathNodeLabels = useMemo(() => {
    const labels = new Set();
    for (const ap of _rawAttackPaths) {
      if (ap.workload) labels.add(ap.workload.toLowerCase());
      for (const w of (ap.affected_workloads || [])) labels.add(w.toLowerCase());
      for (const ep of (ap.entry_points || [])) labels.add(ep.toLowerCase());
    }
    return labels;
  }, [_rawAttackPaths]);

  const isOnAttackPath = useCallback((r, other) => {
    if (r.critical) return true;
    return attackPathNodeLabels.has((other?.label || '').toLowerCase());
  }, [attackPathNodeLabels]);

  // Connection groups — categorized, sorted, with attack path counts
  const connGroups = useMemo(() => {
    const groups = new Map();
    for (const r of connected) {
      const meta = CONNECTION_CATEGORIES[r.type] || { cat: 'other', label: 'OTHER', color: '#64748b' };
      if (!groups.has(meta.cat)) groups.set(meta.cat, { meta, edges: [] });
      groups.get(meta.cat).edges.push(r);
    }
    // Sort edges within each group: attack-path first, then critical, then alphabetical
    for (const g of groups.values()) {
      g.edges.sort((a, b) => {
        const aOther = nodes.find(n => n.id === (sid(a.source) === node.id ? sid(a.target) : sid(a.source)));
        const bOther = nodes.find(n => n.id === (sid(b.source) === node.id ? sid(b.target) : sid(b.source)));
        const aOn = isOnAttackPath(a, aOther) ? 1 : 0;
        const bOn = isOnAttackPath(b, bOther) ? 1 : 0;
        if (aOn !== bOn) return bOn - aOn;
        if ((a.critical ? 1 : 0) !== (b.critical ? 1 : 0)) return (b.critical ? 1 : 0) - (a.critical ? 1 : 0);
        return (aOther?.label || '').localeCompare(bOther?.label || '');
      });
    }
    return CAT_ORDER
      .filter(cat => groups.has(cat))
      .map(cat => groups.get(cat))
      .concat([...groups.values()].filter(g => !CAT_ORDER.includes(g.meta.cat)));
  }, [connected, node.id, nodes, isOnAttackPath]);

  const totalAttackPathEdges = useMemo(() => {
    let count = 0;
    for (const r of connected) {
      const otherId = sid(r.source) === node.id ? sid(r.target) : sid(r.source);
      const other = nodes.find(n => n.id === otherId);
      if (isOnAttackPath(r, other)) count++;
    }
    return count;
  }, [connected, node.id, nodes, isOnAttackPath]);

  // All controls across ALL attack paths
  const allControls = [];
  const seenCtrl = new Set();
  for (const ap of _rawAttackPaths) {
    for (const ctrl of (ap.ranked_controls || [])) {
      if (!seenCtrl.has(ctrl.id)) { seenCtrl.add(ctrl.id); allControls.push(ctrl); }
    }
  }
  allControls.sort((a, b) => (b.score?.composite || 0) - (a.score?.composite || 0));

  const backendEnforcedPaths = _rawAttackPaths.filter(ap => ap.remediation?.status === 'enforced');
  const hasBackendEnforcement = backendEnforcedPaths.length > 0;

  // KPIs
  const maxBlast = _rawAttackPaths.reduce((m, ap) => Math.max(m, ap.blast_radius || 0), 0);
  const credCount = node.credential_summary?.count || (isCredential ? 1 : 0);
  const scoreNum = node.score || 0;

  // Restore enforce state from backend
  useEffect(() => {
    const restored = {};
    for (const ap of _rawAttackPaths) {
      if (ap.remediation?.status === 'enforced') {
        for (const ctrl of (ap.ranked_controls || [])) restored[ctrl.id] = true;
      }
    }
    if (Object.keys(restored).length > 0) {
      setEnforced(prev => {
        const merged = { ...prev, ...restored };
        return JSON.stringify(merged) === JSON.stringify(prev) ? prev : merged;
      });
    }
  }, [node.id]);

  // Live KPIs
  const enforcedCount = Object.values(enforced).filter(Boolean).length;
  const backendScoreBonus = hasBackendEnforcement
    ? Math.min(100 - scoreNum, backendEnforcedPaths.length > 0
        ? Math.round(allControls.slice(0, Math.min(allControls.length, backendEnforcedPaths.length)).reduce((s, c) => s + (c.score?.composite || 60) * 0.5, 0) / Math.max(1, backendEnforcedPaths.length) * Math.min(backendEnforcedPaths.length, 3))
        : 0)
    : 0;
  const effectiveBonus = Math.min(100 - scoreNum, Math.max(cumulativeScoreBonusRef.current, backendScoreBonus));
  const liveScore = effectiveBonus > 0 ? Math.min(100, scoreNum + effectiveBonus) : scoreNum;
  const allBackendEnforced = hasBackendEnforcement && backendEnforcedPaths.length === _rawAttackPaths.length && _rawAttackPaths.length > 0;
  const liveBlast = enforcedCount > 0
    ? Math.max(0, maxBlast - allControls.slice(0, enforcedCount).reduce((s, c) => s + (c.path_break?.edges_severed || c.path_break?.severed || 1), 0) * 2)
    : (hasBackendEnforcement ? 0 : maxBlast);
  const livePaths = attackPaths.filter(ap => ap.remediation?.status !== 'enforced').length;
  const liveGrade = liveScore >= 85 ? 'A' : liveScore >= 70 ? 'B' : liveScore >= 55 ? 'C' : liveScore >= 40 ? 'D' : 'F';
  const liveGradeColor = liveScore >= 85 ? '#10b981' : liveScore >= 70 ? '#f59e0b' : '#ef4444';

  // Credential & AI data
  const credSummary = node.credential_summary;
  const nodeCredential = node.credential;
  const aiData = node.ai_enrichment || node.meta || {};
  const detectedTools = aiData.detected_tools || aiData.tools || [];
  const isAIAgent = node.type === 'a2a-agent' || node.type === 'mcp-server' || aiData.is_ai_agent;

  // ── Semantic KPI computations ──────────────────────────────────
  const WORKLOAD_NODE_TYPES = new Set(['cloud-run', 'cloud-run-service', 'a2a-agent', 'mcp-server', 'lambda', 'ec2', 'container', 'pod', 'workload']);
  const totalWorkloads = nodes.filter(n => WORKLOAD_NODE_TYPES.has(n.type)).length || 1;
  const staticCredCount = credSummary?.static_count || 0;
  const topCtrlForKpi = allControls[0];
  const topControlPathsBreak = topCtrlForKpi ? (topCtrlForKpi.path_break?.edges_severed || 1) : 0;
  const projectedBlast = Math.max(0, maxBlast - topControlPathsBreak * 2);
  // Worst-severity path for chain display
  const worstPath = [..._rawAttackPaths].sort((a, b) => (SEV_ORDER[a.severity] || 4) - (SEV_ORDER[b.severity] || 4))[0];
  const displayChain = worstPath?.credential_chain || attackPaths[0]?.credential_chain || [];

  // Moved up: needed by kpis
  const allEnforced = allBackendEnforced || (allControls.length > 0 && allControls.every(c => enforced[c.id]));

  // Semantic KPI array
  const kpis = (() => {
    const scoreColor = liveScore >= 80 ? SEM.good : liveScore >= 55 ? SEM.warn : SEM.bad;
    const blastPct = totalWorkloads > 0 ? liveBlast / totalWorkloads : 0;
    const blastColor = liveBlast === 0 ? SEM.good : blastPct > 0.15 ? SEM.bad : SEM.warn;
    const pathsColor = livePaths === 0 ? SEM.good : livePaths > 3 ? SEM.bad : SEM.warn;
    const credsColor = staticCredCount > 0 ? SEM.bad : credCount > 0 ? SEM.warn : SEM.good;

    const hasDelta = enforcedCount > 0 || hasBackendEnforcement;
    return [
      { key: 'score', value: liveScore, label: 'Score', color: allEnforced ? SEM.good : scoreColor,
        sub: liveGrade, delta: hasDelta ? { from: scoreNum, to: liveScore } : null },
      { key: 'blast', value: liveBlast, label: 'Blast', color: allEnforced ? SEM.good : blastColor,
        sub: `/${totalWorkloads}`, delta: hasDelta && liveBlast !== maxBlast ? { from: maxBlast, to: liveBlast } : null },
      { key: 'paths', value: livePaths, label: 'Paths', color: allEnforced ? SEM.good : pathsColor,
        sub: null, delta: livePaths !== _rawAttackPaths.length ? { from: _rawAttackPaths.length, to: livePaths } : null },
      { key: 'creds', value: credCount, label: 'Creds', color: allEnforced ? SEM.good : credsColor,
        sub: staticCredCount > 0 ? `${staticCredCount} static` : null, delta: null },
    ];
  })();

  // ── Simulate a control ───────────────────────────────────────
  const handleSimulate = (ctrl) => {
    setSimState(s => ({ ...s, running: ctrl.id }));
    setTimeout(() => {
      const predictedDenies = ctrl.simulate?.predicted_deny_rate > 0 ? Math.round(20 * ctrl.simulate.predicted_deny_rate) : 0;
      const scoreGain = Math.round((ctrl.risk_reduction_score || ctrl.score?.composite || 60) * 0.5);
      const edgesCut = ctrl.path_break?.edges_severed || ctrl.kills_edges?.length || 1;
      const result = {
        safe_to_enforce: predictedDenies === 0, predicted_denies: predictedDenies,
        impacted_clients: predictedDenies > 0 ? ['api-gateway'] : [],
        impact: { score_before: scoreNum, score_after: Math.min(100, scoreNum + scoreGain), blast_before: maxBlast, blast_after: Math.max(1, maxBlast - edgesCut * 2), attack_paths_eliminated: edgesCut > 0 ? 1 : 0 },
        rollout_plan: (ctrl.simulate?.rollout || ['audit-24h', 'enforce']).map((s, i) => ({ step: i + 1, label: s.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()), duration: s.includes('24h') ? '24 hours' : s.includes('7d') ? '7 days' : 'varies', desc: '' })),
      };
      setSimState(s => ({ ...s, running: null, results: { ...s.results, [ctrl.id]: result } }));
      if (onSimResult) {
        const violatingIds = new Set([node.id, node.label]);
        for (const ap of attackPaths) { for (const w of (ap.affected_workloads || [])) violatingIds.add(w); }
        onSimResult({ violatingIds, compliantIds: new Set() });
      }
    }, 400);
  };

  const handleAudit = async (ctrl) => {
    if (!simState.results[ctrl.id]) return;
    // Create policy in audit mode so state persists across refresh
    if (ctrl.template_id) {
      try {
        const matchedAP = attackPaths.find(ap => (ap.ranked_controls || []).some(c => c.id === ctrl.id));
        await fetch(`${API}/policies/from-template/${ctrl.template_id}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enforcement_mode: 'audit',
            workload: node.label,
            client_workload_id: node.workload_id || null,
            attack_path_id: matchedAP?.id || null,
          }),
        });
      } catch (_) { /* non-fatal */ }
    }
    const killedAPs = attackPaths.filter(ap => (ap.ranked_controls || []).some(c => c.id === ctrl.id));
    const killedPaths = killedAPs.map(ap => ap.id).filter(Boolean);
    const affectedNodes = new Set([node.label, node.id]);
    for (const ap of killedAPs) {
      for (const w of (ap.affected_workloads || [])) affectedNodes.add(w);
      for (const n of (ap.credential_chain || [])) { if (n.label) affectedNodes.add(n.label); if (n.id) affectedNodes.add(n.id); }
    }
    if (onEnforced) onEnforced(node.label, killedPaths, 'audit', [...affectedNodes]);
  };

  const handleEnforce = async (ctrl) => {
    if (!simState.results[ctrl.id]) return;
    const ts = new Date().toISOString();
    setEnforced(e => ({ ...e, [ctrl.id]: true }));
    setEnforceFlash(ctrl.id);
    setTimeout(() => setEnforceFlash(null), 2200);
    const scoreGain = Math.round((ctrl.score?.composite || 60) * 0.5);
    cumulativeScoreBonusRef.current += scoreGain;

    const killedAPs = attackPaths.filter(ap => (ap.ranked_controls || []).some(c => c.id === ctrl.id));
    const killedPaths = killedAPs.map(ap => ap.id).filter(Boolean);
    const affectedNodes = new Set([node.label, node.id]);
    for (const ap of killedAPs) {
      for (const w of (ap.affected_workloads || [])) affectedNodes.add(w);
      for (const n of (ap.credential_chain || [])) { if (n.label) affectedNodes.add(n.label); if (n.id) affectedNodes.add(n.id); }
    }
    if (onEnforced) onEnforced(node.label, killedPaths, 'enforce', [...affectedNodes]);

    let policyId = null;
    try {
      if (ctrl.template_id) {
        const matchedAP = killedAPs[0];
        const r = await fetch(`${API}/policies/from-template/${ctrl.template_id}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enforcement_mode: 'enforce',
            workload: node.label,
            client_workload_id: node.workload_id || null,
            attack_path_id: matchedAP?.id || null,
          }),
        });
        if (r.ok) { const data = await r.json(); policyId = data.id || data.policy?.id || null; }
      }
    } catch (_) { /* non-fatal */ }

    // Post batch decisions with trace context
    const traceId = `trace-${Date.now()}-${Math.random().toString(36).slice(2, 8)}-enforce`;
    const apDesc = killedAPs[0]?.description || '';
    const targetMatch = apDesc.match(/for\s+(\S+)\s*\(/);
    const target = targetMatch ? `${targetMatch[1]} API` : ctrl.name || 'External API';
    const spiffeId = node.spiffe_id || `spiffe://company.com/docker/container/${node.label}`;
    const trustLevel = node.trust_level || node.trust || 'medium';
    const ttlSec = trustLevel === 'cryptographic' ? 3600 : trustLevel === 'high' ? 1800 : 900;
    const sharedToken = { attestation_method: 'abac-multi-signal', trust_level: trustLevel, valid: true, spiffe_id: spiffeId, algorithm: 'HS256', issuer: 'wid-platform://wid-platform.local', audience: 'wid-gateway://wid-platform.local', ttl_seconds: ttlSec };
    const credName = killedAPs[0]?.credential_chain?.[0]?.label || 'STATIC_API_KEY';
    const vaultPath = `secret/data/wid/${node.label.replace(/[^a-zA-Z0-9-]/g, '-')}/${target.replace(/\s+/g, '-').toLowerCase()}`;
    try {
      const baseId = `dec-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      await fetch(`${API}/access/decisions/batch`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ entries: [
          { decision_id: `${baseId}-baseline`, source_name: node.label, destination_name: target, source_principal: spiffeId, destination_principal: target, method: 'GET', path_pattern: '/api/*', verdict: 'allow', policy_name: 'baseline-allow', adapter_mode: 'simulate', enforcement_action: 'FORWARD_REQUEST', enforcement_detail: 'Baseline: traffic flowing with static credential', latency_ms: 2, trace_id: traceId, hop_index: 0, total_hops: 3, token_context: { ...sharedToken, phase: 'baseline' }, request_context: { source: node.label, destination: target, method: 'GET', path: '/api/*', wid_token: 'none' }, response_context: { verdict: 'allow', enforcement: 'FORWARD_REQUEST', policy_name: 'baseline-allow', latency_ms: 2, reason: 'No policy active' } },
          { decision_id: `${baseId}-audit`, source_name: node.label, destination_name: target, source_principal: spiffeId, destination_principal: target, method: 'GET', path_pattern: '/api/*', verdict: 'deny', policy_name: ctrl.name || 'audit-policy', adapter_mode: 'audit', enforcement_action: 'MONITOR', enforcement_detail: 'Audit: static credential violation detected', latency_ms: 3, trace_id: traceId, hop_index: 1, total_hops: 3, parent_decision_id: `${baseId}-baseline`, token_context: { ...sharedToken, phase: 'audit' }, request_context: { source: node.label, destination: target, method: 'GET', path: '/api/*', wid_token: 'attached (HS256)' }, response_context: { verdict: 'deny', enforcement: 'MONITOR', policy_name: ctrl.name || 'audit-policy', latency_ms: 3, reason: 'Static credential detected — WOULD_BLOCK in enforce mode' } },
          { decision_id: `${baseId}-enforce`, source_name: node.label, destination_name: target, source_principal: spiffeId, destination_principal: target, method: 'GET', path_pattern: '/api/*', verdict: 'deny', policy_name: ctrl.name || 'enforce-policy', adapter_mode: 'enforce', enforcement_action: 'REJECT_REQUEST', enforcement_detail: 'Enforce: static credential rejected', latency_ms: 1, trace_id: traceId, hop_index: 2, total_hops: 3, parent_decision_id: `${baseId}-audit`, token_context: { ...sharedToken, phase: 'enforce', jit_ttl_seconds: ttlSec, vault_path: vaultPath }, request_context: { source: node.label, destination: target, method: 'GET', path: '/api/*', wid_token: 'required (HS256)', credential_broker: { status: 'redirect', vault_path: vaultPath, ttl: `${ttlSec}s` } }, response_context: { verdict: 'deny', enforcement: 'REJECT_REQUEST', policy_name: ctrl.name || 'enforce-policy', latency_ms: 1, reason: 'Static credential REJECTED' } },
        ]}),
      });
    } catch (batchErr) { console.warn('[enforce] batch decisions POST failed:', batchErr.message); }

    setEnforceLog(prev => [{ ctrl, ts, traceId, policyId, pathsKilled: killedPaths.length, workload: node.label, simResult: simState.results[ctrl.id] }, ...prev]);
  };

  const handleRollback = async () => {
    setRollbackLoading(true);
    try {
      const policyIds = new Set();
      for (const ap of _rawAttackPaths) {
        if (ap.remediation?.status === 'enforced') {
          for (const p of (ap.remediation.policies || [])) { if (p.id) policyIds.add(p.id); }
          if (ap.remediation.policy_id) policyIds.add(ap.remediation.policy_id);
        }
      }
      for (const entry of enforceLog) { if (entry.policyId) policyIds.add(entry.policyId); }
      for (const pid of policyIds) {
        await fetch(`${API}/policies/${pid}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enforcement_mode: 'audit' }) });
      }
      setEnforced({}); cumulativeScoreBonusRef.current = 0; setEnforceLog([]); setSimState({ running: null, results: {} });
      const affectedNodes = new Set([node.label, node.id]);
      for (const ap of _rawAttackPaths) {
        if (ap.remediation?.status === 'enforced') {
          for (const w of (ap.affected_workloads || [])) affectedNodes.add(w);
          for (const n of (ap.credential_chain || [])) { if (n.label) affectedNodes.add(n.label); }
        }
      }
      const killedPaths = _rawAttackPaths.filter(ap => ap.remediation?.status === 'enforced').map(ap => ap.id).filter(Boolean);
      if (onEnforced) onEnforced(node.label, killedPaths, 'audit', [...affectedNodes]);
      setTimeout(() => { if (typeof window.__widFetchAll === 'function') window.__widFetchAll(); }, 1500);
    } catch (e) { console.error('Rollback failed:', e); }
    finally { setRollbackLoading(false); }
  };

  // Top control for Quick Action Bar
  const topCtrl = allControls.find(c => !enforced[c.id]) || allControls[0];
  const topSimResult = topCtrl ? simState.results?.[topCtrl.id] : null;
  const topSimDone = !!topSimResult;
  const topEnforced = topCtrl ? !!enforced[topCtrl.id] : false;
  const topSimRunning = simState.running === topCtrl?.id;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* ── Node Header ── */}
      <div style={{ padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <div style={{ width: 34, height: 34, borderRadius: 9, background: `${v.color}10`, border: `1px solid ${v.color}22`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, flexShrink: 0 }}>
            {isCredential ? '🗝️' : isResource ? '🔗' : v.icon}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#e8e8ee', fontFamily: 'monospace', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.label}</div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
              <span style={{ fontSize: 9, color: v.color, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{isCredential ? 'Credential' : isResource ? 'External Resource' : v.label}</span>
              {node.trust && node.trust !== 'none' && ndChip(`🔐 ${node.trust}`, TRUST_COLORS[node.trust] || '#888')}
              {isAIAgent && ndChip('🤖 AI', '#8b5cf6')}
              {node.classification === 'rogue' && ndChip('🚨 ROGUE', '#ef4444')}
              {node.classification === 'zombie' && ndChip('💀 ZOMBIE', '#6b7280')}
              {node.classification === 'shadow' && ndChip('👁 SHADOW', '#f97316')}
              {node.classification === 'orphan' && ndChip('🔗 ORPHAN', '#a855f7')}
              {node.classification === 'managed' && !node.is_publicly_exposed && !node.is_unused_iam && ndChip('✓ MANAGED', '#10b981')}
              {node.is_publicly_exposed && ndChip('🌐 PUBLIC', '#eab308')}
              {node.is_unused_iam && ndChip('🔑 UNUSED', '#a855f7')}
            </div>
          </div>
          {/* Grade */}
          {!isCredential && !isResource && (
            <div style={{ width: 38, height: 38, borderRadius: 9, background: `${liveGradeColor}10`, border: `2px solid ${liveGradeColor}28`, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flexShrink: 0, transition: 'all 0.5s' }}>
              <span style={{ fontSize: 18, fontWeight: 900, color: liveGradeColor, lineHeight: 1, fontFamily: 'monospace' }}>{liveGrade}</span>
              <span style={{ fontSize: 6, color: liveGradeColor, opacity: 0.7, fontFamily: 'monospace' }}>{liveScore}</span>
            </div>
          )}
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, flexShrink: 0 }}>
            <X className="w-3.5 h-3.5" style={{ color: '#888' }} />
          </button>
        </div>
      </div>

      {/* ── KPI Strip ── */}
      {attackPaths.length > 0 && (
        <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.03)', flexShrink: 0 }}>
          {/* Enforce success toast */}
          <div style={{ overflow: 'hidden', maxHeight: enforceFlash ? 40 : 0, opacity: enforceFlash ? 1 : 0, transition: 'all 0.35s ease', marginBottom: enforceFlash ? 6 : 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 6 }}>
              <span style={{ fontSize: 12 }}>⚡</span>
              <span style={{ fontSize: 9, fontWeight: 700, color: '#10b981', fontFamily: 'monospace' }}>Control enforced · Risk score updated</span>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 4 }}>
            {kpis.map(({ key, value, label, color, sub, delta }) => {
              const isFlashing = enforceFlash && (key === 'score' || key === 'blast');
              return (
                <div key={key} style={{
                  background: isFlashing ? 'rgba(16,185,129,0.06)' : `${color}08`,
                  border: isFlashing ? '1px solid rgba(16,185,129,0.2)' : `1px solid ${color}18`,
                  borderRadius: 5, padding: '5px 0', textAlign: 'center', transition: 'all 0.5s',
                }}>
                  {delta ? (
                    <div style={{ fontSize: 11, fontWeight: 900, fontFamily: 'monospace', lineHeight: 1, transition: 'color 0.5s' }}>
                      <span style={{ color: SEM.neutral }}>{delta.from}</span>
                      <span style={{ color: SEM.neutral, margin: '0 1px' }}>{'\u2192'}</span>
                      <span style={{ color: SEM.good }}>{delta.to}</span>
                      {delta.from !== delta.to && (
                        <span style={{ fontSize: 8, color: SEM.good, marginLeft: 2 }}>
                          {'\u25BC'}{Math.abs(delta.from - delta.to)}
                        </span>
                      )}
                    </div>
                  ) : (
                    <div style={{ fontSize: 16, fontWeight: 900, color, lineHeight: 1, fontFamily: 'monospace', transition: 'color 0.5s' }}>{value}</div>
                  )}
                  <div style={{ fontSize: 8, color: '#888', marginTop: 1, textTransform: 'uppercase', letterSpacing: '0.06em', fontFamily: 'monospace' }}>
                    {label}
                  </div>
                  {sub && (
                    <div style={{ fontSize: 7, color: color, opacity: 0.7, fontFamily: 'monospace', marginTop: 1 }}>{sub}</div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Quick Action Bar ── */}
      {topCtrl && !allEnforced && (
        <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.03)', flexShrink: 0 }}>
          <div style={{ fontSize: 9, color: '#888', fontFamily: 'monospace', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{topCtrl.name}</div>
          {/* ── Stepper indicator ── */}
          {(() => {
            const step = topEnforced ? 3 : edgeEnforceState?.[node.label] === 'audit' ? 2 : topSimDone ? 1 : 0;
            const dots = [
              { label: 'SIM', color: '#a78bfa' },
              { label: 'AUDIT', color: '#f59e0b' },
              { label: 'ENFORCE', color: '#10b981' },
            ];
            return (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0, marginBottom: 6 }}>
                {dots.map((dot, i) => (
                  <React.Fragment key={dot.label}>
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
                      <div style={{
                        width: 8, height: 8, borderRadius: '50%',
                        background: i < step ? dot.color : i === step ? dot.color + '40' : '#2a2a3a',
                        border: `1.5px solid ${i <= step ? dot.color : '#2a2a3a'}`,
                        boxShadow: i === step ? `0 0 6px ${dot.color}40` : 'none',
                        transition: 'all 0.3s',
                      }} />
                      <span style={{ fontSize: 6, color: i <= step ? dot.color : '#666', fontFamily: 'monospace', fontWeight: 600 }}>{dot.label}</span>
                    </div>
                    {i < 2 && (
                      <div style={{
                        width: 24, height: 1.5, marginBottom: 10,
                        background: i < step ? dots[i + 1].color : '#2a2a3a',
                        transition: 'all 0.3s',
                      }} />
                    )}
                  </React.Fragment>
                ))}
              </div>
            );
          })()}
          <div style={{ display: 'flex', gap: 4 }}>
            <button onClick={() => handleSimulate(topCtrl)} disabled={topSimRunning || topEnforced}
              style={{ flex: 1, padding: '6px 0', fontSize: 10, fontWeight: 700, fontFamily: 'monospace', background: topSimRunning ? 'rgba(124,111,240,0.03)' : topSimDone ? 'rgba(124,111,240,0.04)' : 'rgba(124,111,240,0.08)', border: topSimDone ? '1px solid rgba(124,111,240,0.1)' : '1px solid rgba(124,111,240,0.2)', borderRadius: 5, color: (topSimRunning || topEnforced) ? '#666' : topSimDone ? '#7c6ff080' : '#a78bfa', cursor: (topSimRunning || topEnforced) ? 'default' : 'pointer' }}>
              {topSimDone ? '✓ SIM' : topSimRunning ? '⏳ …' : '▶ SIM'}
            </button>
            <button onClick={() => handleAudit(topCtrl)} disabled={!topSimDone || topEnforced}
              style={{ flex: 1, padding: '6px 0', fontSize: 10, fontWeight: 700, fontFamily: 'monospace', background: topSimDone ? 'rgba(245,158,11,0.1)' : 'rgba(245,158,11,0.02)', border: `1px solid rgba(245,158,11,${topSimDone ? '0.3' : '0.06'})`, borderRadius: 5, color: topSimDone ? '#f59e0b' : '#665a30', cursor: topSimDone ? 'pointer' : 'default' }}>
              ◐ AUDIT
            </button>
            <button onClick={() => handleEnforce(topCtrl)} disabled={!topSimDone || topEnforced}
              style={{ flex: 1, padding: '6px 0', fontSize: 10, fontWeight: 700, fontFamily: 'monospace', background: topSimDone ? 'rgba(16,185,129,0.1)' : 'rgba(16,185,129,0.02)', border: `1px solid rgba(16,185,129,${topSimDone ? '0.3' : '0.06'})`, borderRadius: 5, color: topSimDone ? '#10b981' : '#306a4a', cursor: topSimDone ? 'pointer' : 'default' }}>
              ⚡ ENFORCE
            </button>
          </div>
          {topSimDone && (
            <div style={{ marginTop: 4, fontSize: 9, fontFamily: 'monospace' }}>
              {topSimResult.safe_to_enforce
                ? <span style={{ color: '#10b981' }}>✓ 0 predicted denies — safe to enforce</span>
                : <span style={{ color: '#f59e0b' }}>⚠ {topSimResult.predicted_denies} predicted denies</span>}
            </div>
          )}
          {!topSimDone && <p style={{ fontSize: 8, color: '#666', margin: '3px 0 0', fontFamily: 'monospace', textAlign: 'center' }}>▶ SIM → ◐ AUDIT → ⚡ ENFORCE</p>}
        </div>
      )}
      {/* MANAGED banner when all enforced */}
      {allEnforced && allControls.length > 0 && (
        <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(16,185,129,0.1)', flexShrink: 0, background: 'rgba(16,185,129,0.03)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Shield size={13} color="#10b981" />
            <span style={{ fontSize: 10, fontWeight: 700, color: '#10b981', fontFamily: 'monospace' }}>MANAGED</span>
            <span style={{ fontSize: 8, color: '#888' }}>All {allControls.length} control{allControls.length !== 1 ? 's' : ''} enforced</span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
              <button onClick={() => onNavigateAudit && onNavigateAudit(node.label)} style={{ fontSize: 8, fontFamily: 'monospace', fontWeight: 600, background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 4, color: '#60a5fa', cursor: 'pointer', padding: '2px 6px' }}>Logs</button>
              <button onClick={handleRollback} disabled={rollbackLoading} style={{ fontSize: 8, fontFamily: 'monospace', fontWeight: 600, background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.15)', borderRadius: 4, color: rollbackLoading ? '#666' : '#f59e0b', cursor: rollbackLoading ? 'default' : 'pointer', padding: '2px 6px' }}>
                {rollbackLoading ? '…' : '↩ Rollback'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Scrollable Sections ── */}
      <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>

        {/* ▼ THREAT BRIEF ─────────────────────────────────────── */}
        <CollapsibleSection id="threatBrief" title="Threat Brief" icon="⚡" accentColor="#ef4444"
          badge={attackPaths.length > 0 ? `${attackPaths.length} paths` : null}
          collapsed={collapsedSections.threatBrief} onToggle={() => toggleSection('threatBrief')}>

          {/* Shadow IT banner */}
          {node.is_shadow && (
            <div style={{ padding: '8px 10px', background: 'rgba(249,115,22,0.04)', border: '1px solid rgba(249,115,22,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                <span style={{ fontSize: 11 }}>👁</span>
                <span style={{ fontSize: 9, color: '#f97316', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Shadow IT</span>
                {node.metadata?.shadow_score > 0 && <span style={{ fontSize: 8, color: 'rgba(249,115,22,0.5)', fontFamily: 'monospace' }}>score: {node.metadata.shadow_score}</span>}
              </div>
              {(() => {
                const reasons = node.metadata?.shadow_reasons || node.shadow_reasons || [];
                const parsed = Array.isArray(reasons) ? reasons : typeof reasons === 'string' ? (() => { try { return JSON.parse(reasons); } catch { return []; } })() : [];
                return parsed.length > 0 ? (
                  <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    {parsed.map((r, i) => (
                      <span key={i} style={{ fontSize: 7, color: '#f97316', background: 'rgba(249,115,22,0.06)', border: '1px solid rgba(249,115,22,0.12)', padding: '1px 6px', borderRadius: 8, fontFamily: 'monospace' }}>{r}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 8, color: 'rgba(249,115,22,0.6)' }}>Missing governance attributes (owner, team, environment)</div>
                );
              })()}
            </div>
          )}

          {/* Zombie IT banner */}
          {node.is_dormant && (
            <div style={{ padding: '8px 10px', background: 'rgba(107,114,128,0.04)', border: '1px solid rgba(107,114,128,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                <span style={{ fontSize: 11 }}>💀</span>
                <span style={{ fontSize: 9, color: '#6b7280', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Zombie IT</span>
                {node.dormancy_score > 0 && <span style={{ fontSize: 8, color: 'rgba(107,114,128,0.5)', fontFamily: 'monospace' }}>score: {Math.round(node.dormancy_score)}</span>}
              </div>
              {(() => {
                const reasons = node.dormancy_reasons || [];
                const parsed = Array.isArray(reasons) ? reasons : typeof reasons === 'string' ? (() => { try { return JSON.parse(reasons); } catch { return []; } })() : [];
                return parsed.length > 0 ? (
                  <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    {parsed.map((r, i) => (
                      <span key={i} style={{ fontSize: 7, color: '#6b7280', background: 'rgba(107,114,128,0.06)', border: '1px solid rgba(107,114,128,0.12)', padding: '1px 6px', borderRadius: 8, fontFamily: 'monospace' }}>{r}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 8, color: 'rgba(107,114,128,0.6)' }}>No recorded activity for an extended period</div>
                );
              })()}
            </div>
          )}

          {/* Rogue IT banner */}
          {node.is_rogue && (
            <div style={{ padding: '8px 10px', background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                <span style={{ fontSize: 11 }}>🚨</span>
                <span style={{ fontSize: 9, color: '#ef4444', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Rogue IT</span>
                {node.rogue_score > 0 && <span style={{ fontSize: 8, color: 'rgba(239,68,68,0.5)', fontFamily: 'monospace' }}>score: {Math.round(node.rogue_score)}</span>}
              </div>
              {(() => {
                const reasons = node.rogue_reasons || [];
                const parsed = Array.isArray(reasons) ? reasons : typeof reasons === 'string' ? (() => { try { return JSON.parse(reasons); } catch { return []; } })() : [];
                return parsed.length > 0 ? (
                  <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    {parsed.map((r, i) => (
                      <span key={i} style={{ fontSize: 7, color: '#ef4444', background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.12)', padding: '1px 6px', borderRadius: 8, fontFamily: 'monospace' }}>{r}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 8, color: 'rgba(239,68,68,0.6)' }}>Bypassing governance controls</div>
                );
              })()}
            </div>
          )}

          {/* Public Exposure banner */}
          {node.is_publicly_exposed && (
            <div style={{ padding: '8px 10px', background: 'rgba(234,179,8,0.04)', border: '1px solid rgba(234,179,8,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 4 }}>
                <span style={{ fontSize: 11 }}>🌐</span>
                <span style={{ fontSize: 9, color: '#eab308', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Publicly Exposed</span>
              </div>
              {(() => {
                const reasons = node.exposure_reasons || [];
                const parsed = Array.isArray(reasons) ? reasons : typeof reasons === 'string' ? (() => { try { return JSON.parse(reasons); } catch { return []; } })() : [];
                return parsed.length > 0 ? (
                  <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                    {parsed.map((r, i) => (
                      <span key={i} style={{ fontSize: 7, color: '#eab308', background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.12)', padding: '1px 6px', borderRadius: 8, fontFamily: 'monospace' }}>{r}</span>
                    ))}
                  </div>
                ) : null;
              })()}
            </div>
          )}

          {/* Unused IAM banner */}
          {node.is_unused_iam && (
            <div style={{ padding: '8px 10px', background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 2 }}>
                <span style={{ fontSize: 11 }}>🔑</span>
                <span style={{ fontSize: 9, color: '#a855f7', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Unused IAM</span>
              </div>
              <div style={{ fontSize: 8, color: 'rgba(168,85,247,0.6)' }}>
                Identity has not been used in over 90 days. Consider reviewing permissions or scheduling deletion.
              </div>
            </div>
          )}

          {/* Orphan identity banner */}
          {node.is_orphan && (
            <div style={{ padding: '8px 10px', background: 'rgba(168,85,247,0.04)', border: '1px solid rgba(168,85,247,0.15)', borderRadius: 7, marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 2 }}>
                <span style={{ fontSize: 11 }}>🔗</span>
                <span style={{ fontSize: 9, color: '#a855f7', fontWeight: 700, fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  {node.is_service_linked ? 'Service-Linked Role' : 'Orphan Identity'}
                </span>
              </div>
              <div style={{ fontSize: 8, color: 'rgba(168,85,247,0.6)' }}>
                {node.is_service_linked
                  ? 'Auto-created by AWS. No direct relationships to workloads.'
                  : 'No relationships detected. May be unused or require further scanning.'}
              </div>
            </div>
          )}

          {/* All enforced banner */}
          {!isCredential && !isResource && allBackendEnforced && (
            <div style={{ padding: '12px 10px', background: 'rgba(16,185,129,0.04)', border: '1px solid rgba(16,185,129,0.15)', borderRadius: 7, textAlign: 'center', marginBottom: 8 }}>
              <Shield size={18} color="#10b981" style={{ margin: '0 auto 6px' }} />
              <div style={{ fontSize: 9, color: '#10b981', fontFamily: 'monospace', fontWeight: 700 }}>All {backendEnforcedPaths.length} attack paths remediated</div>
              <div style={{ fontSize: 8, color: '#888' }}>Controls enforced — risk mitigated</div>
            </div>
          )}

          {/* No attack paths at all */}
          {!isCredential && !isResource && _rawAttackPaths.length === 0 && (
            <div style={{ padding: '12px 10px', background: 'rgba(16,185,129,0.04)', border: '1px solid rgba(16,185,129,0.1)', borderRadius: 7, textAlign: 'center' }}>
              <div style={{ fontSize: 16, marginBottom: 4 }}>🛡</div>
              <div style={{ fontSize: 9, color: '#10b981', fontFamily: 'monospace', fontWeight: 700 }}>No attack paths detected</div>
            </div>
          )}

          {/* Risk Summary — only when unresolved paths exist */}
          {_rawAttackPaths.length > 0 && !allBackendEnforced && (
            <>
              {ndLabel("Risk Summary")}
              <p style={{ fontSize: 9, color: '#888', fontFamily: 'monospace', margin: '0 0 6px', lineHeight: 1.4 }}>
                {maxBlast} workload{maxBlast !== 1 ? 's' : ''} at risk via {credSummary?.count || 0} exposed credential{(credSummary?.count || 0) !== 1 ? 's' : ''}
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5, marginBottom: 8 }}>
                <div style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.1)', borderRadius: 6, padding: 8 }}>
                  <div style={{ fontSize: 22, fontWeight: 900, color: '#ef4444', lineHeight: 1, fontFamily: 'monospace' }}>{maxBlast}</div>
                  <div style={{ fontSize: 9, color: '#888', marginBottom: 4 }}>workloads at risk</div>
                  {(attackPaths[0]?.affected_workloads || []).slice(0, 3).map(w => (
                    <div key={w} style={{ display: 'flex', alignItems: 'center', gap: 3, marginBottom: 1 }}>
                      <div style={{ width: 3, height: 3, borderRadius: '50%', background: '#ef4444', flexShrink: 0 }} />
                      <span style={{ fontSize: 8, color: '#666', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{w}</span>
                    </div>
                  ))}
                </div>
                <div style={{ background: 'rgba(249,115,22,0.04)', border: '1px solid rgba(249,115,22,0.1)', borderRadius: 6, padding: 8 }}>
                  <div style={{ fontSize: 22, fontWeight: 900, color: '#f97316', lineHeight: 1, fontFamily: 'monospace' }}>{credSummary?.count || 0}</div>
                  <div style={{ fontSize: 9, color: '#888', marginBottom: 4 }}>exposed credentials</div>
                  {(credSummary?.providers || []).map(p => (
                    <div key={p} style={{ fontSize: 8, color: '#777', fontFamily: 'monospace' }}>{p}</div>
                  ))}
                </div>
              </div>

            </>
          )}

          {/* Findings summary — always visible, shows enforced status */}
          {/* Skip classification-based findings already shown as banners above */}
          {_rawAttackPaths.length > 0 && (() => {
            const BANNER_FINDING_TYPES = new Set([
              'zombie-workload', 'rogue-workload', 'unused-iam-role',
              'public-exposure-untagged', 'orphaned-asset',
            ]);
            const ftCounts = {};
            for (const ap of _rawAttackPaths) {
              const ft = ap._resolved_ft || ap.finding_type || 'unknown';
              if (BANNER_FINDING_TYPES.has(ft)) continue; // already shown as classification banner
              const isEnf = ap.remediation?.status === 'enforced';
              if (!ftCounts[ft]) ftCounts[ft] = { count: 0, enforcedCount: 0, maxSev: 'info' };
              ftCounts[ft].count++;
              if (isEnf) ftCounts[ft].enforcedCount++;
              if ((SEV_ORDER[ap.severity] || 4) < (SEV_ORDER[ftCounts[ft].maxSev] || 4)) ftCounts[ft].maxSev = ap.severity;
            }
            if (Object.keys(ftCounts).length === 0) return null;
            return (
              <>
                {ndLabel('Findings')}
                {Object.entries(ftCounts).sort((a, b) => (SEV_ORDER[a[1].maxSev] || 4) - (SEV_ORDER[b[1].maxSev] || 4)).map(([ft, info]) => {
                  const sc = SEV[info.maxSev] || SEV.info;
                  const fullyEnforced = info.enforcedCount === info.count;
                  return (
                    <div key={ft} onClick={() => {
                      const matchingAP = _rawAttackPaths.find(ap => (ap._resolved_ft || ap.finding_type) === ft);
                      if (matchingAP && setActiveAttackPathProp) setActiveAttackPathProp(matchingAP);
                    }}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', cursor: 'pointer',
                      background: fullyEnforced ? 'rgba(16,185,129,0.03)' : 'rgba(255,255,255,0.01)',
                      border: `1px solid ${fullyEnforced ? 'rgba(16,185,129,0.15)' : sc.color + '14'}`,
                      borderLeft: `3px solid ${fullyEnforced ? '#10b981' : sc.color}`,
                      borderRadius: '0 5px 5px 0', marginBottom: 2, opacity: fullyEnforced ? 0.7 : 1,
                      transition: 'background 0.15s' }}
                    onMouseEnter={e => e.currentTarget.style.background = fullyEnforced ? 'rgba(16,185,129,0.06)' : 'rgba(255,255,255,0.04)'}
                    onMouseLeave={e => e.currentTarget.style.background = fullyEnforced ? 'rgba(16,185,129,0.03)' : 'rgba(255,255,255,0.01)'}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: fullyEnforced ? '#10b981' : sc.color, flex: 1,
                        textDecoration: fullyEnforced ? 'line-through' : 'none' }}>
                        {FL(ft)}
                      </span>
                      <span style={{ fontSize: 9, fontFamily: 'monospace', color: '#666' }}>{info.count} path{info.count !== 1 ? 's' : ''}</span>
                      {fullyEnforced
                        ? ndChip('ENFORCED', '#10b981')
                        : ndChip(info.maxSev, sc.color)}
                    </div>
                  );
                })}
              </>
            );
          })()}

          {/* Credential detail — at bottom of Threat Brief for credential nodes */}
          {isCredential && nodeCredential && (
            <div style={{ marginTop: 8, padding: '8px 10px', background: 'rgba(249,115,22,0.04)', border: '1px solid rgba(249,115,22,0.12)', borderRadius: 7 }}>
              {ndLabel('Credential Detail')}
              {ndRow('Type', nodeCredential.type || 'API Key', '#f97316')}
              {ndRow('Provider', nodeCredential.provider || '—', '#3b82f6')}
              {ndRow('Status', (nodeCredential.lifecycle_status || 'active').toUpperCase(), nodeCredential.lifecycle_status === 'active' ? '#10b981' : '#f59e0b')}
              {ndRow('Expires', nodeCredential.never_expires ? '⚠ Never' : (nodeCredential.expiry || '—'), nodeCredential.never_expires ? '#ef4444' : '#10b981')}
            </div>
          )}

        </CollapsibleSection>

        {/* ▼ REMEDIATION ──────────────────────────────────────── */}
        <CollapsibleSection id="remediation" title="Remediation" icon="🛡" accentColor="#7c6ff0"
          badge={allControls.length > 0 ? `${allControls.length} ctrl` : null}
          collapsed={collapsedSections.remediation} onToggle={() => toggleSection('remediation')}>

          {/* ── Impact Preview ── */}
          {attackPaths.length > 0 && !allEnforced && topCtrlForKpi && (
            <div style={{ marginBottom: 10, padding: '8px 10px', background: 'rgba(124,111,240,0.03)', border: '1px solid rgba(124,111,240,0.12)', borderRadius: 7 }}>
              {ndLabel('Impact Preview')}
              <p style={{ fontSize: 9, color: '#aaa', lineHeight: 1.5, margin: '0 0 8px', fontFamily: 'monospace' }}>
                Enforcing <span style={{ color: SEM.accent, fontWeight: 700 }}>{topCtrlForKpi.name}</span> breaks{' '}
                <span style={{ color: SEM.bad, fontWeight: 700 }}>{topControlPathsBreak}/{_rawAttackPaths.length}</span> paths, reduces blast{' '}
                <span style={{ color: SEM.bad }}>{maxBlast}</span>{'\u2192'}<span style={{ color: SEM.good }}>{projectedBlast}</span>
              </p>
              {/* Before bar */}
              <div style={{ marginBottom: 4 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span style={{ fontSize: 7, color: '#888', fontFamily: 'monospace', width: 32 }}>Now</span>
                  <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.04)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${Math.min(100, (maxBlast / Math.max(totalWorkloads, 1)) * 100)}%`, height: '100%', background: SEM.bad, borderRadius: 3, transition: 'width 0.5s' }} />
                  </div>
                  <span style={{ fontSize: 7, color: SEM.bad, fontFamily: 'monospace', width: 16, textAlign: 'right' }}>{maxBlast}</span>
                </div>
                {/* After bar */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 7, color: '#888', fontFamily: 'monospace', width: 32 }}>After</span>
                  <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.04)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${Math.min(100, (projectedBlast / Math.max(totalWorkloads, 1)) * 100)}%`, height: '100%', background: SEM.good, borderRadius: 3, transition: 'width 0.5s' }} />
                  </div>
                  <span style={{ fontSize: 7, color: SEM.good, fontFamily: 'monospace', width: 16, textAlign: 'right' }}>{projectedBlast}</span>
                </div>
              </div>
            </div>
          )}

          {/* Credential chain (from worst-severity attack path) — only show if actual chain (>1 node) */}
          {displayChain.length > 1 && (
            <div style={{ marginBottom: 8 }}>
              {ndLabel('Credential Chain')}
              <div style={{ display: 'flex', alignItems: 'center', padding: '6px 8px', background: 'rgba(255,255,255,0.015)', borderRadius: 6, border: '1px solid rgba(255,255,255,0.04)', overflowX: 'auto', gap: 0 }}>
                {displayChain.map((n, i) => {
                  const nType = n.type || n.node_type || '';
                  const isIdentity = nType === 'service-account' || nType === 'managed-identity' || nType === 'identity';
                  const isCred = nType === 'credential';
                  const isRes = nType === 'resource' || nType === 'external-resource' || nType === 'external-api';
                  const pillColor = isIdentity ? '#3b82f6' : isCred ? '#f97316' : isRes ? '#10b981' : '#64748b';
                  const pillLabel = isIdentity ? 'identity' : isCred ? 'credential' : isRes ? 'resource' : nType.replace(/-/g, ' ');
                  const isStatic = n.is_static || (isCred && n.storage_method === 'env-var');
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                      <div style={{ textAlign: 'center', padding: '2px 5px', background: `${pillColor}0a`, border: `1px solid ${pillColor}20`, borderRadius: 5, minWidth: 46 }}>
                        <div style={{ fontSize: 12 }}>{TYPE_ICONS_ND[nType] || '○'}</div>
                        <div style={{ fontSize: 7, color: '#bbb', fontFamily: 'monospace', maxWidth: 58, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }}>{n.label}</div>
                        <div style={{ display: 'flex', justifyContent: 'center', gap: 2, marginTop: 1 }}>
                          <span style={{ fontSize: 6, color: pillColor, fontFamily: 'monospace', textTransform: 'uppercase' }}>{pillLabel}</span>
                          {isStatic && <span style={{ fontSize: 5.5, color: SEM.bad, fontWeight: 800, background: 'rgba(239,68,68,0.1)', padding: '0 3px', borderRadius: 2 }}>STATIC</span>}
                        </div>
                        {n.provider && isCred && <div style={{ fontSize: 5.5, color: '#666', fontFamily: 'monospace', marginTop: 1 }}>{n.provider}</div>}
                      </div>
                      {i < displayChain.length - 1 && <span style={{ fontSize: 9, color: SEM.bad, padding: '0 2px', fontWeight: 700 }}>{'\u2192\u2192'}</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Playbook controls */}
          {allControls.length > 0 && !allEnforced && (
            <>
              {ndLabel('Remediation Playbook')}
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
                <span style={{ fontSize: 8, color: SEM.accent, background: `${SEM.accent}12`, border: `1px solid ${SEM.accent}25`, padding: '2px 7px', borderRadius: 10, fontFamily: 'monospace', fontWeight: 700 }}>
                  {allControls.length} controls
                </span>
                {topControlPathsBreak > 0 && (
                  <span style={{ fontSize: 8, color: SEM.bad, background: `${SEM.bad}12`, border: `1px solid ${SEM.bad}25`, padding: '2px 7px', borderRadius: 10, fontFamily: 'monospace', fontWeight: 700 }}>
                    top breaks {topControlPathsBreak} paths
                  </span>
                )}
                {enforcedCount > 0 && (
                  <span style={{ fontSize: 8, color: SEM.good, background: `${SEM.good}12`, border: `1px solid ${SEM.good}25`, padding: '2px 7px', borderRadius: 10, fontFamily: 'monospace', fontWeight: 700 }}>
                    {enforcedCount} enforced
                  </span>
                )}
              </div>
              <Playbook
                controls={allControls}
                simState={simState}
                onSimulate={handleSimulate}
                onEnforce={handleEnforce}
                onAudit={handleAudit}
                enforced={enforced}
                enforceLog={enforceLog}
                recentDecisions={enforceLogStream}
                onNavigateAudit={onNavigateAudit}
                onAddCustomPolicy={onAddCustomPolicy}
                scoreNum={scoreNum}
                maxBlast={maxBlast}
                renderedRemediations={renderedRemediations}
              />
            </>
          )}

          {/* ── Enforcement Trace ── */}
          {enforceLogStream.length > 0 && (
            <div style={{ marginTop: 8, marginBottom: 8 }}>
              {ndLabel('Enforcement Trace')}
              <div style={{ maxHeight: 180, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 2, padding: '4px 0' }}>
                {enforceLogStream.slice(0, 20).map((entry, i) => {
                  const verdict = entry.decision || entry.verdict || entry.enforcement_action || '';
                  const verdictUpper = verdict.toUpperCase();
                  const vColor = verdictUpper === 'DENY' || verdictUpper === 'REJECT_REQUEST' ? SEM.bad
                    : verdictUpper === 'ALLOW' || verdictUpper === 'FORWARD_REQUEST' ? SEM.good
                    : verdictUpper === 'WOULD_BLOCK' || verdictUpper === 'MONITOR' ? SEM.warn : SEM.neutral;
                  const vLabel = verdictUpper === 'REJECT_REQUEST' ? 'DENY' : verdictUpper === 'FORWARD_REQUEST' ? 'ALLOW' : verdictUpper === 'MONITOR' ? 'WOULD_BLOCK' : verdictUpper;
                  const ts = entry.ts || entry.timestamp || entry.created_at;
                  const timeStr = ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
                  const action = entry.action || entry.path_pattern || entry.method || '';
                  const workload = entry.source_name || entry.workload || '';
                  const ttl = entry.ttl || entry.token_context?.ttl_seconds;
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '3px 7px', borderRadius: 4, borderLeft: `2px solid ${vColor}`, background: `${vColor}06` }}>
                      <span style={{ fontSize: 6.5, color: '#777', flexShrink: 0, fontFamily: 'monospace', minWidth: 48 }}>{timeStr}</span>
                      <span style={{ fontSize: 7, fontWeight: 800, color: vColor, flexShrink: 0, fontFamily: 'monospace', minWidth: 36, padding: '1px 4px', borderRadius: 3, background: `${vColor}14`, textAlign: 'center' }}>{vLabel}</span>
                      <span style={{ fontSize: 7, color: '#888', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace', flex: 1 }}>{workload}</span>
                      <span style={{ fontSize: 7, color: '#888', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace', maxWidth: 60 }}>{action}</span>
                      {ttl && <span style={{ fontSize: 6, color: SEM.good, flexShrink: 0, fontFamily: 'monospace' }}>TTL:{ttl}s</span>}
                    </div>
                  );
                })}
              </div>
              {enforceLogStream[0]?.reason && (
                <p style={{ fontSize: 7, color: '#666', fontFamily: 'monospace', margin: '4px 0 0', fontStyle: 'italic' }}>{enforceLogStream[0].reason}</p>
              )}
              <button onClick={() => onNavigateAudit && onNavigateAudit(node.label)}
                style={{ width: '100%', marginTop: 6, padding: '5px 0', fontSize: 8, fontFamily: 'monospace', fontWeight: 600, background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 5, color: '#60a5fa', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                <span>{'\u2192'} View all {enforceLogStream.length} decisions in Access Events</span>
              </button>
            </div>
          )}

          {/* Managed state: all enforced — controls + audit link only (findings shown in Threat Brief) */}
          {allEnforced && allControls.length > 0 && (() => {
            const enforcedControls = allControls.filter(c => enforced[c.id] || backendEnforcedPaths.some(ap => (ap.ranked_controls || []).some(rc => rc.id === c.id)));
            return (
              <div>
                {/* Enforced controls list */}
                {enforcedControls.length > 0 && (
                  <>
                    {ndLabel('Enforced Controls')}
                    {enforcedControls.map(ctrl => (
                      <div key={ctrl.id} style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '5px 8px', marginBottom: 2, background: 'rgba(16,185,129,0.02)', border: '1px solid rgba(16,185,129,0.08)', borderRadius: 5 }}>
                        <span style={{ fontSize: 9, color: SEM.good, fontWeight: 700 }}>{'\u2713'}</span>
                        <span style={{ fontSize: 9, color: '#bbb', fontFamily: 'monospace', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ctrl.name}</span>
                        {ndChip(ctrl.action_type, ACTION_COLOR[ctrl.action_type] || '#888')}
                      </div>
                    ))}
                  </>
                )}

                {/* Access Events deep link */}
                <button onClick={() => onNavigateAudit && onNavigateAudit(node.label)}
                  style={{ width: '100%', marginTop: 8, padding: '6px 0', fontSize: 8, fontFamily: 'monospace', fontWeight: 700, background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 5, color: '#60a5fa', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                  {'\u2192'} View enforcement decisions in Access Events
                </button>
              </div>
            );
          })()}

          {/* ── Enforcement Record (moved to bottom) ── */}
          {enforceLog.length > 0 && (
            <div style={{ marginTop: 8 }}>
              {ndLabel('Enforcement Record')}
              {enforceLog.map((entry, i) => (
                <div key={`er-bottom-${i}`} style={{ marginBottom: 4, padding: '6px 8px', background: 'rgba(16,185,129,0.04)', border: '1px solid rgba(16,185,129,0.15)', borderRadius: 6, borderLeft: '3px solid #10b981' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 2 }}>
                    <span style={{ fontSize: 9, fontWeight: 700, color: '#10b981', fontFamily: 'monospace', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{'\u2713'} {entry.ctrl.name}</span>
                    {entry.pathsKilled > 0 && <span style={{ fontSize: 7, color: SEM.bad, fontFamily: 'monospace' }}>{'\u2702'} {entry.pathsKilled} paths</span>}
                  </div>
                  <div style={{ display: 'flex', gap: 6, fontSize: 7, color: '#888', fontFamily: 'monospace' }}>
                    <span>{'\u23F1'} {new Date(entry.ts).toLocaleTimeString()}</span>
                    {entry.traceId && (
                      <button onClick={() => onNavigateAudit && onNavigateAudit(entry.workload, null, null, entry.traceId)}
                        style={{ fontSize: 7, fontFamily: 'monospace', fontWeight: 600, background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.12)', borderRadius: 3, color: '#60a5fa', cursor: 'pointer', padding: '1px 5px' }}>
                        trace
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {attackPaths.length === 0 && !hasBackendEnforcement && allControls.length === 0 && (
            <div style={{ textAlign: 'center', padding: '12px 0', color: '#777' }}>
              <p style={{ fontSize: 9, fontFamily: 'monospace' }}>No controls for this node</p>
            </div>
          )}
        </CollapsibleSection>

        {/* ▶ AI AGENT (only for AI agent/MCP nodes) ──────────── */}
        {isAIAgent && (
          <CollapsibleSection id="agent" title="AI Agent" icon="🤖" accentColor="#8b5cf6"
            collapsed={collapsedSections.agent} onToggle={() => toggleSection('agent')}>

            {(() => {
              const proto = node.meta?.transport || node.meta?.protocol || 'unknown';
              const skills = node.meta?.skills || [];
              const tools = node.meta?.tools || detectedTools || [];
              const hasDelegator = node.meta?.requires_human_delegator;
              const hasAuth = node.meta?.has_auth;
              const isSigned = node.meta?.is_signed;
              const rawProviders = aiData.llm_providers || [];
              const llmProviders = rawProviders.map(p => typeof p === 'string' ? p : (p?.label || p?.id || p?.name || p?.provider || p?.model || 'unknown'));
              const scopeCeiling = aiData.scope_ceiling || node.meta?.scope_ceiling || null;
              const humanInLoop = aiData.human_in_loop !== undefined ? aiData.human_in_loop : node.meta?.human_in_loop;
              const llmModel = rawProviders[0]?.model || aiData.llm_model || aiData.model || node.meta?.model;
              const embeddingModel = aiData.embedding_model || node.meta?.embedding_model;
              const vectorStore = aiData.vector_store || node.meta?.vector_store;

              return (
                <>
                  {ndLabel('Trust Posture')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', marginBottom: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
                    {ndRow('Protocol', proto.toUpperCase(), '#3b82f6')}
                    {ndRow('Auth', hasAuth ? '✓ Required' : '⚠ None', hasAuth ? '#10b981' : '#ef4444')}
                    {ndRow('Card Signed', isSigned ? '✓ JWS' : '⚠ Unsigned', isSigned ? '#10b981' : '#f59e0b')}
                    {ndRow('Delegator', hasDelegator ? '✓ Required' : '⚠ Not required', hasDelegator ? '#10b981' : '#f97316')}
                    {ndRow('Scope Ceiling', scopeCeiling || '⚠ None', scopeCeiling ? '#10b981' : '#f59e0b')}
                  </div>

                  {ndLabel('LLM Configuration')}
                  <div style={{ background: 'rgba(139,92,246,0.04)', border: '1px solid rgba(139,92,246,0.1)', borderRadius: 6, padding: '6px 8px', marginBottom: 8 }}>
                    {ndRow('Providers', llmProviders.length > 0 ? llmProviders.join(', ') : '—', '#8b5cf6')}
                    {llmModel && ndRow('Model', llmModel, '#8b5cf6')}
                    {embeddingModel && ndRow('Embedding', embeddingModel, '#8b5cf6')}
                    {vectorStore && ndRow('Vector Store', vectorStore, '#8b5cf6')}
                    {ndRow('Human-in-loop', humanInLoop !== undefined ? (humanInLoop ? '✓ Yes' : '⚠ No') : '—', humanInLoop ? '#10b981' : '#f59e0b')}
                  </div>

                  {skills.length > 0 && (
                    <div style={{ marginBottom: 8 }}>
                      {ndLabel(`Skills (${skills.length})`)}
                      <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                        {skills.slice(0, 8).map((sk, i) => (
                          <span key={i} style={{ fontSize: 7, color: '#8b5cf6', background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.12)', padding: '1px 5px', borderRadius: 8, fontFamily: 'monospace' }}>{sk.name || sk.id || sk}</span>
                        ))}
                      </div>
                    </div>
                  )}

                  {tools.length > 0 && (
                    <div>
                      {ndLabel(`Tools (${tools.length})`)}
                      <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                        {tools.map(t => ndChip(typeof t === 'string' ? t : t.name || t.id, '#7c6ff0'))}
                      </div>
                    </div>
                  )}

                  {/* IETF AIMS fields — integrated into AI Agent section */}
                  {node.meta?.ietf_aims && (() => {
                    const aims = node.meta.ietf_aims;
                    const delegationColors = { user_delegation: '#3b82f6', cross_domain: '#f97316', self_auth: '#10b981' };
                    const attestationColors = { tee: '#10b981', platform: '#3b82f6', software: '#f59e0b', none: '#ef4444' };
                    const driftColor = (aims.scope_drift_score || 0) > 0.3 ? '#ef4444' : (aims.scope_drift_score || 0) > 0.1 ? '#f59e0b' : '#10b981';
                    const cred = aims.credential_provisioning || {};
                    const credColor = cred.method === 'jit' ? '#10b981' : cred.method === 'static' ? '#ef4444' : '#64748b';

                    return (
                      <>
                        {ndLabel('Identity & Attestation')}
                        <div style={{ background: 'rgba(6,182,212,0.04)', border: '1px solid rgba(6,182,212,0.1)', borderRadius: 6, padding: '6px 8px', marginBottom: 8 }}>
                          {aims.agent_identifier && ndRow('SPIFFE ID', aims.agent_identifier, '#06b6d4')}
                          {ndRow('Attestation', (aims.attestation_type || 'none').toUpperCase(), attestationColors[aims.attestation_type] || '#64748b')}
                          {ndRow('Delegation', aims.delegation_type ? aims.delegation_type.replace(/_/g, ' ').toUpperCase() : '—', delegationColors[aims.delegation_type] || '#64748b')}
                          {(aims.delegation_depth || 0) > 0 && ndRow('Delegation Depth', String(aims.delegation_depth), (aims.delegation_depth || 0) >= 3 ? '#ef4444' : '#bbb')}
                        </div>

                        {ndLabel('Credential Provisioning')}
                        <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', marginBottom: 8, border: '1px solid rgba(255,255,255,0.04)' }}>
                          {ndRow('Method', (cred.method || 'unknown').toUpperCase(), credColor)}
                          {cred.rotation_interval_s && ndRow('Rotation', `${cred.rotation_interval_s}s`, '#06b6d4')}
                          {cred.active_tokens !== undefined && ndRow('Active Tokens', String(cred.active_tokens), '#06b6d4')}
                        </div>

                        {ndRow('Scope Drift', (aims.scope_drift_score || 0).toFixed(2), driftColor)}

                        {(aims.observable_risk_indicators || []).length > 0 && (
                          <div style={{ marginTop: 4 }}>
                            <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
                              {aims.observable_risk_indicators.map((ind, i) => ndChip(ind, ind.includes('delegation') || ind.includes('drift') ? '#f97316' : '#ef4444'))}
                            </div>
                          </div>
                        )}
                      </>
                    );
                  })()}
                </>
              );
            })()}
          </CollapsibleSection>
        )}

        {/* ▶ CREDENTIALS ──────────────────────────────────────── */}
        <CollapsibleSection id="credentials" title="Credentials" icon="🗝️" accentColor="#f97316"
          badge={credCount > 0 ? String(credCount) : null}
          collapsed={collapsedSections.credentials} onToggle={() => toggleSection('credentials')}>

          {!isCredential && credSummary && (
            <div style={{ marginBottom: 8 }}>
              {ndLabel(`Summary (${credSummary.count || 0})`)}
              <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                {ndRow('Total', credSummary.count || 0)}
                {ndRow('Static/Plaintext', credSummary.static_count || 0, credSummary.static_count > 0 ? '#ef4444' : '#10b981')}
                {ndRow('Providers', (credSummary.providers || []).join(', ') || '—', '#3b82f6')}
              </div>
            </div>
          )}

          {/* Credential inventory from attack paths */}
          {!isCredential && _rawAttackPaths.length > 0 && (() => {
            const credMap = {};
            for (const ap of _rawAttackPaths) {
              for (const c of (ap.credential_chain || [])) {
                if (c.type === 'credential' || c.node_type === 'credential') {
                  const key = c.label || c.id;
                  if (key && !credMap[key]) {
                    credMap[key] = { label: c.label || c.id, type: c.credential_type || c.subtype || 'API Key', provider: c.provider || '—', storage: c.storage_method || 'env-var', isStatic: c.is_static !== false, pathCount: 0 };
                  }
                  if (key) credMap[key].pathCount++;
                }
              }
            }
            const creds = Object.values(credMap);
            if (creds.length === 0) return null;
            return (
              <div>
                {ndLabel(`Inventory (${creds.length})`)}
                {creds.map(cred => (
                  <div key={cred.label} style={{ padding: '6px 8px', background: cred.isStatic ? 'rgba(239,68,68,0.03)' : 'rgba(255,255,255,0.015)', border: `1px solid ${cred.isStatic ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.04)'}`, borderRadius: 6, marginBottom: 3 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 3 }}>
                      <span style={{ fontSize: 10 }}>🗝️</span>
                      <span style={{ fontSize: 8, fontWeight: 700, color: '#e8e8ee', fontFamily: 'monospace', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.label}</span>
                      {cred.isStatic && ndChip('STATIC', '#ef4444')}
                    </div>
                    {ndRow('Type', cred.type, '#f97316')}
                    {ndRow('Storage', cred.storage.replace(/-/g, ' '), cred.storage === 'env-var' ? '#f59e0b' : '#10b981')}
                  </div>
                ))}
              </div>
            );
          })()}

          {/* Exposure assessment */}
          {!isCredential && (
            <div style={{ marginTop: 6 }}>
              {ndLabel('Exposure Assessment')}
              <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                {ndRow('Trust Level', node.trust || 'none', TRUST_COLORS[node.trust] || '#ef4444')}
                {ndRow('Attestation', (() => {
                  const t = node.trust || 'none';
                  if (['cryptographic','very-high','high'].includes(t)) return `\u2713 ${t.replace(/-/g,' ').replace(/\b\w/g, c => c.toUpperCase())}`;
                  if (['medium','low'].includes(t)) return `\u25D0 ${t.charAt(0).toUpperCase() + t.slice(1)}`;
                  return '\u26A0 Not Attested';
                })(), (['cryptographic','very-high','high'].includes(node.trust || 'none') ? '#10b981' :
                       ['medium','low'].includes(node.trust || 'none') ? '#f59e0b' : '#ef4444'))}
                {ndRow('Credential Storage', credSummary?.static_count > 0 ? `⚠ ${credSummary.static_count} in plaintext/env` : '✓ No plaintext detected', credSummary?.static_count > 0 ? '#ef4444' : '#10b981')}
              </div>
            </div>
          )}
        </CollapsibleSection>

        {/* ▶ RESOURCE DETAILS ──────────────────────────────────── */}
        {node.metadata && Object.keys(node.metadata).length > 0 && (() => {
          const m = node.metadata;
          const ntype = node.workload_type || node.type || '';
          const isIAM = ['iam-role', 'iam-user', 'iam-group', 'iam-policy', 'service-account', 'managed-identity'].includes(ntype);
          const isStorage = ['s3-bucket', 'rds-instance', 'dynamodb-table', 'gcs-bucket', 'cloud-sql', 'storage-account', 'azure-sql'].includes(ntype);
          const isNetwork = ['vpc', 'security-group', 'load-balancer', 'firewall-rule', 'nsg'].includes(ntype);
          const isSecurity = ['kms-key', 'key-vault', 'managed-secret', 'cloudtrail'].includes(ntype);
          const isCompute = ['ec2', 'lambda', 'ecs-task', 'cloud-run-service', 'compute-instance', 'cloud-function', 'gke-workload', 'azure-vm', 'azure-container', 'aks-workload'].includes(ntype);
          const hasDetails = isIAM || isStorage || isNetwork || isSecurity || isCompute;
          if (!hasDetails) return null;
          return (
            <CollapsibleSection id="resource" title="Resource Details" icon="📋" accentColor="#06b6d4"
              collapsed={collapsedSections.resource} onToggle={() => toggleSection('resource')}>

              {/* Compute details */}
              {isCompute && (
                <div style={{ marginBottom: 8 }}>
                  {ndLabel('Compute')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    {m.instance_type && ndRow('Instance Type', m.instance_type, '#06b6d4')}
                    {m.runtime && ndRow('Runtime', m.runtime, '#8b5cf6')}
                    {m.memory_size && ndRow('Memory', `${m.memory_size} MB`, '#06b6d4')}
                    {m.handler && ndRow('Handler', m.handler, '#06b6d4')}
                    {m.ami_id && ndRow('AMI', m.ami_id, '#06b6d4')}
                    {m.vpc_id && ndRow('VPC', m.vpc_id, '#3b82f6')}
                    {m.subnet_id && ndRow('Subnet', m.subnet_id, '#3b82f6')}
                    {m.private_ip && ndRow('Private IP', m.private_ip, '#06b6d4')}
                    {m.public_ip && ndRow('Public IP', m.public_ip, '#f59e0b')}
                    {m.launch_type && ndRow('Launch Type', m.launch_type, '#06b6d4')}
                    {m.security_groups?.length > 0 && ndRow('Security Groups', m.security_groups.join(', '), '#3b82f6')}
                    {m.iam_instance_profile && ndRow('IAM Profile', m.iam_instance_profile.split('/').pop(), '#f97316')}
                    {m.role && ndRow('Execution Role', m.role.split('/').pop(), '#f97316')}
                  </div>
                </div>
              )}

              {/* IAM details */}
              {isIAM && (
                <div style={{ marginBottom: 8 }}>
                  {ndLabel('IAM Configuration')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    {m.attached_policies?.length > 0 && ndRow('Policies', `${m.attached_policies.length} attached`, '#3b82f6')}
                    {m.inline_policies?.length > 0 && ndRow('Inline Policies', `${m.inline_policies.length}`, '#f59e0b')}
                    {m.permission_boundary_arn && ndRow('Permission Boundary', m.permission_boundary_arn.split('/').pop(), '#10b981')}
                    {m.member_arns?.length > 0 && ndRow('Members', `${m.member_arns.length} users`, '#3b82f6')}
                    {m.groups?.length > 0 && ndRow('Groups', m.groups.join(', '), '#3b82f6')}
                    {m.has_admin_access && ndRow('Admin Access', '⚠ Yes', '#ef4444')}
                    {m.cross_account_trusts?.length > 0 && ndRow('Cross-Account', `${m.cross_account_trusts.length} trusts`, '#f97316')}
                    {m.effective_permissions_summary && (() => {
                      const eps = m.effective_permissions_summary;
                      return (
                        <>
                          {eps.has_admin && ndRow('Admin', '⚠ Full admin', '#ef4444')}
                          {eps.has_wildcard_actions && ndRow('Wildcards', '⚠ * actions', '#f59e0b')}
                          {eps.can_escalate && ndRow('Escalation', '⚠ Can escalate', '#ef4444')}
                          {eps.sensitive_services?.length > 0 && ndRow('Sensitive', eps.sensitive_services.slice(0, 5).join(', '), '#f97316')}
                        </>
                      );
                    })()}
                  </div>
                  {m.attached_policies?.length > 0 && (
                    <div style={{ marginTop: 4 }}>
                      {ndLabel(`Attached Policies (${m.attached_policies.length})`)}
                      <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                        {m.attached_policies.slice(0, 10).map((p, i) => (
                          <span key={i} style={{ fontSize: 7, color: (p.PolicyName || p).includes('Admin') ? '#ef4444' : '#3b82f6', background: (p.PolicyName || p).includes('Admin') ? 'rgba(239,68,68,0.06)' : 'rgba(59,130,246,0.06)', border: `1px solid ${(p.PolicyName || p).includes('Admin') ? 'rgba(239,68,68,0.12)' : 'rgba(59,130,246,0.12)'}`, padding: '1px 5px', borderRadius: 8, fontFamily: 'monospace' }}>{p.PolicyName || p}</span>
                        ))}
                        {m.attached_policies.length > 10 && <span style={{ fontSize: 7, color: '#777' }}>+{m.attached_policies.length - 10} more</span>}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Storage details */}
              {isStorage && (
                <div style={{ marginBottom: 8 }}>
                  {ndLabel('Storage Configuration')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    {m.engine && ndRow('Engine', m.engine, '#06b6d4')}
                    {m.is_public !== undefined && ndRow('Public Access', m.is_public ? '⚠ Public' : '✓ Private', m.is_public ? '#ef4444' : '#10b981')}
                    {m.publicly_accessible !== undefined && ndRow('Public Access', m.publicly_accessible ? '⚠ Publicly Accessible' : '✓ Private', m.publicly_accessible ? '#ef4444' : '#10b981')}
                    {m.storage_encrypted !== undefined && ndRow('Encryption', m.storage_encrypted ? '✓ Encrypted' : '⚠ Unencrypted', m.storage_encrypted ? '#10b981' : '#ef4444')}
                    {m.encryption && ndRow('Encryption', m.encryption.type || (m.encryption.enabled ? '✓ Enabled' : '⚠ None'), m.encryption.enabled || m.encryption.type ? '#10b981' : '#ef4444')}
                    {m.versioning !== undefined && ndRow('Versioning', m.versioning ? '✓ Enabled' : '⚠ Disabled', m.versioning ? '#10b981' : '#f59e0b')}
                    {m.logging_enabled !== undefined && ndRow('Logging', m.logging_enabled ? '✓ Enabled' : '⚠ Disabled', m.logging_enabled ? '#10b981' : '#f59e0b')}
                    {m.iam_auth_enabled !== undefined && ndRow('IAM Auth', m.iam_auth_enabled ? '✓ Enabled' : '⚠ Disabled', m.iam_auth_enabled ? '#10b981' : '#f59e0b')}
                    {m.multi_az !== undefined && ndRow('Multi-AZ', m.multi_az ? '✓ Yes' : 'No', m.multi_az ? '#10b981' : '#888')}
                    {m.backup_retention && ndRow('Backup Retention', `${m.backup_retention} days`, '#06b6d4')}
                    {m.point_in_time_recovery !== undefined && ndRow('PITR', m.point_in_time_recovery ? '✓ Enabled' : '⚠ Disabled', m.point_in_time_recovery ? '#10b981' : '#f59e0b')}
                    {m.ssl_required !== undefined && ndRow('SSL Required', m.ssl_required ? '✓ Yes' : '⚠ No', m.ssl_required ? '#10b981' : '#f59e0b')}
                  </div>
                </div>
              )}

              {/* Network details */}
              {isNetwork && (
                <div style={{ marginBottom: 8 }}>
                  {ndLabel('Network Configuration')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    {m.cidr_block && ndRow('CIDR', m.cidr_block, '#06b6d4')}
                    {m.has_internet_gateway !== undefined && ndRow('Internet GW', m.has_internet_gateway ? '✓ Yes' : 'No', m.has_internet_gateway ? '#f59e0b' : '#888')}
                    {m.public_subnet_count !== undefined && ndRow('Public Subnets', m.public_subnet_count, m.public_subnet_count > 0 ? '#f59e0b' : '#888')}
                    {m.private_subnet_count !== undefined && ndRow('Private Subnets', m.private_subnet_count, '#10b981')}
                    {m.flow_logs_enabled !== undefined && ndRow('Flow Logs', m.flow_logs_enabled ? '✓ Enabled' : '⚠ Disabled', m.flow_logs_enabled ? '#10b981' : '#f59e0b')}
                    {m.allows_public_ingress !== undefined && ndRow('Public Ingress', m.allows_public_ingress ? '⚠ Allowed' : '✓ Restricted', m.allows_public_ingress ? '#ef4444' : '#10b981')}
                    {m.public_ports?.length > 0 && ndRow('Public Ports', m.public_ports.join(', '), '#ef4444')}
                    {m.scheme && ndRow('Scheme', m.scheme, m.scheme === 'internet-facing' ? '#f59e0b' : '#10b981')}
                  </div>
                  {m.ingress_rules?.length > 0 && (
                    <div style={{ marginTop: 4 }}>
                      {ndLabel(`Ingress Rules (${m.ingress_rules.length})`)}
                      {m.ingress_rules.slice(0, 6).map((rule, i) => (
                        <div key={i} style={{ fontSize: 7, color: rule.cidr === '0.0.0.0/0' ? '#ef4444' : '#888', fontFamily: 'monospace', padding: '2px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                          {rule.protocol || 'tcp'}:{rule.port || rule.from_port || '*'} ← {rule.cidr || rule.source || 'any'}
                        </div>
                      ))}
                      {m.ingress_rules.length > 6 && <span style={{ fontSize: 7, color: '#777' }}>+{m.ingress_rules.length - 6} more</span>}
                    </div>
                  )}
                </div>
              )}

              {/* Security / Encryption details */}
              {isSecurity && (
                <div style={{ marginBottom: 8 }}>
                  {ndLabel('Security Configuration')}
                  <div style={{ background: 'rgba(255,255,255,0.015)', borderRadius: 6, padding: '6px 8px', border: '1px solid rgba(255,255,255,0.04)' }}>
                    {m.key_manager && ndRow('Key Manager', m.key_manager, '#06b6d4')}
                    {m.rotation_enabled !== undefined && ndRow('Rotation', m.rotation_enabled ? '✓ Enabled' : '⚠ Disabled', m.rotation_enabled ? '#10b981' : '#ef4444')}
                    {m.last_rotated && ndRow('Last Rotated', new Date(m.last_rotated).toLocaleDateString(), '#06b6d4')}
                    {m.last_accessed && ndRow('Last Accessed', new Date(m.last_accessed).toLocaleDateString(), '#06b6d4')}
                    {m.days_since_rotation !== undefined && ndRow('Days Since Rotation', m.days_since_rotation, m.days_since_rotation > 90 ? '#ef4444' : '#10b981')}
                    {m.is_stale !== undefined && ndRow('Status', m.is_stale ? '⚠ Stale' : '✓ Active', m.is_stale ? '#ef4444' : '#10b981')}
                    {m.policy_allows_cross_account !== undefined && ndRow('Cross-Account', m.policy_allows_cross_account ? '⚠ Allowed' : '✓ Restricted', m.policy_allows_cross_account ? '#f59e0b' : '#10b981')}
                  </div>
                </div>
              )}

              {/* IAM credentials attached to this workload */}
              {m.credentials?.length > 0 && (
                <div style={{ marginTop: 4 }}>
                  {ndLabel(`IAM Credentials (${m.credentials.length})`)}
                  {m.credentials.slice(0, 8).map((cred, i) => (
                    <div key={i} style={{ padding: '4px 8px', background: cred.is_static ? 'rgba(239,68,68,0.03)' : 'rgba(255,255,255,0.015)', border: `1px solid ${cred.is_static ? 'rgba(239,68,68,0.1)' : 'rgba(255,255,255,0.04)'}`, borderRadius: 6, marginBottom: 2 }}>
                      {ndRow(cred.name || cred.key, cred.value || cred.type, cred.is_static ? '#ef4444' : '#10b981')}
                    </div>
                  ))}
                </div>
              )}
            </CollapsibleSection>
          );
        })()}

        {/* ▶ IDENTITY & EVIDENCE ──────────────────────────────── */}
        <CollapsibleSection id="identity" title="Identity & Evidence" icon="🪪" accentColor="#3b82f6"
          badge={connected.length > 0 ? `${connected.length} conn${totalAttackPathEdges > 0 ? ` · ⚡${totalAttackPathEdges}` : ''}` : null}
          collapsed={collapsedSections.identity} onToggle={() => toggleSection('identity')}>

          {/* Identity metadata */}
          {ndLabel('Identity')}
          {ndRow('Attestation', node.verified ? 'Verified' : 'Unverified', node.verified ? '#10b981' : '#f59e0b')}
          {ndRow('Owner', node.owner || '⚠ Unassigned', node.owner ? '#bbb' : '#f59e0b')}
          {ndRow('Team', node.team || '—', node.team ? '#bbb' : '#777')}
          {ndRow('Category', `${node.category || '—'}${node.subcategory ? ` · ${node.subcategory}` : ''}`, '#3b82f6')}
          {ndRow('SPIFFE ID', node.spiffe_id || node.workload_id?.replace('w:', 'spiffe://dev.local/') || '—', '#a78bfa')}

          {/* Connections — grouped by category */}
          <div style={{ marginTop: 8 }}>
            {ndLabel(`Connections (${connected.length})`)}
            {connGroups.map((g, gi) => {
              const catExpanded = expandedCats.has(g.meta.cat);
              const visibleEdges = catExpanded ? g.edges : g.edges.slice(0, 5);
              const hiddenCount = g.edges.length - 5;
              const pathCountInGroup = g.edges.filter(r => {
                const otherId = sid(r.source) === node.id ? sid(r.target) : sid(r.source);
                const other = nodes.find(n => n.id === otherId);
                return isOnAttackPath(r, other);
              }).length;

              return (
                <div key={gi} style={{ marginBottom: 6 }}>
                  {/* Group header */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 0 3px' }}>
                    <div style={{ width: 3, height: 12, background: g.meta.color, borderRadius: 1, flexShrink: 0 }} />
                    <span style={{ fontSize: 8, flexShrink: 0 }}>{CAT_ICONS[g.meta.cat] || '○'}</span>
                    <span style={{ fontSize: 7.5, fontWeight: 700, color: g.meta.color, fontFamily: 'monospace', letterSpacing: '0.08em', flex: 1 }}>
                      {g.meta.label}
                    </span>
                    {pathCountInGroup > 0 && (
                      <span style={{ fontSize: 6, fontWeight: 700, padding: '1px 4px', borderRadius: 3, background: '#ef444418', color: '#ef4444', border: '1px solid #ef444430', fontFamily: 'monospace' }}>
                        ⚡{pathCountInGroup}
                      </span>
                    )}
                    <span style={{ fontSize: 7, color: '#555', fontFamily: 'monospace' }}>{g.edges.length}</span>
                  </div>

                  {/* Edge rows */}
                  {visibleEdges.map((r, i) => {
                    const otherId = sid(r.source) === node.id ? sid(r.target) : sid(r.source);
                    const other = nodes.find(n => n.id === otherId);
                    const dir = sid(r.source) === node.id ? '\u2192' : '\u2190';
                    const onPath = isOnAttackPath(r, other);
                    const meaning = CONNECTION_MEANING[r.type]?.(r, other);
                    const edgeKey = `${gi}-${i}`;
                    const evidenceOpen = expandedEvidence.has(edgeKey) || onPath;

                    // Runtime traffic lookup
                    const nodeLbl = (node.label || '').toLowerCase();
                    const otherLbl = (other?.label || '').toLowerCase();
                    const rtEntry = runtimeMap[`${nodeLbl}::${otherLbl}`] || runtimeMap[`${otherLbl}::${nodeLbl}`];

                    // Policy status from attack paths
                    const policyEntry = (() => {
                      for (const ap of _rawAttackPaths) {
                        if (!ap.remediation) continue;
                        const involved = [(ap.workload || '').toLowerCase(), ...(ap.affected_workloads || []).map(w => w.toLowerCase())];
                        if (involved.includes(otherLbl) || involved.includes(nodeLbl)) {
                          const pol = ap.remediation.policies?.[0];
                          if (pol) return { mode: ap.remediation.status, name: pol.name };
                        }
                      }
                      return null;
                    })();

                    return (
                      <div key={i} style={{
                        padding: '4px 0 4px 6px', borderBottom: '1px solid rgba(255,255,255,0.04)',
                        background: onPath ? 'rgba(239,68,68,0.03)' : 'transparent',
                        borderLeft: onPath ? '2px solid rgba(239,68,68,0.2)' : '2px solid transparent',
                      }}>
                        {/* Row header */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}
                          onClick={() => setExpandedEvidence(prev => {
                            const next = new Set(prev);
                            next.has(edgeKey) ? next.delete(edgeKey) : next.add(edgeKey);
                            return next;
                          })}>
                          <span style={{ fontSize: 7, color: onPath ? '#ef4444' : g.meta.color + '80', fontFamily: 'monospace', flexShrink: 0, width: 10 }}>{dir}</span>
                          <span style={{ fontSize: 9 }}>{vis(other?.type, other)?.icon || '○'}</span>
                          <span style={{ fontSize: 8, flex: 1, color: onPath ? '#fca5a5' : '#ccc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace', fontWeight: onPath ? 600 : 400 }}>
                            {other?.label || otherId}
                          </span>
                          {onPath && (
                            <span style={{ fontSize: 5.5, fontWeight: 700, padding: '1px 3px', borderRadius: 2, background: '#ef444418', color: '#ef4444', border: '1px solid #ef444430', fontFamily: 'monospace', flexShrink: 0 }}>
                              ⚡PATH
                            </span>
                          )}
                          {rtEntry && (
                            <span style={{ fontSize: 5.5, fontWeight: 600, padding: '1px 3px', borderRadius: 2, background: '#f59e0b15', color: '#f59e0b', fontFamily: 'monospace', flexShrink: 0 }}>
                              {rtEntry.total}
                            </span>
                          )}
                          <span style={{ fontSize: 6, color: g.meta.color + '80', fontFamily: 'monospace', flexShrink: 0 }}>{r.type}</span>
                        </div>

                        {/* Practical meaning */}
                        {meaning && (
                          <div style={{ fontSize: 7, color: '#6b7280', fontFamily: 'monospace', lineHeight: 1.4, marginTop: 2, marginLeft: 14, paddingRight: 4 }}>
                            {meaning}
                          </div>
                        )}

                        {/* Three-layer evidence strip */}
                        {evidenceOpen && (
                          <div style={{ marginTop: 3, marginLeft: 14 }}>
                            {/* Layer 1: DISCOVERED */}
                            {r.discovered_by && (
                              <div style={{ padding: '3px 6px', background: 'rgba(99,102,241,0.06)', borderLeft: '2px solid rgba(99,102,241,0.35)', marginBottom: 2, borderRadius: '0 3px 3px 0' }}>
                                <span style={{ fontSize: 6.5, color: '#a5b4fc', fontFamily: 'monospace', fontWeight: 700 }}>
                                  DISCOVERED · via {r.discovered_by}
                                </span>
                                {r.evidence && (
                                  <div style={{ fontSize: 6, color: '#64748b', fontFamily: 'monospace', lineHeight: 1.4, marginTop: 1, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                                    {r.evidence}
                                  </div>
                                )}
                              </div>
                            )}
                            {/* Layer 2: CONFIRMED (runtime traffic) */}
                            {rtEntry && (
                              <div style={{ padding: '3px 6px', background: 'rgba(245,158,11,0.06)', borderLeft: '2px solid rgba(245,158,11,0.35)', marginBottom: 2, borderRadius: '0 3px 3px 0' }}>
                                <span style={{ fontSize: 6.5, color: '#f59e0b', fontFamily: 'monospace', fontWeight: 700 }}>
                                  CONFIRMED · {rtEntry.total} decisions observed
                                </span>
                                <span style={{ fontSize: 6, color: '#94a3b8', fontFamily: 'monospace', marginLeft: 4 }}>
                                  {rtEntry.allow > 0 ? `${rtEntry.allow}\u2713` : ''}{rtEntry.deny > 0 ? ` ${rtEntry.deny}\u2717` : ''}
                                </span>
                              </div>
                            )}
                            {/* Layer 3: ACTIONABLE (policy status) */}
                            {policyEntry && (
                              <div style={{ padding: '3px 6px', background: policyEntry.mode === 'enforced' ? 'rgba(16,185,129,0.06)' : 'rgba(245,158,11,0.06)', borderLeft: `2px solid ${policyEntry.mode === 'enforced' ? 'rgba(16,185,129,0.4)' : 'rgba(245,158,11,0.4)'}`, borderRadius: '0 3px 3px 0' }}>
                                <span style={{ fontSize: 6.5, color: policyEntry.mode === 'enforced' ? '#10b981' : '#f59e0b', fontFamily: 'monospace', fontWeight: 700 }}>
                                  ACTIONABLE · {policyEntry.mode === 'enforced' ? 'ENFORCED' : 'AUDIT'}
                                </span>
                                <div style={{ fontSize: 6, color: '#94a3b8', fontFamily: 'monospace' }}>
                                  {policyEntry.name}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}

                  {/* Show more expander */}
                  {!catExpanded && hiddenCount > 0 && (
                    <div style={{ padding: '4px 0 0 10px', cursor: 'pointer' }}
                      onClick={() => setExpandedCats(prev => { const n = new Set(prev); n.add(g.meta.cat); return n; })}>
                      <span style={{ fontSize: 7, color: g.meta.color, fontFamily: 'monospace', fontWeight: 600 }}>
                        + {hiddenCount} more
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Recent Activity */}
          {(() => {
            const nodeLabel = (node.label || '').toLowerCase();
            const nodeEvents = timeline.filter(e =>
              (e.workload || e.summary || '').toLowerCase().includes(nodeLabel) ||
              (e.detail?.workload || '').toLowerCase().includes(nodeLabel)
            ).slice(0, 6);
            if (nodeEvents.length === 0) return null;
            return (
              <div style={{ marginTop: 8 }}>
                {ndLabel(`Recent Activity (${nodeEvents.length})`)}
                {nodeEvents.map((evt, i) => {
                  const tc = { attestation: '#10b981', graph_finding: '#a78bfa', authorization: '#3b82f6', policy: '#f59e0b' }[evt.type] || '#64748b';
                  return (
                    <div key={i} style={{ display: 'flex', gap: 6, padding: '4px 0', borderBottom: '1px solid rgba(255,255,255,0.02)' }}>
                      <span style={{ fontSize: 7, color: '#777', fontFamily: 'monospace', flexShrink: 0, width: 32 }}>{evt.timestamp ? timeAgo(evt.timestamp) : ''}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 8, color: '#999', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{evt.summary}</div>
                        <span style={{ fontSize: 6, fontWeight: 700, color: tc, textTransform: 'uppercase' }}>{evt.type === 'graph_finding' ? 'finding' : evt.type}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })()}

          {/* Access Events link */}
          <div style={{ marginTop: 8 }}>
            {ndLabel('Access Events')}
            <button onClick={() => onNavigateAudit && onNavigateAudit(node.label, null, null)}
              style={{ width: '100%', padding: '6px 0', fontSize: 8, fontFamily: 'monospace', fontWeight: 700, background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 5, color: '#60a5fa', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
              → View in Access Events
            </button>
          </div>
        </CollapsibleSection>

      </div>

      {/* ── Status Bar ── */}
      {enforcedCount > 0 && (() => {
        const totalPathsKilled = enforceLog.reduce((s, r) => s + (r.pathsKilled || 0), 0);
        const blastBefore = enforceLog[0]?.simResult?.impact?.blast_before ?? maxBlast;
        return (
          <div style={{ padding: '6px 12px', borderTop: '1px solid rgba(16,185,129,0.1)', flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 4px rgba(16,185,129,0.6)' }} />
              <span style={{ fontSize: 9, color: '#10b981', fontFamily: 'monospace', fontWeight: 700 }}>
                {enforcedCount} enforced · {liveGrade} · Blast {blastBefore > liveBlast ? `${blastBefore}→${liveBlast}` : liveBlast}
              </span>
              {totalPathsKilled > 0 && <span style={{ fontSize: 8, fontFamily: 'monospace', color: '#ef4444', marginLeft: 'auto' }}>✂ {totalPathsKilled} paths</span>}
            </div>
          </div>
        );
      })()}
    </div>
  );
}

/* ═══════════════════════════════════════════
   Helpers
   ═══════════════════════════════════════════ */
function sid(x) { return x?.id || x; }

function hlNode(nodeId, node, link, links) {
  // Direct neighbors only (1-hop) — not full BFS which reaches everything
  const connected = new Set([nodeId]);
  links.forEach(r => {
    const s = sid(r.source), t = sid(r.target);
    if (s === nodeId) connected.add(t);
    if (t === nodeId) connected.add(s);
  });
  // Dim non-connected nodes
  node.select('circle.gnode').transition().duration(200)
    .attr('opacity', n => connected.has(n.id) ? 1 : 0.08)
    .attr('stroke-width', n => n.id === nodeId ? 4 : connected.has(n.id) ? 2 : 1)
    .attr('stroke', n => n.id === nodeId ? '#e8e8ee' : vis(n.type, n).color)
    .attr('r', n => n.id === nodeId ? (vis(n.type, n).r + 4) : vis(n.type, n).r);
  node.selectAll('text').transition().duration(200).attr('opacity', n => connected.has(n.id) ? 1 : 0.08);
  // Add glow filter to selected node
  node.select('circle.gnode')
    .attr('filter', n => n.id === nodeId ? 'url(#selectedGlow)' : null);
  // Pulse ring animation on selected node
  node.each(function(d) {
    if (d.id !== nodeId) return;
    const g = d3.select(this);
    g.selectAll('.select-pulse').remove();
    const r = vis(d.type, d).r;
    g.insert('circle', ':first-child')
      .attr('class', 'select-pulse')
      .attr('r', r + 6)
      .attr('fill', 'none')
      .attr('stroke', '#e8e8ee')
      .attr('stroke-width', 1.5)
      .attr('opacity', 0.6)
      .transition().duration(800).ease(d3.easeQuadOut)
      .attr('r', r + 16)
      .attr('opacity', 0)
      .on('end', function() { d3.select(this).remove(); });
  });
  // Only highlight edges directly touching the selected node
  const isConn = l => sid(l.source) === nodeId || sid(l.target) === nodeId;
  link.transition().duration(200)
    .attr('opacity', l => isConn(l) ? 1 : 0.03)
    .attr('stroke-width', l => isConn(l) ? 2.5 : 0.5)
    .attr('stroke', l => isConn(l) ? '#f59e0b' : 'rgba(255,255,255,0.05)');
  link.attr('stroke-dasharray', l => isConn(l) ? '6,3' : null);
}

function resetHL(node, link) {
  node.select('circle.gnode').transition().duration(200)
    .attr('opacity', 1).attr('stroke-width', 1.5)
    .attr('stroke', d => vis(d.type, d).color)
    .attr('r', d => vis(d.type, d).r);
  node.select('circle.gnode').attr('filter', null);
  node.selectAll('.select-pulse').remove();
  node.selectAll('text').transition().duration(200).attr('opacity', 1);
  link.attr('stroke-dasharray', null);
  link.transition().duration(200).attr('opacity', 1).attr('stroke-width', d => d.critical ? 2 : 0.7)
    .attr('stroke', d => d.critical ? 'rgba(239,68,68,0.25)' : 'rgba(255,255,255,0.07)');
}

function timeAgo(ts) {
  const d = (Date.now() - new Date(ts).getTime()) / 1000;
  if (d < 60) return 'just now'; if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`; return `${Math.floor(d / 86400)}d ago`;
}
