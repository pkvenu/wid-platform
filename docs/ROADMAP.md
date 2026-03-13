# WID Platform — Roadmap

> Version 1.0 | March 2026
> Prioritized backlog with acceptance criteria. Updated each session.

---

## Priority Levels

- **P0 — Ship or Die**: Blocks demo, compliance deadline, or core value prop
- **P1 — Competitive Moat**: Differentiators that no competitor has
- **P2 — Production Readiness**: Required before first customer deployment
- **P3 — Nice to Have**: Important but not blocking

---

## P0 — Ship or Die

### 0.1 Remediation Decision Framework
**Status**: DONE (deployed March 9, 2026)
**Files**: `GraphPage.jsx`, `Policies.jsx`, `graph-routes.js`, `routes.js`, `init.sql`
**Description**: Split Playbook into Policy Remediations (Simulate/Audit/Enforce) vs IAM/CLI Remediations (manual steps).
**What was built**:
- [x] Controls classified by `remediation_type` (policy vs iac/infra/code_change/vendor/process)
- [x] Policy controls show Simulate/Audit/Enforce buttons
- [x] IAM/CLI controls show CLI steps, Terraform export, no enforcement buttons
- [x] Code change, vendor, and process controls show type-specific UIs
- [x] "+ Custom Policy" button navigates to Policies page with pre-filled workload context
- [x] Deployed policies are scoped to specific workload (not global)

### 0.2 Workload-Scoped Policy Enforcement
**Status**: DONE (deployed March 9, 2026)
**Files**: `routes.js` (from-template endpoint), `graph-routes.js` (enrichment), `init.sql`, `Policies.jsx`
**Description**: When a user enforces a policy on billing-agent, it only affects billing-agent's attack paths.
**What was built**:
- [x] `policies` table has `attack_path_id` column
- [x] `from-template` endpoint resolves workload name -> UUID, stores `client_workload_id`
- [x] Graph enrichment filters matched policies by scope
- [x] Policies page shows "Scoped to: billing-agent" badge
- [x] Gateway evaluate filters by `client_workload_id`

### 0.3 Simulate/Audit/Enforce Visual Flows End-to-End
**Status**: DONE (deployed March 9, 2026)
**Files**: `GraphPage.jsx`
**Description**: Complete visual feedback for each enforcement mode.
**What was built**:
- [x] Simulate: WOULD_BLOCK decisions shown in panel, violating nodes highlighted on graph
- [x] Audit: amber dashed edges + amber node rings + ⚡ icon, live WOULD_BLOCK decision stream
- [x] Enforce: edges severed (gray dashed + ✂), credential nodes dim (40%), enforced nodes GREEN (ring + 🛡 + fill tint), score/blast/paths deltas update live
- [x] 3-step stepper indicator (SIM → AUDIT → ENFORCE) with proper color progression

### 0.4 Connection Display Redesign
**Status**: DONE (deployed March 9, 2026)
**Files**: `GraphPage.jsx`
**What was built**:
- [x] Four color-coded semantic categories (exposure, identity, privilege, agent)
- [x] Practical meaning per relationship type
- [x] Attack path badges on connections
- [x] Three-layer evidence (Discovered/Confirmed/Actionable)
- [x] Show-more expanders for 30+ connections

---

## P1 — Competitive Moat (AI Agent Security)

### 1.1 Chain-Aware Enforcement (Anti-Confused-Deputy)
**Status**: DONE (deployed March 9, 2026)
**Files**: `routes.js` (gateway evaluate), `evaluator.js`, `templates.js`
**Description**: Policy decisions at hop N see the full trace back to hop 0. Prevents confused deputy attacks — the #1 IAM threat for agentic AI.
**What was built**:
- [x] `POST /api/v1/access/evaluate/principal` accepts `trace_id`, `token_jti`, `hop_index`, `total_hops` and queries prior hops from `ext_authz_decisions`
- [x] Chain context built: `chain.origin`, `chain.delegator`, `chain.depth`, `chain.authorized`, `chain.all_hops_allowed`, `chain.has_revoked_hop`, `chain.root_jti`, `chain.hops`
- [x] 9 new condition fields in evaluator (`chain.*` category)
- [x] Policy conditions can reference all chain fields with all operators
- [x] 3 new policy templates: `require-authorized-chain`, `chain-max-depth`, `chain-require-origin`
- [x] Chain context stored in `token_context` JSONB column on `ext_authz_decisions`
- [x] `chain_context` included in evaluate response for audit
- [x] `GET /api/v1/access/decisions/chain/:traceId` endpoint for full chain query
- [x] One DB query for prior hops (indexed on `trace_id`)
**Why it matters**: ISACA's #1 IAM threat. 80% of IT pros have seen agents perform unauthorized actions. Only 24.4% have A2A visibility. WID is the only product that enforces at every hop with chain context.

### 1.2 Deterministic Decision Replay
**Status**: DONE (deployed March 9, 2026)
**Files**: `routes.js` (replay endpoint), `init.sql` (policy_snapshots table), `evaluator.js`
**Description**: Given any `trace_id`, reconstruct the exact decision context with policy versions for auditor verification.
**What was built**:
- [x] `computePolicyVersionHash()` generates deterministic SHA-256 hash of policy conditions/actions/effect
- [x] `ext_authz_decisions` stores `policy_version` hash + `request_context` JSONB on every evaluation
- [x] `policy_snapshots` table stores versioned policy state (conditions, actions, effect, enforcement_mode, severity)
- [x] Snapshots written on first evaluation with a new policy version (deduplicated by policy_id + version_hash)
- [x] `GET /api/v1/access/decisions/replay/:traceId` returns full replay package (all hops, policy version per hop, request context, verdict, policy snapshots)
- [x] `GET /api/v1/access/decisions/chain/:traceId` returns chain analysis (origin, authorization status, all hops)
- [x] Frontend: "Audit Replay" button on trace detail view with full replay panel (metadata, per-hop policy snapshots, conditions, actions, token context, chain integrity)
- [x] PDF export for auditors (jsPDF) — downloadable replay report with trace details, hop chain, policy snapshots, chain integrity assessment
**Why it matters**: EU AI Act Article 12 mandatory August 2, 2026. California ADMT requires 5-year retention. No current product provides deterministic replay of authorization decisions across agent chains.

### 1.3 MCP Server Integrity Scanning
**Status**: DONE (deployed March 9, 2026)
**Files**: `protocol-scanner.js` (detection + integrity + poisoning), `graph-routes.js` (CONTROL_CATALOG), `GraphPage.jsx` (CONTROL_CATALOG_FALLBACK)
**Description**: 13,000+ MCP servers on GitHub, 7.2% have exploitable flaws, 5.5% have tool poisoning. WID detects MCP servers, verifies their integrity, and flags tool description poisoning.
**What was built**:
- [x] Detect MCP server connections in workload environment (env vars, config files, Agent Card skills) — already existed
- [x] Hash MCP server capabilities and compare against known-good registry (`_verifyMCPIntegrity` with SHA-256 fingerprinting)
- [x] Scan tool descriptions for hidden instructions (`_detectToolPoisoning` with 23 patterns across 8 categories: prompt-injection, hidden-text, encoded-payload, code-execution, exfiltration, suspicious-url, tool-hijack, stealth)
- [x] New finding types: `mcp-unverified-server`, `mcp-tool-poisoning`, `mcp-outdated-version`
- [x] Add to CONTROL_CATALOG with appropriate remediation controls (6 new controls across 3 finding types)
- [x] Graph nodes for MCP servers show integrity status (verified/unverified/outdated) + poisoning indicators in node metadata
- [x] Known-good registry with 12 verified packages (official @modelcontextprotocol/* servers)
**Why it matters**: Supply chain attacks against MCP servers are confirmed (Postmark, Smithery). No vendor provides MCP integrity verification at scale. This is the "Snyk for MCP servers" positioning.

---

## P2 — Production Readiness

### 2.1 Multi-Tenancy
**Status**: Not started
**Files**: All DB queries, `init.sql`, middleware
**Description**: Add `tenant_id` to all tables. Row-Level Security (RLS) in PostgreSQL. Tenant onboarding flow.
**Acceptance Criteria**:
- [ ] All tables have `tenant_id` column with RLS policies
- [ ] Tenant isolation verified (tenant A cannot see tenant B's data)
- [ ] Tenant onboarding creates isolated namespace
- [ ] API routes respect tenant context from JWT

### 2.2 Enterprise Auth (SSO)
**Status**: Not started
**Description**: SAML 2.0, OIDC federation, RBAC roles (admin, viewer, operator).
**Acceptance Criteria**:
- [ ] SAML 2.0 SSO integration (Okta, Azure AD)
- [ ] OIDC federation support
- [ ] RBAC: admin (full), operator (enforce), viewer (read-only)
- [ ] Audit log for auth events

### 2.3 Secret Manager Integration
**Status**: Credential broker exists but needs customer vault integration
**Description**: Read/rotate credentials from customer vaults (HashiCorp Vault, AWS SM, GCP SM).
**Acceptance Criteria**:
- [ ] Credential broker connects to customer Vault instances
- [ ] Auto-rotation policies for static credentials
- [ ] Rotation events logged in `credential_rotations` table

### 2.4 SIEM/SOAR Integration
**Status**: Not started
**Description**: Ship audit events to Splunk, Datadog, Sentinel. Webhook triggers.
**Acceptance Criteria**:
- [ ] Webhook endpoint configuration (Slack, PagerDuty)
- [ ] Syslog/CEF output for SIEM ingestion
- [ ] Splunk HEC integration
- [ ] Event schema documented

### 2.5 Compliance Policy Packs
**Status**: DONE (deployed March 11, 2026)
**Files**: `compliance-frameworks.js`, `templates.js`, `routes.js`, `002-policy-templates.sql`, `Compliance.jsx`
**Description**: Pre-built policy sets mapped to SOC 2, PCI-DSS, NIST 800-53, ISO 27001, EU AI Act. See `docs/COMPLIANCE.md` for full documentation.
**What was built**:
- [x] 5 frameworks defined with 68 controls (SOC 2: 10, PCI DSS: 13, NIST: 19, ISO: 17, EU AI Act: 9)
- [x] 125 of 133 templates mapped to compliance frameworks with per-control granularity
- [x] `compliance_frameworks` JSONB column on `policy_templates` with GIN index
- [x] 4 compliance API endpoints (list, detail, deploy, coverage)
- [x] One-click deploy deploys all framework templates in audit mode
- [x] Compliance dashboard page with framework cards, coverage bars, detail view, deploy workflow
- [x] Coverage tracking: real-time % per framework and per control
- [x] URL map updated for GCP load balancer routing

### 2.6 Production Hardening
**Status**: Not started
**Description**: Rate limiting, DDoS protection, WAF, encrypted audit logs, SOC 2 readiness.
**Acceptance Criteria**:
- [ ] Rate limiting on all public endpoints
- [ ] Audit log encryption at rest
- [ ] Security headers (CSP, HSTS, etc.)
- [ ] Dependency vulnerability scanning in CI

---

## P3 — Nice to Have

### 3.1 AWS Spoke Deployment
**Status**: Not started
**Description**: Terraform modules for deploying relay + edge-gateways in customer AWS.
**Acceptance Criteria**:
- [ ] Terraform module for EKS + relay + gateways
- [ ] Auto-registration with GCP central hub
- [ ] Verified policy sync and audit forwarding

### 3.2 Agent SDK
**Status**: Not started
**Description**: SDK for customers to instrument their own AI agents with WID policy evaluation.
**Acceptance Criteria**:
- [ ] Node.js SDK: `@wid/agent-sdk`
- [ ] Python SDK: `wid-agent-sdk`
- [ ] Methods: `evaluateAccess()`, `startTrace()`, `endTrace()`
- [ ] Auto-instrumentation for LangChain and CrewAI

### 3.3 Custom Domain + TLS
**Status**: Not started
**Description**: Production load balancer with custom domain, managed TLS.

### 3.4 Dashboard Stats Update After Enforce
**Status**: Not started
**Description**: Dashboard KPIs should update in real-time when policies are enforced.

### 3.5 Graph Node Label Readability
**Status**: Not started
**Description**: Labels are hard to read at low zoom levels. Need adaptive sizing.

### 3.6 Stale Relay Entries Cleanup
**Status**: Not started
**Description**: GCP hub accumulates relay entries on spoke restart. Need TTL-based cleanup.

---

## Completed

| Item | Date | Notes |
|------|------|-------|
| Multi-cloud discovery engine | 2026-02 | GCP, AWS, Azure, K8s, Docker |
| Identity graph with attack paths | 2026-02 | 11 detectors, blast radius, risk scoring |
| Policy engine with templates | 2026-02 | 14 operators, Rego compiler |
| SPIFFE/SPIRE attestation | 2026-02 | Manual + auto + continuous |
| Edge gateway (sidecar) | 2026-02 | No mesh required, AIInspector |
| Hub-spoke federation | 2026-02 | Policy sync, audit forwarding, heartbeats |
| Demo agents (7 + orchestrator) | 2026-02 | UC1, UC2, UC3 verified working |
| GCP Cloud Run deployment | 2026-03 | 6 core + 8 demo services |
| Bug fixes (4 critical) | 2026-03 | AI enrichments, credentials, events filter, controls |
| Connection provenance | 2026-03 | discovered_by + evidence on all 172 edges |
| Connection display redesign | 2026-03-09 | 4 categories, attack path badges, 3-layer evidence |
| Competitive research | 2026-03-09 | 15+ NHI vendors analyzed |
| Remediation Decision Framework | 2026-03-09 | Policy vs IAM/CLI split, type-specific UIs, + Custom Policy button |
| Workload-Scoped Policy Enforcement | 2026-03-09 | Backend scoping, from-template resolves workload, scope badge on Policies page |
| Simulate/Audit/Enforce visual flows | 2026-03-09 | Audit vs enforce node differentiation, WOULD_BLOCK preview, credential dimming |
| Chain-Aware Enforcement | 2026-03-09 | 9 chain condition fields, 3 templates, chain trace endpoint, anti-confused-deputy |
| Deterministic Decision Replay | 2026-03-09 | Policy version hashing, snapshots table, replay endpoint, EU AI Act readiness |
| MCP Server Integrity Scanning | 2026-03-09 | 23 poisoning patterns, integrity verification, 3 new finding types, 6 controls |
| P1.2 Replay UI + PDF Export | 2026-03-11 | Audit Replay button, replay panel with policy snapshots, jsPDF export |
| P2.5 Compliance Policy Packs | 2026-03-11 | 5 frameworks, 68 controls, 125 templates mapped, one-click deploy, coverage dashboard |
| Token Crypto Upgrade (HS256 → ES256) | 2026-03-13 | ECDSA P-256 asymmetric signing, JWKS endpoint, credential-broker uses validate endpoint, dual verification for migration (ADR-10) |
