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

### 1.4 MCP Tool Invocation Auditing (Runtime)
**Status**: DONE (deployed March 13, 2026)
**Files**: `mcp-inspector.js`, `core.js`, `gateway.js`, `routes.js`, `14-mcp-telemetry.sql`, `init.sql`
**Description**: Intercept MCP JSON-RPC traffic at the edge gateway, log structured telemetry to dedicated audit table. Zero hot-path latency (same pattern as AIInspector).
**What was built**:
- [x] MCPInspector class mirroring AIInspector (zero-copy tee, async parse, AuditBuffer emission)
- [x] O(1) MCP host detection via configurable Set
- [x] Tool argument values redacted by default (keys only, zero customer data)
- [x] `mcp_tool_events` table with indexes on source, destination, tool, method, created_at
- [x] Batch routing in policy-sync-service (mcp_tool_call INSERT, mcp_tool_response UPDATE)
- [x] `GET /api/v1/mcp/events` — filtered MCP events query
- [x] `GET /api/v1/mcp/events/stats` — aggregated stats by server, tool, source
- [x] 21 tests passing

### 1.5 Dynamic Capability Fingerprinting
**Status**: DONE (deployed March 13, 2026)
**Files**: `protocol-scanner.js`, `graph-routes.js`, `discovery index.js`, `15-mcp-fingerprints.sql`, `init.sql`
**Description**: Periodically re-probe MCP servers, detect capability drift (tools added/removed, descriptions changed). Catches post-deployment supply chain poisoning.
**What was built**:
- [x] Enhanced fingerprint includes tool descriptions hash (catches description-only poisoning)
- [x] `rescanMCPServers()` method: re-probe, compute fingerprint, compare, store drift
- [x] `_computeDriftDetails()`: tools added/removed, description change detection
- [x] `mcp_fingerprints` table with drift tracking
- [x] Periodic scheduler (default 5 min, configurable via `MCP_RESCAN_INTERVAL_MS`)
- [x] `mcp-capability-drift` finding type (severity: high, category: supply-chain)
- [x] 2 new controls: `mcp-drift-investigate`, `mcp-drift-pin-version`
- [x] `GET /api/v1/mcp/fingerprints` and `GET /api/v1/mcp/fingerprints/:workloadName/drift` endpoints
- [x] 15 tests passing

### 1.6 Agent Card JWS Signing & Verification
**Status**: DONE (deployed March 13, 2026)
**Files**: `agent-card-signer.js`, `crypto.js`, `token-service index.js`, `protocol-scanner.js`, `agent-base.js`, `GraphPage.jsx`
**Description**: Cryptographically sign A2A Agent Cards with ES256 (same keys as token-service), verify during discovery, expose 4-state verification status.
**What was built**:
- [x] `shared/agent-card-signer.js` — zero-dependency JWS compact serialization (sign + verify)
- [x] Token-service `getPrivateKeyPem()`/`getPublicKeyPem()` exports
- [x] `POST /api/v1/agent-card/sign` endpoint (30-day expiry, issuer: workload-identity-platform)
- [x] Demo agents sign Agent Cards on startup (graceful degradation if token-service unavailable)
- [x] Protocol scanner verifies JWS signatures during discovery (JWKS cached 1 hour)
- [x] 4-state signature status: `verified`, `invalid`, `unverified`, `unsigned`
- [x] `a2a-invalid-signature` finding type (severity: high) with 2 controls
- [x] Graph nodes show `signature_status` and `signature_kid` in metadata
- [x] 14 tests passing

---

## P2 — Production Readiness

### 2.1 Multi-Tenancy
**Status**: DONE (deployed March 15, 2026)
**Files**: `init.sql`, `tenant-middleware.js`, `routes.js`, `auth-routes.js`, all service DB query modules
**Description**: Shared database, shared schema with PostgreSQL RLS + application-layer tenant middleware + tenant-scoped caches. Three defense layers. See [ADR-12](ADR-12-multi-tenancy.md).
**What was built**:
- [x] `tenants` and `tenant_memberships` tables with registration + invitation flow
- [x] All 25+ data tables have `tenant_id NOT NULL` column with RLS policies
- [x] Tenant middleware extracts `tenantId` from JWT, sets `SET LOCAL app.current_tenant` on every DB connection
- [x] `pg.Client` replaced with `pg.Pool` across all services
- [x] All cache keys prefixed with `tenant:{tenantId}:` (policy cache, graph cache, relay cache)
- [x] JWT includes `tenantId` and `tenantSlug` claims
- [x] Relay registration includes tenant binding (spoke-to-tenant verified via mTLS + API key)
- [x] Data sovereignty: region-tagged tenants, strict residency mode, spoke-local storage for sovereign deployments
- [x] 20 threat categories covered (cross-tenant leakage, cache poisoning, JWT spoofing, IDOR, privilege escalation, etc.)
- [x] Tenant API: create, update, invite, list members, switch context
- [x] Existing single-tenant data migrated to default tenant on upgrade

### 2.2 Enterprise Auth (SSO)
**Status**: Not started
**Description**: SAML 2.0, OIDC federation, RBAC roles (admin, viewer, operator).
**Acceptance Criteria**:
- [ ] SAML 2.0 SSO integration (Okta, Azure AD)
- [ ] OIDC federation support
- [ ] RBAC: admin (full), operator (enforce), viewer (read-only)
- [ ] Audit log for auth events

### 2.3 Secret Manager Integration
**Status**: DONE (deployed March 16, 2026)
**Files**: `azure-provider.js`, `gcp-provider.js`, `aws-provider.js`, `vault-provider.js`, `scheduler.js`, `lifecycle-routes.js`, `004-credential-rotations.sql`
**Description**: Read/rotate credentials from customer vaults (HashiCorp Vault, AWS SM, GCP SM, Azure KV).
**What was built**:
- [x] All 4 providers fully functional: Vault (KV v1/v2 + dynamic secrets), AWS SM, GCP SM, Azure KV
- [x] All providers support: getSecret, putSecret, rotateSecret, revokeSecret, listSecrets, healthCheck
- [x] Auto-rotation scheduler with configurable intervals per secret (30d, 90d, custom)
- [x] Rotation events logged in `credential_rotations` table with audit trail
- [x] API: rotate, rotation-status, providers list with health
- [x] Provider priority with automatic failover

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
**Status**: DONE (deployed March 16, 2026)
**Files**: `security-headers.js`, `rate-limit-middleware.js`, `005-audit-encryption.sql`, `.github/workflows/`, `core.js` (RateLimiter), `gateway.js`
**Description**: Rate limiting, security headers, encrypted audit logs, CI security scanning.
**What was built**:
- [x] Security headers middleware (HSTS, CSP, X-Frame-Options, etc.) mounted on all 4 services
- [x] Rate limiting middleware: 10 req/min per IP on auth, 300 req/min per tenant on API
- [x] Per-tenant rate limiting at edge gateway with X-RateLimit-* response headers
- [x] Audit log encryption at rest (pgcrypto, column-level on details/context blobs)
- [x] GitHub Actions CI: npm audit, tests, container scanning (Trivy)
- [x] Security headers: CSP, HSTS, nosniff, DENY framing, referrer policy, permissions policy

### 2.7 Multi-Cloud Spoke Hardening
**Status**: Federation Trust + Azure Spoke DONE (March 16, 2026). Relay HA, Observability, AWS/GCP hardening remaining.
**Files**: `tls-manager.js`, `trace-context.js`, `federation-routes.js`, `relay index.js`, `003-spoke-relays.sql`, `ADR-13`
**Description**: Production-grade spoke deployments across AWS, GCP, and Azure. Current spokes work for demo but lack trust, HA, and observability.
**Acceptance Criteria**:

**Federation Trust (all clouds)** — DONE:
- [x] mTLS between spoke relay and central hub (SPIFFE SVIDs for relay identity)
- [x] Spoke identity verification on registration (hub validates relay certificate)
- [x] Cross-environment delegation chain linking (trace_id spans AWS→GCP hops)
- [x] Webhook/push-based policy updates (complement pull-based sync for urgent revocations)
- [x] DB-backed relay registry (`spoke_relays` table, replaces in-memory Map)
- [x] Federation audit trail (`federation_events` table)
- [x] Certificate bootstrap flow for environments without SPIRE
- [x] Automatic stale relay detection (5-min heartbeat timeout)
- [x] Relay revocation API with cert fingerprint invalidation
- [x] API key fallback for backward compatibility

**Relay High Availability**:
- [ ] Relay desired_count=2+ with health-based routing (AWS ALB, GCP LB)
- [ ] Audit buffer persistence (SQS/Pub/Sub queue before central) — no event loss on relay crash
- [ ] Graceful shutdown: drain audit buffer before termination (SIGTERM handler)
- [ ] Exponential backoff on central sync failures (currently fixed interval)

**Observability**:
- [ ] Prometheus metrics export from relay (policy_sync_duration, audit_buffer_size, central_reachable)
- [ ] CloudWatch/Cloud Monitoring dashboards per spoke
- [ ] Alerting: spoke disconnected >5min, audit buffer >80% full, policy version drift

**AWS Spoke**:
- [ ] HTTPS on ALB (ACM certificate)
- [ ] VPC Flow Logs enabled
- [ ] ECS task auto-scaling (CPU/memory triggers)
- [ ] Cost tagging for spoke resources

**GCP Central**:
- [ ] Cloud Run min-instances=1 for relay (avoid cold start on spoke registration)
- [ ] Cloud Armor WAF rules on LB
- [ ] Cloud SQL automated backups verified
- [ ] Secret Manager rotation for DB credentials

**Azure Spoke** — DONE:
- [x] Complete Container Apps Terraform (VNET, Managed Identity, Key Vault, Monitor)
- [x] Azure Monitor integration (alert rules: relay health, container restarts, memory)
- [x] Managed Identity for relay (no stored credentials — User-Assigned MI with AcrPull + KV access)
- [x] VNET integration for private connectivity (10.2.0.0/16 with Container Apps subnet)

---

## P3 — Nice to Have

### 3.1 AWS Spoke Deployment
**Status**: DONE (deployed March 13, 2026)
**Files**: `deploy/aws/terraform/spoke/` (main.tf, variables.tf, outputs.tf)
**Description**: ECS Fargate spoke with relay + N edge-gateways (configurable). Terraform modules for deploying in customer AWS.
**What was built**:
- [x] Terraform module: VPC, ECS Fargate, ALB, ECR, IAM, CloudWatch, Service Discovery
- [x] Relay registers with GCP central hub on startup
- [x] Policy sync (pull every 15s) and audit forwarding (batch every 5s) verified
- [x] Gateway configs via `gateway_configs` variable (0 to N gateways)
- [x] Secrets Manager integration for central API key

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
**Status**: DONE (deployed March 16, 2026)
**Description**: Dashboard KPIs update in real-time via BroadcastChannel when policies are enforced. "Last updated" indicator. Poll interval reduced to 15s.

### 3.5 Graph Node Label Readability
**Status**: DONE (deployed March 16, 2026)
**Description**: Adaptive font sizing (7-12px) based on zoom level. Smooth opacity fade-in. Dark halo stroke for contrast. Zoom-dependent label truncation.

### 3.6 Stale Relay Entries Cleanup
**Status**: DONE (March 16, 2026) — part of mTLS Federation (ADR-13)
**Description**: 5-minute heartbeat timeout with automatic stale marking. Federation routes handle cleanup.

### 3.7 Per-Tenant Rate Limiting at Gateway
**Status**: DONE (deployed March 16, 2026)
**Description**: Rate limiting at edge gateway level, keyed by tenant_id. Part of Production Hardening.
**What was built**:
- [x] Per-tenant request rate limits (configurable via env vars)
- [x] Rate limit headers in responses (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
- [x] 429 response with Retry-After when exceeded
- [ ] 429 response with retry-after when exceeded
- [ ] Gateway-level implementation (not per-service) for single enforcement point

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
| AWS Spoke Deployment | 2026-03-13 | ECS Fargate relay, Terraform module, federation with GCP hub verified |
| Multi-Tenancy | 2026-03-15 | Shared schema + RLS + tenant middleware + scoped caches. 20 threat categories. Data sovereignty (ADR-12) |
| mTLS Federation Trust | 2026-03-16 | SPIFFE SVID relay auth, TLSManager, cert bootstrap, webhook push, DB relay registry, cross-env trace linking, federation audit trail (ADR-13) |
| Azure Spoke Hardening | 2026-03-16 | Managed Identity, VNET integration, Azure Key Vault, Azure Monitor alerts, mTLS env vars |
| Secret Manager Integration | 2026-03-16 | All 4 providers complete (Vault, AWS SM, GCP SM, Azure KV), auto-rotation scheduler, credential_rotations table |
| Production Hardening | 2026-03-16 | Security headers, rate limiting (control + data plane), audit encryption (pgcrypto), CI pipeline (GitHub Actions) |
| Demo Polish | 2026-03-16 | Graph adaptive labels (7-12px + halo), Dashboard BroadcastChannel refresh, per-tenant gateway rate limiting |
