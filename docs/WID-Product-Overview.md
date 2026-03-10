# Workload Identity Director (WID)

### The Identity Security Platform for Non-Human Identities and AI Agents

---

## The Problem: A $10.7B Blind Spot

Every enterprise runs thousands of non-human identities (NHIs) — service accounts, API keys, AI agents, machine credentials — that outnumber human users 17:1. These identities access databases, payment APIs, AI models, and internal services across multi-cloud environments. Yet most enterprises have **zero visibility** into what these identities can access, which credentials are over-privileged, and what the blast radius would be if any single one were compromised.

The consequences are real. Static API keys never get rotated. Service accounts accumulate permissions over years. AI agents call external APIs with hardcoded credentials nobody tracks. A compromised service account in staging can reach production databases through credential chains that no human approved.

**This is the fastest-growing attack surface in enterprise security** — and the market is projected to reach $18.7B by 2030 (MarketsandMarkets, CAGR 11.5%).

---

## What WID Does

WID is an enterprise-grade platform that **discovers, maps, and controls every non-human identity** across your infrastructure — from Kubernetes workloads to AI agent chains.

### Core Capabilities

**1. Discovery & Identity Graph**
Automatically discover all NHIs across AWS, GCP, Azure, Kubernetes, Docker, and on-prem environments. WID builds a live identity graph that maps every workload, its credentials, the external APIs it calls, and the attack paths between them. Risk scores are computed from blast radius (how many downstream systems are reachable) and credential exposure (static keys, over-privileged access, toxic delegation chains).

**2. Attack Path Analysis**
For every workload, WID identifies credential chains — `workload -> static-credential -> external-API` — and computes blast radius. If a billing agent is compromised, WID shows exactly which payment APIs, databases, and downstream services are reachable, and ranks them by risk.

**3. Progressive Policy Enforcement: Simulate -> Audit -> Enforce**
This is WID's core differentiator. Instead of "deploy and pray," WID lets security teams roll out controls progressively:

- **Simulate** — Project what *would* be blocked without touching live traffic. Security teams see WOULD_BLOCK decisions, validate impact, build confidence.
- **Audit** — Enable live monitoring. Traffic still flows, but every authorization decision is logged with full trace context. Violations become visible in real-time dashboards.
- **Enforce** — Block unauthorized access. Credential edges are severed, static keys are replaced with short-lived SPIFFE-bound tokens, and the identity graph updates in real-time — risk scores drop, attack paths go to zero.

No other NHI platform offers this three-phase rollout. This is how you get security teams to actually press the button.

**4. AI Agent Chain Tracing**
WID traces authorization decisions across multi-hop AI agent chains. When a ServiceNow IT agent calls a code-review agent, which calls OpenAI, which triggers a billing check against Stripe — WID traces every hop with `trace_id`, `hop_index`, and `total_hops`. Full chain visibility in one audit view.

**5. Edge-First Architecture**
Policy decisions happen at the edge, not in a central bottleneck. Each environment runs lightweight edge gateways with embedded OPA engines that evaluate policy locally using cached, signed policy bundles. The control plane can go down — enforcement continues. This is how you get sub-millisecond policy decisions at scale.

---

## Example: Three Real-World Use Cases

| Use Case | What Happens | What WID Does |
|----------|-------------|---------------|
| **IT Ticket Orchestration** | ServiceNow agent -> Code Review (OpenAI) -> Billing (Stripe). 4-hop chain with static API keys at each hop | Maps full chain, scores risk, enforces per-hop authorization. Blocks non-billing agents from accessing Stripe. |
| **Supply Chain Security** | GitHub Actions agent delegates to Code Review agent (toxic delegation). Unintended transitive access | Detects toxic delegation chain. In Enforce mode, blocks the unauthorized delegation while allowing direct access. |
| **Shadow AI Detection** | CRM agent secretly calls Anthropic API with customer data. No approved integration exists | Discovers undocumented AI API calls via credential scanning. Flags as shadow AI. Enforce blocks the call. |

---

## How WID Compares

| Capability | WID | Astrix Security | Oasis Security | Aembit |
|-----------|-----|-----------------|----------------|--------|
| **NHI Discovery** (multi-cloud) | AWS, GCP, Azure, K8s, Docker, on-prem | SaaS, cloud, secret managers | Multi-environment | Cloud, SaaS, on-prem |
| **Identity Graph + Attack Paths** | Full graph with blast radius, risk scores, credential chains | Relationship graph between NHIs and resources | Posture-based view | No graph — access policy focused |
| **Progressive Enforcement (Sim/Audit/Enforce)** | Native three-phase rollout per workload | Remediation workflows (not inline enforcement) | Policy-driven remediation | Inline enforcement (no simulation phase) |
| **AI Agent Chain Tracing** | End-to-end trace across multi-hop agent chains | AI agent discovery | Not specialized for AI agents | Agent identity support |
| **Edge-First Data Plane** | Distributed gateways, local OPA, works without control plane | Cloud-only SaaS | Cloud SaaS | Proxy-based broker |
| **Works Without Service Mesh** | Yes — edge gateway deploys anywhere (VMs, Docker, K8s) | N/A (SaaS API-based) | N/A (SaaS) | Requires agent install |
| **Hub-Spoke Federation** | Central control plane + spoke relays per environment | Centralized | Centralized | Centralized |
| **Deployment Model** | Self-hosted or managed. Runs in customer VPC | SaaS only | SaaS only | SaaS + agent |

### Why WID Wins

1. **Simulate before you Enforce.** No other NHI platform lets you project enforcement impact before touching live traffic. This is the difference between a security tool that gets deployed and one that sits on the shelf. CISOs buy tools that their teams will actually use.

2. **Edge-first, not cloud-only.** Astrix and Oasis are SaaS-only — they can discover and recommend, but they can't enforce inline at the workload level. WID's edge gateways sit in the data path and make real-time decisions with cached policy. This works in air-gapped, on-prem, and hybrid environments where SaaS-only solutions can't reach.

3. **AI agent chains are first-class.** As agentic AI explodes (44% growth in NHIs from 2024-2025, driven by AI agents), WID is built from day one to trace and enforce across multi-hop agent chains. Competitors bolt this on; WID was designed around it.

4. **No infrastructure prerequisites.** Competitors like Aembit require agent installs or specific infrastructure. WID's edge gateway works without a service mesh, without Istio, without Envoy. Drop it next to any workload and it works.

---

## What We've Built (Current State)

| Component | Status |
|-----------|--------|
| Multi-cloud discovery engine (AWS, GCP, Azure, K8s, Docker) | Live |
| Identity graph with attack paths, blast radius, risk scoring | Live |
| Simulate / Audit / Enforce policy engine | Live |
| SPIFFE/SPIRE-based workload attestation | Live |
| Edge gateway (sidecar, no mesh required) | Live |
| Hub-spoke federation (central control plane + spoke relays) | Live |
| AI agent chain tracing (trace_id, hop_index) | Live |
| 3 demo use cases (IT orchestration, supply chain, shadow AI) | Live |
| React SPA with identity graph, playbook, evidence tabs | Live |
| Connector onboarding (cloud account setup wizard) | Live |
| User authentication (login, JWT sessions) | Live |
| GCP Cloud Run deployment (6 core services + 8 demo agents) | Live |
| Pre-deploy security scanning (npm audit, gitleaks, trivy) | Live |

---

## Path to Production Grade

| Priority | Area | What's Needed | Effort |
|----------|------|--------------|--------|
| **P0** | Multi-tenancy | Tenant isolation (tenant_id + RLS), tenant onboarding, billing integration | 4-6 weeks |
| **P0** | SSO / Enterprise Auth | SAML 2.0, OIDC federation, RBAC (admin/viewer/operator roles) | 2-3 weeks |
| **P0** | Secret Management | Integration with customer vaults (HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager) for credential rotation | 3-4 weeks |
| **P1** | Compliance Frameworks | Pre-built policy packs for SOC 2, PCI-DSS, NIST 800-53, ISO 27001. Compliance dashboards | 3-4 weeks |
| **P1** | Real Remediation Execution | Today: recommend controls. Next: one-click execute (rotate key, revoke SA, deploy JIT token) via Terraform/CLI | 4-5 weeks |
| **P1** | SIEM/SOAR Integration | Ship audit events to Splunk, Datadog, Sentinel. Webhook triggers for PagerDuty/Slack | 2 weeks |
| **P1** | Production Hardening | Rate limiting, DDoS protection, WAF, encrypted audit logs, SOC 2 Type II readiness | 3-4 weeks |
| **P2** | Agent SDK | SDK for customers to instrument their own AI agents with WID policy evaluation | 2-3 weeks |
| **P2** | MCP Protocol Scanner | Full Model Context Protocol discovery — detect MCP server connections and tool invocations | 2-3 weeks |
| **P2** | AWS/Azure Spoke Deployment | Terraform modules for deploying spoke relays + gateways in customer AWS/Azure environments | 2-3 weeks |
| **P2** | Custom Domain + TLS | Production load balancer with custom domain, managed TLS certificates | 1 week |

**Total to production-ready v1.0: ~16-20 weeks** with a team of 3-4 engineers, prioritizing P0 + P1 items.

---

*WID: See every identity. Trace every chain. Enforce with confidence.*
