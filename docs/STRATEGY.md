# WID Platform — Strategy

> Version 1.0 | March 2026
> What we are, what we are not, and why we win.

---

## Mission

WID gives enterprises visibility and control over every non-human identity — service accounts, AI agents, API keys, and machine credentials — across their entire infrastructure, with the confidence to enforce without breaking production.

---

## What WID IS

### 1. An Identity Security Platform for Non-Human Identities

WID discovers, maps, and controls NHIs across multi-cloud and hybrid environments. We build a live identity graph that shows every workload, its credentials, the external APIs it calls, and the attack paths between them.

### 2. A Progressive Enforcement Engine

Our core differentiator: **Simulate -> Audit -> Enforce**. Security teams roll out controls without operational risk. No other NHI platform offers this. This is how you get CISOs to actually press the button.

### 3. An Edge-First Data Plane

Policy decisions happen at the edge, not in a central bottleneck. Edge gateways with embedded OPA evaluate policy locally using cached, signed bundles. The control plane can fail — enforcement continues. Sub-millisecond decisions at scale.

### 4. An AI Agent Security Platform

WID is built from day one to trace and enforce across multi-hop AI agent chains. A2A Agent Card scanning, MCP server discovery, delegation chain monitoring, and per-hop authorization decisions with full trace correlation.

### 5. A Compliance Evidence Engine

Every authorization decision is logged with full context: who called what, under which policy version, with what verdict, linked to the full trace chain. This is the audit evidence that EU AI Act Article 12, SOC 2, and ISO 42001 require.

---

## What WID is NOT

### 1. NOT an LLM Firewall

We do not inspect prompt content, detect jailbreaks, or filter model outputs. That's Lakera, Prompt Security, and now Palo Alto (Protect AI) and Cisco (Robust Intelligence). Prompt injection detection is a feature, not a product — and it's being commoditized by the big platforms. We operate at the infrastructure/identity layer, not the model layer.

### 2. NOT a SaaS-Only Scanner

We are not Astrix or Oasis. We don't just discover NHIs via API scanning and recommend remediations. We sit in the data path and enforce in real-time. Discovery without enforcement is a report, not a security product.

### 3. NOT a PAM Extension

We are not CyberArk or Delinea extending PAM to non-human identities. PAM is vault-centric (store and rotate secrets). WID is identity-centric (attest workloads, enforce policy at the edge, trace delegation chains). We integrate with vaults — we don't replace them.

### 4. NOT a Service Mesh

We are not Istio or Envoy. We don't require a service mesh. Our edge gateway works without one. For customers who already have Istio, we provide an ext-authz adapter that plugs into their existing mesh. We complement meshes, we don't compete with them.

### 5. NOT a CNAPP / Cloud Security Posture Tool

We are not Wiz, Orca, or Prisma Cloud. We don't scan cloud infrastructure for misconfigurations across all resource types. We focus specifically on identity — who can access what, through which credentials, and what the blast radius is. We can integrate with CNAPPs to enrich their findings with identity context.

### 6. NOT a SIEM or SOAR

We produce audit events, we don't aggregate them from other sources. We integrate with SIEMs (Splunk, Datadog, Sentinel) as a data source, not as a replacement.

---

## Target Buyer

### Primary: CISO / Head of Identity

**Pain**: "I have 17x more non-human identities than human users, and I have zero visibility into what they can access. My board asks about NHI risk every quarter and I don't have an answer."

**Why WID**: One graph that shows the full blast radius of every NHI. Simulate/Audit/Enforce so they can demonstrate progress to the board without production risk.

### Secondary: Platform Engineering / DevSecOps Lead

**Pain**: "Security wants me to lock down service accounts but they can't tell me which ones are actually used. I can't rotate credentials without breaking things."

**Why WID**: Simulate mode shows exactly what would break before you touch anything. Evidence from runtime traffic confirms which credentials are actually in use vs. theoretical permissions.

### Tertiary: Compliance / Audit Team

**Pain**: "Our auditor is asking for evidence that AI agents are governed. We have nothing."

**Why WID**: Decision logs with full trace context, policy version tracking, deterministic replay — the structured evidence that SOC 2 and EU AI Act Article 12 require.

---

## Competitive Positioning

### The Market Has Two Lanes

**Lane 1 — Discovery-Only (Reports)**: Astrix, Oasis, Clutch, Silverfort. They scan APIs, produce inventories, recommend remediations. They do NOT sit in the data path or enforce in real-time. Switching cost is near zero — export findings, import into another tool. No moat.

**Lane 2 — Identity + Enforcement (Controls)**: Aembit, CyberArk, WID. These products issue credentials, enforce policy at runtime, and produce audit evidence. Switching cost is high because enforcement policies, audit trails, and operational workflows are built around the platform. Strong moat.

### WID's Unique Capabilities

Three things no competitor offers today:

| Capability | What It Means | Why Nobody Else Has It |
|-----------|---------------|----------------------|
| **Simulate -> Audit -> Enforce** | Project impact before touching traffic. Graduated rollout per workload. | Requires sitting in the data path (edge gateway) AND having a graph that updates in real-time. Aembit has enforcement but no graph. Wiz has a graph but no enforcement. |
| **Multi-Hop Trace Correlation** | `trace_id` + `hop_index` + `total_hops` across entire agent delegation chains. Full chain visibility in one audit view. | Requires instrumenting every hop in the chain. Only possible when your edge gateway is the enforcement point at each hop. |
| **Attack Path Graph + Blast Radius** | Compute exactly what an attacker can reach if any single NHI is compromised. Visual graph that updates when policies are enforced. | Requires both discovery (scan APIs) and runtime data (traffic through gateway). Pure scanners have theoretical blast radius. WID has observed blast radius. |

### Competitive Matrix

| Capability | WID | Aembit | Astrix | CyberArk | Wiz |
|-----------|-----|--------|--------|----------|-----|
| NHI Discovery | Multi-cloud + hybrid | Cloud + SaaS | SaaS + cloud | Cloud + SaaS | Cloud only |
| Identity Graph | Full with blast radius | No graph | Relationship graph | No graph | Security graph |
| Simulate/Audit/Enforce | Yes | No (enforce only) | No | No | No |
| Edge enforcement (data plane) | Edge gateway | MCP gateway | No | AI Agent Gateway | No |
| AI agent chain tracing | Full multi-hop | Single hop | Discovery only | Single hop | Discovery only |
| Works without service mesh | Yes | Requires agent | N/A (SaaS) | Requires agent | N/A (agentless) |
| Hub-spoke federation | Yes | No | No | No | No |
| SPIFFE attestation | Yes | No | No | No | No |

---

## Moat Analysis

### What Creates Defensibility

1. **Data Gravity from Edge Gateway**: Every request through the gateway produces a decision record. After 90 days, the behavioral baseline is irreplaceable. Competitors start with zero history. Switching means losing 90+ days of baseline — no CISO accepts that gap.

2. **Operational Switching Cost from Simulate/Audit/Enforce**: Each policy goes through a 3-4 week organizational process (simulate -> review -> audit -> review -> enforce). After 50 policies, that's months of organizational consensus baked in. Switching means re-doing all of it.

3. **Compliance Lock-In from Decision Logs**: Once an audit team builds their SOC 2 / EU AI Act evidence process around WID's trace format, switching means rebuilding the evidence pipeline. 6-12 month migration that no one approves mid-audit.

### What Does NOT Create Defensibility

- Discovery alone (API scanning) — zero switching cost, export and reimport
- Dashboard UI — any team can build a prettier dashboard
- Number of cloud providers supported — table stakes within 12 months
- AI agent detection — every NHI vendor is adding this

### Strategic Priority

**Get customers to deploy edge gateways as early as possible.** Discovery-only customers can leave. Data-path customers can't. Every day of traffic through WID's gateway increases the switching cost.

---

## Market Context (March 2026)

- NHI market projected at $18.7B by 2030 (CAGR 11.5%)
- 60%+ of enterprises deploy AI agents in production
- 88% report confirmed or suspected AI security incidents
- EU AI Act Article 12 mandatory August 2, 2026 (5 months)
- 13,000+ MCP servers on GitHub, 7.2% with exploitable flaws
- Only 24.4% of organizations have full visibility into A2A communication
- 80% of IT pros have seen agents perform unauthorized actions
- Palo Alto acquired Protect AI, Cisco acquired Robust Intelligence — LLM firewall consolidation complete
- Aembit, Astrix, CyberArk, Wiz all launched AI agent security features in 2025

---

## Anti-Goals

Things we will deliberately NOT do:

1. **Build a general-purpose CNAPP**. We focus on identity and access paths. Cloud misconfigurations (S3 bucket public, security group too open) are only relevant when they're part of an identity attack path.

2. **Compete on discovery breadth with Astrix**. Astrix integrates with 200+ SaaS APIs. We don't need to scan Salesforce's internal RBAC. We need to know that a service account has a Salesforce API key and what it can reach.

3. **Sell to SMBs**. Our buyer is a CISO at a 500+ employee company with multi-cloud infrastructure and compliance requirements. SMBs don't have NHI problems at scale.

4. **Build a model security product**. We don't evaluate model safety, detect hallucinations, or test adversarial robustness. That's a different product category.

5. **Require infrastructure changes to adopt**. Edge gateway drops in next to any workload. No service mesh. No kernel module. No eBPF. No agent SDK required for day-1 value.
