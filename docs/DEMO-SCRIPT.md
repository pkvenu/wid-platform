# WID Platform — Demo Script

> **Format**: 8-minute walkthrough | **Audience**: Hiring managers, VPs of Engineering, CISOs
> **Tone**: Confident, technical but accessible, problem-led
> **Setup**: Live GCP deployment at `http://34.120.74.81` with 7 demo agents running

---

## Opening Hook (0:00 - 0:45)

> *"There are 100 machine identities for every human in a typical enterprise. 97% of them have excessive privileges. And with AI agents, these identities are now autonomous — they can spin up new resources, call APIs, delegate to other agents, all without a human in the loop.*
>
> *The security industry calls this the non-human identity crisis. ISACA ranked it the #1 IAM threat for 2026. And yet — no product on the market can answer a simple question: if this agent is compromised, what can the attacker reach?*
>
> *That's what WID does. Let me show you."*

---

## Act 1: Discovery & Identity Graph (0:45 - 2:30)

**What to show**: Navigate to the Graph page. The force-directed graph should be fully loaded with workloads, credentials, service accounts, and attack paths.

### Talking Points

> *"WID auto-discovers every non-human identity across your infrastructure — GCP, AWS, Azure, Kubernetes, Docker. We're looking at a live environment right now."*

**Click on a workload node (e.g., `billing-agent`):**

> *"This is billing-agent — an AI agent that processes invoices. WID discovered it automatically, found it runs as a GCP service account, holds credentials to Stripe and our internal Cloud SQL database, and communicates with three other agents via the A2A protocol.*
>
> *Notice the risk score: 78 out of 100. Why? Let me show you."*

**Expand the attack path panel:**

> *"WID found 4 attack paths from this single agent. If billing-agent is compromised, an attacker can pivot through its shared service account to reach the CRM database — that's customer PII. The blast radius is 6 nodes.*
>
> *No other product shows you this. Competitors do credential scanning — they tell you 'you have a leaked key.' We show you 'that leaked key gives an attacker a path to your customer database through 3 intermediate hops.'"*

**Show the connection types:**

> *"Every connection is color-coded and evidence-backed: red for credential exposure, blue for identity bindings, orange for privilege chains, green for agent protocols. Each one has three layers of evidence — discovered, confirmed, and actionable."*

---

## Act 2: Policy Enforcement — Simulate, Audit, Enforce (2:30 - 4:30)

**What to show**: Click on a finding/control in the attack path panel, then walk through the 3-step enforcement flow.

### Talking Points

> *"Discovery is table stakes. The real value is enforcement. WID has a unique 3-stage lifecycle: Simulate, Audit, Enforce."*

**Click "Simulate" on a policy control:**

> *"Simulate shows us what WOULD happen if we blocked this path — without actually blocking anything. See? 'WOULD_BLOCK: billing-agent -> stripe-api'. The graph highlights the affected nodes. Zero risk to production."*

**Promote to "Audit":**

> *"Now in Audit mode. The policy is live — every request is evaluated — but nothing is blocked. These amber indicators show real traffic that violates the policy. We're collecting evidence.*
>
> *This is critical for compliance. The EU AI Act requires that you can demonstrate you observed before you enforced. WID gives you that audit trail automatically."*

**Promote to "Enforce":**

> *"Now I click Enforce. Watch the graph — the edge turns gray and dashed, the credential node dims, and billing-agent gets a green shield. That attack path is severed. The risk score just dropped from 78 to 34.*
>
> *This happened at the edge gateway — no central dependency, sub-millisecond latency. Even if our control plane goes down, enforcement continues with cached policies."*

---

## Act 3: Chain-Aware Enforcement — Anti-Confused-Deputy (4:30 - 5:45)

**What to show**: Navigate to Access Events, find a multi-hop trace, click "Audit Replay."

### Talking Points

> *"Here's where WID is fundamentally different from every NHI vendor. AI agents delegate to other agents — user calls billing-agent, billing-agent calls the CRM agent, CRM agent calls a Stripe MCP server. That's a 3-hop delegation chain.*
>
> *ISACA's #1 IAM threat: the confused deputy problem. 80% of IT pros have seen agents perform unauthorized actions. Only 24% have agent-to-agent visibility."*

**Click on a trace with 3+ hops:**

> *"WID tracks every hop. At each step, the policy engine sees the full chain context — who initiated it, what scopes were delegated, whether any previous hop was revoked. If hop 2 tries to escalate beyond what hop 1 allowed, it's blocked.*
>
> *And everything is deterministically replayable."*

**Click "Audit Replay":**

> *"This replay shows the exact policy version, the exact request context, and the exact verdict for every hop. I can export this as a PDF for auditors. This is EU AI Act Article 12 compliance — mandatory August 2, 2026. No other product has this."*

---

## Act 4: MCP Server Integrity (5:45 - 6:30)

**What to show**: Find an MCP server node in the graph, click it.

### Talking Points

> *"There are 13,000 MCP servers on GitHub. Research shows 7.2% have exploitable flaws, 5.5% have tool description poisoning — hidden instructions that make AI agents exfiltrate data.*
>
> *WID scans every MCP server your agents connect to."*

**Show the MCP findings:**

> *"This MCP server has a verified integrity fingerprint — we hash its capabilities and compare against known-good. If someone pushes a poisoned update that changes tool descriptions, WID detects the drift and flags it immediately.*
>
> *We scan for 23 poisoning patterns across 8 attack categories: prompt injection, hidden text, encoded payloads, exfiltration URLs, tool hijacking. This is the 'Snyk for MCP servers' that the market is missing."*

---

## Act 5: Production Architecture (6:30 - 7:30)

**What to show**: Switch to a terminal or architecture slide showing the hub-spoke topology.

### Talking Points

> *"Let me show you the architecture, because this is where the engineering depth matters."*

> *"WID runs as a hub-and-spoke federation. The central hub is on GCP — policy engine, discovery, token service. Spokes run in customer environments — we have a live AWS spoke on ECS Fargate and an Azure spoke on Container Apps, both deployed via Terraform."*

> *"Spokes authenticate to the hub using mTLS with SPIFFE X.509 SVIDs — cryptographic relay identity, not shared API keys. Certificate rotation is automatic. If a spoke is compromised, we revoke its certificate without affecting any other spoke."*

> *"Policy evaluation happens locally at the edge — embedded OPA, sub-millisecond decisions, no round-trip to central. The hub can be completely down and enforcement continues. Policies sync every 15 seconds; urgent revocations push via webhook in under 2 seconds."*

> *"Credentials are managed through a pluggable broker that connects to customer vaults — HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault. Auto-rotation policies per secret, full audit trail."*

> *"Multi-tenant from day one — PostgreSQL RLS on every table, tenant-scoped caches, data sovereignty with region-tagged spokes. Five compliance frameworks built in — SOC 2, PCI DSS, NIST 800-53, ISO 27001, EU AI Act — with one-click policy deployment."*

---

## Closing (7:30 - 8:00)

> *"To summarize what you just saw:*
>
> 1. *Auto-discovery of every non-human identity across multi-cloud*
> 2. *Attack path analysis showing blast radius from any compromised identity*
> 3. *Simulate-Audit-Enforce lifecycle with zero-downtime policy rollout*
> 4. *Chain-aware enforcement that prevents confused deputy attacks across AI agent delegation chains*
> 5. *MCP server integrity scanning — the supply chain security layer no one else has*
> 6. *Deterministic decision replay for EU AI Act compliance*
> 7. *Production architecture: mTLS federation, edge enforcement, multi-cloud, multi-tenant*
>
> *The NHI problem is real. 100:1 machine-to-human ratio, 97% over-privileged, and AI agents are making it worse every day. WID is the platform that makes non-human identities a first-class security principal — discovered, attested, governed, and enforced.*
>
> *Questions?"*

---

## Pre-Demo Checklist

- [ ] Login to `http://34.120.74.81` with admin@wid.dev / Admin12345
- [ ] Trigger a fresh scan: `POST /api/v1/workloads/scan` (to ensure graph is populated)
- [ ] Verify graph loads with nodes and edges (Graph page)
- [ ] Verify at least one policy exists in Simulate mode (Policies page)
- [ ] Verify Access Events has recent entries (Access Events page)
- [ ] Verify at least one MCP server node in the graph
- [ ] Have a terminal ready for architecture discussion
- [ ] Browser zoom at 100%, dark theme preferred

## Key Stats to Drop Naturally

| Stat | Source |
|------|--------|
| 100:1 machine-to-human identity ratio | CSA 2025 NHI Report |
| 97% of NHIs have excessive privileges | CSA 2025 NHI Report |
| 80% of IT pros have seen agents perform unauthorized actions | ISACA 2026 |
| Only 24.4% have agent-to-agent visibility | ISACA 2026 |
| 13,000+ MCP servers on GitHub | GitHub search |
| 7.2% have exploitable flaws | Invariant Labs research |
| EU AI Act Article 12 mandatory August 2, 2026 | EU legislation |
| Only 12% of orgs confident in NHI attack prevention | CSA/NHI Forum 2026 |

## Competitive Differentiators to Highlight

| What WID Does | What Competitors Do |
|---------------|-------------------|
| Attack path graph with blast radius | Credential inventory (flat list) |
| Simulate -> Audit -> Enforce lifecycle | Binary on/off policies |
| Chain-aware enforcement (anti-confused-deputy) | No delegation chain awareness |
| Deterministic decision replay (EU AI Act) | "We log decisions" (not replayable) |
| MCP integrity scanning (23 patterns) | No MCP awareness |
| Edge enforcement (no mesh required) | Require Istio/Envoy or agent SDK |
| mTLS federation (SPIFFE SVIDs) | Shared API keys |
| Multi-cloud spokes (AWS + Azure + GCP) | Single cloud only |

---

## Video Recording Tips

1. **Resolution**: 1920x1080 minimum, 4K preferred
2. **Browser**: Chrome, hide bookmarks bar, close other tabs
3. **Font size**: Increase browser zoom to 110% for readability
4. **Mouse movements**: Slow and deliberate — viewers need to track your cursor
5. **Pauses**: Leave 1-2 second pauses after key moments (enforcement action, score change)
6. **Audio**: Use a good microphone, quiet room. Record voiceover separately if needed.
7. **Cuts**: For a polished video, record each act separately and edit together. Natural demo flow is better for live presentations.
8. **Annotations**: Add callout boxes for key metrics (risk score, blast radius, latency)
