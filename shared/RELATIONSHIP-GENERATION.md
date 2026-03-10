# Identity Graph Relationships — How WID Builds the Graph

## Overview

The WID identity graph is a multi-layer dependency graph that maps workloads, identities, credentials, attack paths, and external APIs. It answers the question: **"If this identity is compromised, what can the attacker reach?"**

The graph is generated through a three-phase pipeline:

1. **Relationship Scanner** — discovers workload-to-identity-to-resource relationships from cloud provider APIs
2. **Protocol Scanner** — detects AI agents, MCP servers, and external API credentials via static analysis and active probing
3. **Graph Enrichment** — computes attack paths, scores remediation controls, and ranks playbook actions

---

## Phase 1: Relationship Scanner

The relationship scanner builds the foundational graph by discovering IAM bindings, role assignments, shared identities, and resource grants.

### Node Types

Every entity in the graph is a typed node:

| Group | Node Types |
|-------|-----------|
| **Workload** | cloud-run-service, ec2, lambda, ecs-task, container, vm, kubernetes-pod |
| **Identity** | service-account, iam-role, iam-user, managed-identity, k8s-service-account |
| **Data** | data-store, cloud-sql, s3-bucket, gcs-bucket, secret-manager, key-vault |
| **Network** | security-group, firewall-rule, external-account |
| **Credential** | api-key, secret, token, static-credential |
| **External** | external-api (OpenAI, Stripe, GitHub, Salesforce, etc.) |

### Edge Types

Relationships between nodes have semantic types:

| Edge Type | Meaning | Example |
|-----------|---------|---------|
| `runs-as` | Workload uses this identity | Cloud Run → Service Account |
| `has-role` | Identity has this IAM role | SA → roles/editor |
| `grants-access` | Role provides access to resource | roles/editor → Cloud SQL |
| `shares-identity` | Multiple workloads use same SA | WorkloadA ↔ WorkloadB |
| `exposed-via` | Public internet exposure | Workload → public-internet |
| `can-escalate-to` | Privilege escalation path | Role → higher-privilege role |
| `uses-credential` | Workload uses static credential | Agent → OPENAI_API_KEY |
| `calls-api` | Workload calls external API | Agent → OpenAI API |
| `protected-by` | Protected by network control | EC2 → Security Group |
| `trusts` | Cross-account trust | External Account → IAM Role |

### Discovery Pipeline

The scanner runs a strict 5-phase pipeline per cloud provider:

**Phase 1 — Workload Nodes**: Create one node per discovered workload with metadata (SA, trust level, region, owner, AI/MCP flags).

**Phase 2 — Provider-Specific Relationships**:
- **GCP**: Fetches IAM project bindings via Cloud Resource Manager API. Links service accounts → IAM roles → resources. Maps GCP roles (roles/editor, roles/cloudsql.admin) to their accessible resource types.
- **AWS**: Enumerates attached policies on IAM roles via the IAM SDK. Links Lambda/ECS execution roles → policies → data stores. Detects cross-account trust chains and privilege escalation paths.
- **Azure**: Lists role assignments via Authorization Management Client. Links managed identities → Azure roles (Owner, Contributor). Detects public storage and SQL exposure.
- **On-Prem/K8s**: Maps container → host relationships, K8s service account bindings, port-based exposure, SPIFFE identity linking, and shared Docker/K8s network meshes.

**Phase 3 — Cross-Cutting Relationships**:
- **Shared Identities**: Detects multiple workloads running as the same service account → creates `shares-identity` edges (critical finding: blast radius multiplier)
- **Network Exposure**: Identifies workloads with public IPs, `INGRESS_TRAFFIC_ALL`, or 0.0.0.0 port bindings → creates `exposed-via` edges to a `public-internet` node
- **Credential Nodes**: Creates nodes for user-managed keys, API keys, and secrets discovered in metadata
- **AI Service Relationships**: Links workloads to cloud AI endpoints (Vertex AI, SageMaker, Bedrock, Azure OpenAI)

**Phase 3.5 — Protocol Scanner Integration** (see Phase 2 below)

**Phase 4 — Attack Path Computation** (see Attack Paths section below)

---

## Phase 2: Protocol Scanner

The protocol scanner enriches workloads with AI/ML and external API intelligence using static analysis and optional active probing.

### External API Credential Detection (Two-Pass)

**Pass 1 — Environment Variable Patterns**:
Matches environment variable names against 25+ external API patterns:
- `OPENAI_API_KEY` → OpenAI (critical risk, financial scope)
- `STRIPE_SECRET_KEY` → Stripe (critical risk, financial scope)
- `GITHUB_TOKEN` → GitHub (high risk, code access scope)
- `SALESFORCE_TOKEN` → Salesforce (high risk, CRM data scope)
- `ANTHROPIC_API_KEY` → Anthropic (high risk, AI scope)
- And 20+ more (Slack, Datadog, SendGrid, Twilio, AWS, Azure, etc.)

For each match, the scanner classifies:
- **Credential type**: secret-key > token > oauth-client > api-key
- **Risk level**: critical (financial APIs, admin keys), high (data access), medium (monitoring)
- **Scope**: read, write, admin, financial, code
- **Is static**: Whether the credential is a hardcoded environment variable vs. managed secret

**Important**: The scanner never downgrades risk. If `SALESFORCE_TOKEN` (high risk) is matched before `SF_CLIENT_ID` (medium risk), the high-risk classification is preserved.

**Pass 2 — Structured Metadata**:
Processes `workload.metadata.credentials[]` from cloud scanners. This is critical for GCP Cloud Run where environment variable values are redacted as `[secret]` — only the key names and storage method are visible. Credentials stored via Secret Manager are marked as NOT static (managed secrets).

### AI Agent Enrichment

For workloads detected as AI agents, the scanner builds a comprehensive profile:
- **LLM providers**: Which AI APIs are called (OpenAI, Anthropic, etc.)
- **Models**: Which specific models are used (gpt-4o, claude-3, etc.)
- **Embeddings & vectors**: Vector stores (Pinecone, Weaviate, Chroma)
- **Frameworks**: LangChain, LlamaIndex, CrewAI, AutoGen
- **Risk flags**: multi-provider, high-credential-count, RAG pipeline, uses-fine-tuned-model

### Finding Generation

The protocol scanner generates typed findings for risk patterns:

| Finding Type | Severity | Trigger |
|---|---|---|
| `static-external-credential` | critical/high | Static API key for external service |
| `toxic-combo` | critical | Single workload holds both Stripe + Salesforce creds |
| `a2a-no-auth` | high | A2A Agent Card has no authentication |
| `a2a-unsigned-card` | medium | Agent Card not signed with JWS |
| `mcp-static-credentials` | high | MCP server uses static env var credentials |
| `mcp-dangerous-tool` | critical | MCP has dangerous tools (shell, exec, delete) |
| `mcp-unauthenticated` | high | MCP endpoint has no authentication |

---

## Attack Path Computation

The relationship scanner uses **breadth-first search (BFS)** to discover risky chains through the graph. For each attack path type, it identifies an entry point and traces all reachable nodes.

### Attack Path Types

| Finding Type | Severity | Entry Point | Blast Radius |
|---|---|---|---|
| `shared-sa` | critical (if public) | Public workloads sharing SA | # identities holding the SA |
| `key-leak` | high/critical | Credential node | # resources reachable via key |
| `public-internal-pivot` | critical | Public-facing nodes | # internal services reachable |
| `over-privileged` | high | High-risk roles | # sensitive resources accessible |
| `privilege-escalation` | critical | Escalation-capable nodes | # nodes reachable via escalation chain |
| `cross-account-trust` | critical/high | External account nodes | # resources reachable via trust |
| `unbounded-admin` | high | Admin identity nodes | # resources reachable from admin |
| `public-data-exposure` | critical | Public data stores | 1 (the data store itself) |
| `internet-to-data` | critical | Public internet node | # data stores reachable from internet |

### Blast Radius Calculation

For each attack path, BFS traverses the adjacency list to count all reachable nodes. This gives the **blast radius** — the number of downstream workloads, identities, and resources that could be compromised if the entry point is breached.

The adjacency list is bidirectional for identity nodes (if workload A `runs-as` SA X, and workload B also `runs-as` SA X, then compromising SA X can pivot to both workloads).

---

## Phase 3: Graph Enrichment

When the graph is served via `GET /api/v1/graph`, the response is enriched with:

### Policy Status
Each attack path is checked against deployed policies. If a policy with `enforcement_mode='enforce'` covers the finding, the path is marked with remediation status:
- `enforced`: Policy active and blocking
- `audit`: Policy logging but not blocking
- `unmitigated`: No policy covers this path

### Ranked Controls
Each attack path gets ranked remediation controls from the `CONTROL_CATALOG`. Controls are scored on four dimensions:
- **Path Break Strength** (40%): How many edges are severed, proximity to crown jewels
- **Blast Radius Impact** (20%, inverse): Fewer affected workloads = higher score
- **Operational Cost** (20%, inverse): Lower implementation effort = higher score
- **Confidence** (20%): Evidence completeness and false positive risk

### Credential Chains
The graph traces which credentials enable which attack paths, creating a chain from workload → credential → external API that the user can inspect in the Playbook tab.

---

## Data Flow

```
Cloud Scanners (GCP/AWS/Azure/Docker/K8s)
  ↓ Workloads with metadata, labels, IAM bindings
RelationshipScanner.discover()
  ├─ Create workload nodes
  ├─ Discover IAM → role → resource relationships
  ├─ Detect shared identities + network exposure
  ├─ ProtocolScanner.scan()
  │   ├─ Detect A2A agents + MCP servers (static scoring)
  │   ├─ Two-pass credential detection (env vars + metadata)
  │   └─ AI agent enrichment (LLM providers, models, frameworks)
  └─ computeAttackPaths() via BFS
      └─ 11 attack path types with blast radius
  ↓
GET /api/v1/graph
  ├─ Attach deployed policy status (audit/enforce/unmitigated)
  ├─ Score + rank remediation controls
  └─ Build credential chains
  ↓
Frontend D3 Visualization
  ├─ Nodes colored by type + risk
  ├─ Edges labeled by relationship type
  ├─ Attack paths highlighted on selection
  └─ Inspector panel: Threat Brief, Playbook, Evidence
```
