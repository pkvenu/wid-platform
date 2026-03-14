# WID Platform — Deployment Models

> Version 1.0 | March 2026

WID's hub-and-spoke architecture supports four deployment modes — from fully managed SaaS to fully air-gapped sovereign clusters. Each mode maps to a buyer persona and operational constraint.

---

## Decision Matrix

| Factor | Mode 1: SaaS | Mode 2: Customer-Hosted | Mode 3: Air-Gapped | Mode 4: Edge-Only |
|--------|:---:|:---:|:---:|:---:|
| Control plane location | WID-managed cloud | Customer cloud | Customer premises | None |
| Data residency | WID region | Customer region | On-premises | Local only |
| Network requirement | Internet | Internet or private link | None | None |
| Database | WID-managed Cloud SQL | Customer-managed | Customer-managed | None |
| Scanners available | All (AWS/GCP/Azure/K8s/Docker) | All | K8s/Docker/on-prem only | None |
| Setup complexity | Minutes | Hours | Days | Minutes |
| Ongoing operations | WID manages | Customer manages | Customer manages | Customer manages |
| Ideal for | SaaS-native teams, fast start | Regulated industries, data-sensitive | Defense, classified, sovereign finance | Quick enforcement wins, PoC |

---

## Mode 1: SaaS Control Plane

**Persona**: Cloud-native teams that want visibility and enforcement without managing infrastructure.

### Architecture

```
    ┌─────────────── WID-Managed (GCP) ──────────────────┐
    │                                                      │
    │  Policy Engine · Discovery · Token Service           │
    │  Credential Broker · Web UI · Relay (Hub)           │
    │  Cloud SQL (PostgreSQL 16)                           │
    │  GLB + Cloud Armor                                  │
    │                                                      │
    └────────────────────┬─────────────────────────────────┘
                         │  TLS + API key auth
                         │
          ┌──────────────┼──────────────────┐
          │              │                  │
    ┌─────▼──────┐ ┌─────▼──────┐ ┌─────────▼──────┐
    │ AWS Spoke  │ │ GCP Spoke  │ │ Azure Spoke    │
    │ ECS Fargate│ │ Cloud Run  │ │ Container Apps │
    │ relay + GWs│ │ relay + GWs│ │ relay + GWs    │
    └────────────┘ └────────────┘ └────────────────┘
```

### What the Customer Deploys

Only two components:

1. **Relay (spoke mode)** — pulls policy bundles (15s), pushes audit events (5s), sends heartbeats (60s)
2. **Edge gateways** — one per workload. Transparent HTTP proxy with iptables redirect or explicit proxy config

Terraform modules available:
- **AWS**: `deploy/aws/terraform/spoke/main.tf` — VPC, ECS Fargate cluster, EFS, relay task, gateway task definitions, ALB
- **Azure**: `deploy/azure/terraform/spoke/main.tf` — VNet, Container Apps environment, relay + gateway containers, Application Gateway

### What WID Manages

- PostgreSQL (Cloud SQL with automated backups, point-in-time recovery)
- All control plane services (policy engine, discovery, token service, credential broker, web UI)
- Relay hub (accepts spoke registrations, serves policy bundles, aggregates audit events)
- GLB with URL map routing + Cloud Armor WAF

### Data Flow

```
Customer Workload ──▶ Edge Gateway ──▶ Policy eval (local cache)
        │                                    │
        │                              Decision logged
        │                                    │
        ▼                                    ▼
  Destination                         Audit Buffer
                                            │
                                     batch flush (5s)
                                            │
                                     Relay (Spoke)
                                            │
                                     TLS + API key
                                            │
                                     Relay (Hub) ──▶ Cloud SQL
```

### Security Model

- Customer workload traffic never touches WID infrastructure — edge gateways evaluate locally
- Audit events contain decision metadata (verdict, policy name, trace_id) — not request payloads
- Policy bundles are signed with version hashing — spokes verify before caching
- MCP/AI telemetry: tool argument values are redacted (keys only, never values)

### Operational Details

- **Spoke auto-registration**: First heartbeat registers the spoke with its environment name and gateway count
- **LKG during outages**: If the hub is unreachable, spokes continue enforcing with the last-known-good policy bundle
- **Upgrade path**: WID pushes control plane updates transparently. Spoke images are versioned — customer upgrades on their schedule

---

## Mode 2: Customer-Hosted

**Persona**: Regulated industries (finance, healthcare) requiring data residency or full infrastructure control.

### Architecture

All WID services run in the customer's cloud account. Same architecture as Mode 1, but the customer owns everything.

```
    ┌─────────────── Customer Cloud Account ─────────────┐
    │                                                      │
    │  ┌──── Control Plane ────┐   ┌──── Data Plane ────┐ │
    │  │ Policy Engine         │   │ Relay (Spoke)       │ │
    │  │ Discovery Service     │   │ Edge Gateways       │ │
    │  │ Token Service         │   │ (per workload)      │ │
    │  │ Credential Broker     │   │                     │ │
    │  │ Web UI                │   │                     │ │
    │  │ Relay (Hub)           │   │                     │ │
    │  └──────────┬────────────┘   └─────────────────────┘ │
    │             │                                        │
    │  ┌──────────▼────────────┐                           │
    │  │ Customer-Managed DB   │                           │
    │  │ (Cloud SQL / RDS /    │                           │
    │  │  Azure SQL / self-    │                           │
    │  │  managed PostgreSQL)  │                           │
    │  └───────────────────────┘                           │
    └──────────────────────────────────────────────────────┘
```

### Terraform Modules

**GCP**: `deploy/gcp/terraform/main.tf` creates:
- VPC with private services access
- Cloud SQL PostgreSQL 16 (private IP, automated backups)
- Artifact Registry for container images
- Secret Manager (DB credentials, ES256 keys)
- Cloud Run services for all WID components
- Global HTTPS Load Balancer with URL map routing

**AWS**: `deploy/aws/terraform/main.tf` creates:
- VPC with private subnets
- RDS PostgreSQL with IAM auth
- ECR repositories
- EKS manifests or ECS task definitions
- ALB with path-based routing

### Key Differences from SaaS

| Aspect | SaaS (Mode 1) | Customer-Hosted (Mode 2) |
|--------|---------------|-------------------------|
| DB backups | WID manages | Customer manages |
| Security patches | WID pushes | Customer pulls new images |
| ES256 key generation | WID rotates | Customer generates and stores |
| Scaling | WID auto-scales | Customer configures min/max |
| Monitoring | WID alerts | Customer integrates with their observability stack |

### Why Customers Choose This

- **Data residency**: All data (policies, audit logs, graph, tokens) stays in the customer's cloud account and region
- **Compliance**: Satisfies requirements that prohibit SaaS for security tooling (common in banking, government)
- **Full control**: Customer owns upgrades, scaling, backup, and secret rotation
- **Air-gap adjacent**: Can run fully within a private VPC with no internet egress (cloud scanner APIs accessed via VPC endpoints)

---

## Mode 3: Air-Gapped Sovereign Cluster

**Persona**: Defense contractors, classified networks, sovereign finance, critical infrastructure.

### Architecture

```
    ┌──────────── Customer Premises (No Internet) ────────┐
    │                                                       │
    │  ┌──── Control Plane (K8s / Docker Compose) ──────┐  │
    │  │ Policy Engine · Discovery · Token Service       │  │
    │  │ Credential Broker · Web UI · Relay (Hub)       │  │
    │  └──────────────────┬─────────────────────────────┘  │
    │                     │                                 │
    │  ┌──────────────────▼──────────────┐                  │
    │  │ Self-Managed PostgreSQL         │                  │
    │  │ (HA pair or Patroni cluster)    │                  │
    │  └─────────────────────────────────┘                  │
    │                                                       │
    │  ┌──── Data Plane ─────────────────────────┐         │
    │  │ Relay (Spoke, same network)              │         │
    │  │ Edge Gateways (per workload)              │         │
    │  └──────────────────────────────────────────┘         │
    │                                                       │
    │  ┌──── Identity ───────────────────────────┐         │
    │  │ SPIRE Server (on-prem)                   │         │
    │  │ HashiCorp Vault (on-prem)                │         │
    │  │ Customer PKI (self-signed CA)             │         │
    │  └──────────────────────────────────────────┘         │
    └───────────────────────────────────────────────────────┘
```

### Key Differences from Customer-Hosted

| Aspect | Customer-Hosted (Mode 2) | Air-Gapped (Mode 3) |
|--------|-------------------------|---------------------|
| Container images | Pulled from cloud registry | Loaded from offline registry (Harbor, Artifactory) |
| Policy bundle distribution | Pull over network (15s) | Can use sneakernet or one-way data diode |
| Cloud scanners | AWS/GCP/Azure APIs available | Not available — K8s, Docker, on-prem scanners only |
| Certificate management | Cloud-managed (ACM, Cloud Cert) | Customer PKI or self-signed CA |
| SPIRE deployment | Optional (cloud attestation available) | Recommended (primary attestation method) |
| Secret management | Cloud Secret Manager | On-prem HashiCorp Vault |
| Updates | Pull new images from registry | Explicit image transfer + upgrade procedure |

### Deployment Targets

- **Kubernetes**: RKE2, K3s, or standard K8s. All services deployed as Deployments + Services. PostgreSQL as StatefulSet or external.
- **Docker Compose**: `docker-compose.fullstack.yml` for bare metal or VMs. All services + PostgreSQL + Vault.
- **Systemd**: Edge gateways can run as systemd services on bare metal VMs with iptables redirect.

### Operational Procedures

**Policy bundle distribution (offline):**
1. Author policies on an internet-connected workstation
2. Export signed policy bundle (`POST /api/v1/policies/export`)
3. Transfer via approved media (USB, data diode, SFTP gateway)
4. Import into air-gapped control plane (`POST /api/v1/policies/import`)
5. Bundles propagate to relay and gateways on next sync cycle

**Container image transfer:**
1. Pull images from WID's public registry on a connected machine
2. `docker save` all images to a tar archive
3. Transfer to air-gapped environment
4. `docker load` into offline registry (Harbor/Artifactory)
5. Update image references in Kubernetes manifests or Compose file

**Upgrade path:**
1. WID publishes release notes + migration guide per version
2. Customer pulls new images and migration SQL on connected machine
3. Transfer to air-gapped environment
4. Apply database migration: `psql -f migration.sql`
5. Rolling update: update images one service at a time
6. Verify health checks pass before proceeding to next service

### Available Scanners

| Scanner | Available | Notes |
|---------|:---------:|-------|
| GCP Cloud Run, IAM, SA | No | Requires internet access to GCP APIs |
| AWS IAM, EC2, Lambda, S3 | No | Requires internet access to AWS APIs |
| Azure RBAC, MSI | No | Requires internet access to Azure APIs |
| Kubernetes | Yes | Scans K8s API server on local network |
| Docker | Yes | Scans Docker daemon socket |
| On-prem | Yes | SPIFFE IDs, container verification, network scanning |
| A2A Agent Card | Yes | Probes `/.well-known/agent.json` on local network |
| MCP Server | Yes | Probes MCP endpoints on local network |

---

## Mode 4: Edge Gateway Enforcement (Standalone)

**Persona**: Teams wanting quick enforcement wins without deploying a full platform. Also the "land-and-expand" entry point.

### Architecture

```
    ┌──────────────────────────────────┐
    │  Workload Pod / VM               │
    │                                   │
    │  ┌──────────┐  ┌──────────────┐  │
    │  │  Your    │  │  WID Edge    │  │
    │  │  App     │──│  Gateway     │  │
    │  │          │  │              │  │
    │  └──────────┘  └──────┬───────┘  │
    │                       │          │
    │               iptables REDIRECT  │
    └──────────────────────────────────┘
                            │
                    Policy evaluation
                    (local rules)
                            │
                    Audit log (local file
                    or stdout)
```

### Setup (Minutes, Not Days)

**Kubernetes sidecar:**
```yaml
# Add to your pod spec (see deploy/k8s/sidecar-example.yaml)
containers:
  - name: wid-gateway
    image: ghcr.io/wid/edge-gateway:latest
    env:
      - name: DEFAULT_MODE
        value: "audit"           # Start observing, don't block
      - name: FAIL_BEHAVIOR
        value: "open"            # If gateway crashes, traffic flows
      - name: WORKLOAD_NAME
        value: "my-billing-agent"
    ports:
      - containerPort: 15001     # Outbound proxy
      - containerPort: 15000     # Admin/metrics
```

**Docker:**
```bash
docker run -d --name wid-gateway \
  --network container:my-app \
  -e DEFAULT_MODE=audit \
  -e FAIL_BEHAVIOR=open \
  -e WORKLOAD_NAME=my-billing-agent \
  ghcr.io/wid/edge-gateway:latest
```

**VM (systemd):**
```bash
# Install binary + iptables redirect
curl -L https://releases.wid.dev/gateway/latest | sudo install -m 755 /dev/stdin /usr/local/bin/wid-gateway
sudo /usr/local/bin/wid-gateway install-iptables --target-port 8080
sudo systemctl enable --now wid-gateway
```

### Minimal Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `DEFAULT_MODE` | `audit` | `audit` (log only) or `enforce` (block) |
| `FAIL_BEHAVIOR` | `open` | `open` (traffic flows on failure) or `closed` (traffic blocked) |
| `WORKLOAD_NAME` | hostname | Name for audit logs |
| `POLICY_SERVICE_URL` | none | Optional: connect to relay for centralized policy |
| `METRICS_PORT` | 15000 | Prometheus metrics endpoint |

### What You Get

- Real-time audit log of all outbound HTTP calls (destination, status, latency)
- AI traffic detection (OpenAI, Anthropic, Google AI, Cohere, HuggingFace)
- MCP tool call interception and telemetry
- Prometheus metrics at `/metrics` (decisions, latency percentiles, circuit breaker state)
- Optional enforcement: block specific destinations or protocols

### What You Don't Get

- No centralized graph or discovery (requires control plane)
- No compliance dashboard (requires control plane + DB)
- No multi-workload policy management (each gateway is independent)
- No attestation or token issuance (requires token service)

### Upgrade Path: Land-and-Expand

```
Mode 4 (Edge-Only)
    │
    │ Add RELAY_URL env var
    │ to edge gateway
    │
    ▼
Mode 1 (SaaS) or Mode 2 (Self-Hosted)
    │
    │ Gateway now receives policies
    │ from central. Audit events flow
    │ upstream. Graph shows workload.
    │
    ▼
Full Platform
    │ All enforcement, discovery,
    │ compliance, and graph features
    │ unlocked.
```

---

## Service Topology Matrix

Which services run where for each mode:

| Service | Mode 1: SaaS | Mode 2: Self-Hosted | Mode 3: Air-Gap | Mode 4: Edge Only |
|---------|:---:|:---:|:---:|:---:|
| Web UI | WID cloud | Customer cloud | Customer on-prem | - |
| Policy Engine | WID cloud | Customer cloud | Customer on-prem | - |
| Discovery Service | WID cloud | Customer cloud | Customer on-prem | - |
| Token Service | WID cloud | Customer cloud | Customer on-prem | - |
| Credential Broker | WID cloud | Customer cloud | Customer on-prem | - |
| Relay (Hub) | WID cloud | Customer cloud | Customer on-prem | - |
| Relay (Spoke) | Customer env | Customer env | Same cluster | - |
| Edge Gateway | Customer env | Customer env | Customer on-prem | Customer env |
| PostgreSQL | Cloud SQL (WID) | Cloud SQL/RDS (customer) | Self-managed | - |
| Vault | WID-managed | Customer-managed | On-prem Vault | - |
| SPIRE | Optional | Optional | Recommended | - |

---

## Rollout Strategy (Any Mode)

All four modes follow the same progressive rollout:

| Phase | Mode | Failure Behavior | Scope |
|-------|------|-----------------|-------|
| **1. Observe** | `audit` | `fail-open` | All workloads. Log every decision, block nothing. |
| **2. Selective enforcement** | `enforce` | `fail-open` | High-risk workloads only (e.g., agents with external API access). |
| **3. Broad enforcement** | `enforce` | `fail-open` | All workloads. Still fail-open for safety. |
| **4. Full enforcement** | `enforce` | `fail-closed` | Critical paths. No traffic flows without a positive policy decision. |

Each phase transition is a configuration change — no code deployment required. Promote per-workload or per-environment.

---

## Monitoring and Observability

All data plane components expose Prometheus metrics at `/metrics`:

### Key Metrics

| Metric | Type | What It Tells You |
|--------|------|-------------------|
| `wid_decisions_total{verdict,mode}` | Counter | Total decisions by allow/deny and simulate/audit/enforce |
| `wid_decision_latency_ms` | Histogram | Policy evaluation latency (p50, p95, p99) |
| `wid_circuit_breaker_state` | Gauge | 0=closed (healthy), 1=half-open, 2=open (failing) |
| `wid_policy_cache_hit_ratio` | Gauge | Cache effectiveness (target: >95%) |
| `wid_audit_buffer_size` | Gauge | Pending audit events (alert if growing) |
| `wid_relay_last_sync_age_s` | Gauge | Seconds since last successful policy sync |
| `wid_ai_requests_total{provider}` | Counter | AI API calls by provider (OpenAI, Anthropic, etc.) |

### Integration

- **Grafana**: Import WID dashboard (JSON template provided)
- **CloudWatch**: Cloud Run metrics + custom metrics via OpenTelemetry
- **Datadog**: StatsD exporter mode available
- **Alerting**: Alert on `circuit_breaker_state > 0`, `relay_last_sync_age_s > 60`, `audit_buffer_size > 1000`

---

## Related Documentation

- [architecture.md](architecture.md) — System architecture overview
- [DEPLOYMENT.md](DEPLOYMENT.md) — Step-by-step deployment guide (local, GCP, AWS)
- [threat-model.md](threat-model.md) — Security implications per deployment mode
- [attack-path-demo.md](attack-path-demo.md) — End-to-end demo walkthrough
- [shared/ARCHITECTURE.md](../shared/ARCHITECTURE.md) — Dual-mode data plane (edge gateway vs ext-authz)
- [SECURITY.md](SECURITY.md) — Production hardening checklist
