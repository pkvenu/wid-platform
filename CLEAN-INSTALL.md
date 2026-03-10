# Workload Identity Platform — Clean Install Guide

## Hybrid Deployment: AWS Control Plane + Local Docker Workloads

This guide walks through deploying the Workload Identity Platform from scratch in a hybrid configuration:

- **Central Control Plane** runs in AWS (EKS or ECS)
- **Local Workloads** run in Docker on your machine, on-prem VMs, or any cloud
- **No service mesh required** — the Edge Gateway sidecar handles identity injection without Istio

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Phase 1: AWS Control Plane](#3-phase-1-aws-control-plane)
4. [Phase 2: Local Docker Environment](#4-phase-2-local-docker-environment)
5. [Phase 3: Connect Local to AWS](#5-phase-3-connect-local-to-aws)
6. [Phase 4: Deploy Sample Workloads](#6-phase-4-deploy-sample-workloads)
7. [Phase 5: Verify End-to-End](#7-phase-5-verify-end-to-end)
8. [Phase 6: Rollout Strategy](#8-phase-6-rollout-strategy)
9. [Adding More Environments](#9-adding-more-environments)
10. [FAQ: Service Mesh vs Edge Gateway](#10-faq-service-mesh-vs-edge-gateway)

---

## 1. Architecture Overview

```
┌─────────────────── AWS (Central Control Plane) ──────────────────┐
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐   │
│  │ Policy   │  │ Token    │  │ Cred     │  │ Discovery      │   │
│  │ Engine   │  │ Service  │  │ Broker   │  │ Service        │   │
│  │ :3001    │  │ :3000    │  │ :3002    │  │ :3003          │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬───────────┘   │
│       └──────────────┴──────────────┴──────────────┘              │
│                          │                                        │
│                   ┌──────▼──────┐     ┌───────────┐              │
│                   │ PostgreSQL  │     │ WID Relay  │              │
│                   │ (RDS)       │     │ (central)  │              │
│                   └─────────────┘     │ :3005      │              │
│                                       └──────┬─────┘              │
│                                              │                    │
│                ┌─────────────────────────────┐│                   │
│                │        Web UI (:3100)        ││                   │
│                │  Unified dashboard across    ││                   │
│                │  ALL environments            ││                   │
│                └─────────────────────────────┘│                   │
└───────────────────────────────┬───────────────┘
                                │
            Policy sync (pull)  │  Audit events (push)
            30s intervals       │  10s batch flush
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│              Local Docker (or On-Prem / GCP / Azure)             │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                      WID Relay (local)                       │ │
│  │                      :3005                                   │ │
│  │  • Caches policies from central                              │ │
│  │  • Buffers audit events, flushes to central                  │ │
│  │  • Serves local adapters/gateways                            │ │
│  └──────────────────────┬───────────────────────────────────────┘ │
│                         │                                         │
│  ┌──────────────────────▼───────────────────────────────────────┐ │
│  │  Your Application Pods / Containers                          │ │
│  │                                                               │ │
│  │  ┌──────────┐  ┌───────────┐     ┌──────────┐  ┌──────────┐│ │
│  │  │ App A    │  │ Edge      │     │ App B    │  │ Edge     ││ │
│  │  │          ├──┤ Gateway   │     │          ├──┤ Gateway  ││ │
│  │  │          │  │ (sidecar) │     │          │  │(sidecar) ││ │
│  │  └──────────┘  └───────────┘     └──────────┘  └──────────┘│ │
│  │                                                               │ │
│  │  No service mesh required!                                    │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### Why No Service Mesh?

Most enterprises don't have Istio or Envoy deployed. Requiring a service mesh adds massive complexity:

| Factor | Service Mesh (Istio) | Edge Gateway (WID) |
|--------|---------------------|--------------------|
| Install complexity | Helm charts, CRDs, istiod, CNI | Single container sidecar |
| Sidecar overhead | Envoy proxy (50-100MB per pod) | Edge Gateway (30MB per pod) |
| Network changes | mTLS everywhere, iptables rewrite | Transparent HTTP proxy |
| Time to deploy | Days to weeks | Minutes |
| Operational burden | Dedicated team | Self-contained |
| Customer prerequisite | Must adopt Istio first | None |

**The Edge Gateway is the default path.** If a customer already has Istio, they can use the ext-authz adapter as an optional optimization.

---

## 2. Prerequisites

### For AWS Control Plane
- AWS account with admin access
- AWS CLI v2 configured (`aws configure`)
- Terraform 1.5+
- kubectl (if using EKS)
- Docker installed

### For Local Docker Environment
- Docker Desktop (Mac/Windows) or Docker Engine (Linux)
- Docker Compose v2
- Node.js 18+ (for web UI development)
- curl and jq (for testing)

### Clone the Repository
```bash
git clone <your-repo-url> wip
cd wip
```

---

## 3. Phase 1: AWS Control Plane

### Option A: Simplified — Docker Compose on EC2 (Quickest)

For getting started fast, run the control plane as Docker containers on a single EC2 instance. This avoids the complexity of EKS, RDS, and Terraform.

#### 3A.1 Launch an EC2 Instance
```bash
# Launch Ubuntu 22.04 t3.medium with 30GB disk
# Security group: open ports 3001, 3005, 3100, 5432 to your IP
# SSH in:
ssh -i your-key.pem ubuntu@<EC2_PUBLIC_IP>
```

#### 3A.2 Install Docker
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker ubuntu
# Log out and back in
```

#### 3A.3 Clone and Start Control Plane
```bash
git clone <your-repo-url> wip && cd wip

# Start ONLY the control plane services (no demo apps or envoy)
docker compose -f services/ext-authz-adapter/deploy/local/docker-compose.yml \
  up -d postgres vault policy-engine token-service credential-broker \
       discovery-service relay web
```

#### 3A.4 Verify
```bash
curl http://localhost:3001/health    # Policy engine
curl http://localhost:3005/health    # Relay (central)
curl http://localhost:3100           # Web UI
```

Note your EC2 public IP — local environments will connect to it:
```bash
export CENTRAL_URL="http://<EC2_PUBLIC_IP>:3005"
echo "Central control plane: ${CENTRAL_URL}"
```

---

### Option B: Production — EKS + RDS (Full Enterprise)

Follow the [AWS/EKS Deployment Guide](aws-deployment-guide.docx) for the full Terraform + EKS path with:
- RDS PostgreSQL (Multi-AZ, encrypted, IAM auth)
- IRSA roles (no static credentials)
- ECR container registry
- HPA, PDB, NetworkPolicy

After completing that guide, your central URL will be:
```bash
export CENTRAL_URL="http://relay.wid-system.svc.cluster.local:3005"
# Or if exposing externally via ALB:
export CENTRAL_URL="https://wid-central.yourcompany.com"
```

---

## 4. Phase 2: Local Docker Environment

This sets up the data-plane components that run alongside your workloads.

### 4.1 Create Local docker-compose.yml

Create `docker-compose.local.yml` in your project root:

```yaml
version: "3.8"

services:
  # ─── WID Relay (connects to AWS central) ───
  relay:
    build: services/relay-service
    ports:
      - "3005:3005"
    environment:
      PORT: 3005
      ENVIRONMENT_NAME: local-dev
      ENVIRONMENT_TYPE: docker
      REGION: local
      CLUSTER_ID: docker-desktop
      CENTRAL_CONTROL_PLANE_URL: "${CENTRAL_URL}"
      CENTRAL_API_KEY: "${CENTRAL_API_KEY:-}"
      POLICY_SYNC_INTERVAL_MS: "15000"
      AUDIT_FLUSH_INTERVAL_MS: "5000"

  # ─── Sample App: Frontend ───
  sample-frontend:
    image: nginx:alpine
    # App listens on 80, gateway intercepts on 15001
    depends_on:
      - frontend-gateway

  # ─── Edge Gateway sidecar for frontend ───
  frontend-gateway:
    build: services/edge-gateway
    ports:
      - "8080:15001"     # Exposed port for testing
    environment:
      OUTBOUND_PORT: 15001
      INBOUND_PORT: 15006
      ADMIN_PORT: 15000
      APP_PORT: 80
      APP_HOST: sample-frontend
      WORKLOAD_NAME: sample-frontend
      NAMESPACE: local
      TRUST_DOMAIN: company.com
      DEFAULT_MODE: audit
      FAIL_BEHAVIOR: open
      POLICY_SERVICE_URL: http://relay:3005
      TOKEN_SERVICE_URL: http://relay:3005
    depends_on:
      - relay

  # ─── Sample App: Backend API ───
  sample-backend:
    image: hashicorp/http-echo
    command: ["-text=Hello from backend!", "-listen=:8080"]

  # ─── Edge Gateway sidecar for backend ───
  backend-gateway:
    build: services/edge-gateway
    ports:
      - "8081:15001"
    environment:
      OUTBOUND_PORT: 15001
      INBOUND_PORT: 15006
      ADMIN_PORT: 15000
      APP_PORT: 8080
      APP_HOST: sample-backend
      WORKLOAD_NAME: sample-backend
      NAMESPACE: local
      TRUST_DOMAIN: company.com
      DEFAULT_MODE: audit
      FAIL_BEHAVIOR: open
      POLICY_SERVICE_URL: http://relay:3005
      TOKEN_SERVICE_URL: http://relay:3005
    depends_on:
      - relay
```

### 4.2 Set Central URL and Start

```bash
# Point to your AWS control plane
export CENTRAL_URL="http://<EC2_PUBLIC_IP>:3005"

# Start local environment
docker compose -f docker-compose.local.yml up --build
```

### 4.3 Verify Local Components

```bash
# Relay health
curl http://localhost:3005/health | jq .

# Expected:
# {
#   "service": "wid-relay",
#   "environment": "local-dev",
#   "central_reachable": true,     ← Connected to AWS!
#   "registered": true,
#   "policy_version": 1,
#   ...
# }

# Gateway health
curl http://localhost:8080/healthz | jq .  # frontend gateway
curl http://localhost:8081/healthz | jq .  # backend gateway
```

---

## 5. Phase 3: Connect Local to AWS

### 5.1 Verify Registration

On your AWS control plane, check that the local relay registered:

```bash
# From AWS (or via port-forward)
curl http://<EC2_PUBLIC_IP>:3005/api/v1/relay/environments | jq .

# Expected:
# {
#   "total": 2,
#   "environments": [
#     { "environment_name": "local-docker", "is_central": true },
#     { "environment_name": "local-dev", "status": "active" }
#   ]
# }
```

### 5.2 Verify Policy Sync

```bash
# Check local relay has policies from central
curl http://localhost:3005/api/v1/relay/policies | jq '.version, .policies | length'

# Force a sync
curl -X POST http://localhost:3005/api/v1/relay/sync | jq .
```

### 5.3 Open the Web UI

Open `http://<EC2_PUBLIC_IP>:3100` in your browser. You should see:

- **Workloads page**: Shows NHIs from ALL environments
- **Authorization page**: Live decisions from both AWS and local
- **Environments**: Connected relays with health status

---

## 6. Phase 4: Deploy Sample Workloads

### 6.1 Create a Policy in the Web UI

1. Go to **Policies** → **New Policy** → **Templates**
2. Deploy "Production Service Access" template
3. Or create a custom access policy:

```bash
curl -X POST http://<EC2_PUBLIC_IP>:3001/api/v1/policies -H 'Content-Type: application/json' -d '{
  "name": "Allow Frontend to Backend",
  "policy_type": "access",
  "effect": "allow",
  "conditions": [
    { "field": "source.name", "operator": "equals", "value": "sample-frontend" },
    { "field": "destination.name", "operator": "equals", "value": "sample-backend" }
  ],
  "actions": [{ "type": "allow", "credential": { "type": "ephemeral", "ttl": 300 } }],
  "enabled": true,
  "enforcement_mode": "audit",
  "severity": "medium"
}'
```

### 6.2 Generate Traffic

```bash
# Through frontend gateway → backend
curl http://localhost:8080/
# Through backend gateway directly
curl http://localhost:8081/
```

### 6.3 Check Decisions

```bash
# Local relay metrics
curl http://localhost:3005/metrics | jq .

# Check decisions appeared on AWS
curl http://<EC2_PUBLIC_IP>:3001/api/v1/access/decisions/live | jq '.total, .decisions[0]'
```

---

## 7. Phase 5: Verify End-to-End

Run through this checklist:

### Discovery
- [ ] AWS discovery service found Docker containers
- [ ] Workloads page shows NHIs from both environments
- [ ] `curl <CENTRAL>/api/v1/relay/environments` shows 2 environments

### Policy Sync
- [ ] Policy created on AWS appears in local relay cache
- [ ] `curl localhost:3005/api/v1/relay/policies` shows the policy
- [ ] Policy version matches between central and local

### Authorization Decisions
- [ ] Traffic through local gateways generates decisions
- [ ] Decisions appear in the central Web UI Authorization page
- [ ] Shadow verdicts visible (audit mode = no traffic blocked)

### Audit Trail
- [ ] Local relay audit buffer flushes to central
- [ ] `curl <CENTRAL>/api/v1/access/decisions/live` shows local decisions
- [ ] Decisions include `source_environment: "local-dev"`

---

## 8. Phase 6: Rollout Strategy

### 8.1 Start in Audit Mode (Default)

Everything is already in audit mode. All traffic flows normally. The gateway adds `x-wid-shadow-verdict` headers showing what WOULD happen.

```bash
# Verify
curl http://localhost:8080/ -v 2>&1 | grep x-wid
# x-wid-shadow-verdict: deny   (or allow if policy matches)
# x-wid-decision-id: dec-xxx
```

### 8.2 Review for 1-2 Weeks

Use the Web UI Authorization page to understand traffic patterns:
- Which workloads talk to which?
- What would be denied?
- Are there unexpected communication paths?

### 8.3 Enforce Per-Workload

Switch specific workloads to enforce mode:

```bash
# On the local gateway, switch to enforce
docker compose -f docker-compose.local.yml exec frontend-gateway \
  wget -qO- --post-data='{"mode":"enforce"}' \
  --header='Content-Type: application/json' \
  http://localhost:15000/mode
```

### 8.4 Enforce Globally

Update the environment variable and restart:

```bash
# In docker-compose.local.yml, change:
# DEFAULT_MODE: enforce

docker compose -f docker-compose.local.yml up -d
```

---

## 9. Adding More Environments

The hub-and-spoke model scales by adding relays. Each new environment is the same pattern:

### Add an On-Prem Server

```bash
# On the on-prem server
docker run -d \
  -e ENVIRONMENT_NAME=onprem-dc1 \
  -e ENVIRONMENT_TYPE=vm \
  -e REGION=us-east-datacenter \
  -e CENTRAL_CONTROL_PLANE_URL=http://<AWS_IP>:3005 \
  -p 3005:3005 \
  wid/relay-service
```

### Add a GCP Environment

```bash
# On GKE or GCE
docker run -d \
  -e ENVIRONMENT_NAME=gcp-production \
  -e ENVIRONMENT_TYPE=gke \
  -e REGION=us-central1 \
  -e CENTRAL_CONTROL_PLANE_URL=http://<AWS_IP>:3005 \
  -p 3005:3005 \
  wid/relay-service
```

### Customer with Existing Istio

For customers who already have Istio, they can optionally use the ext-authz adapter:

```bash
# Deploy ext-authz adapter pointing at the relay
helm install wid-adapter ./charts/ext-authz-adapter \
  --set policyServiceUrl=http://relay.wid-system:3005 \
  --set tokenServiceUrl=http://relay.wid-system:3005
```

The relay handles both Edge Gateway and ext-authz adapter connections identically.

---

## 10. FAQ: Service Mesh vs Edge Gateway

### Q: Do customers need Istio?
**No.** The Edge Gateway is the default deployment model. It works everywhere — Docker, VMs, Kubernetes (with or without mesh), ECS, Lambda (via layer). Istio integration is an optional path for customers who already have it.

### Q: What's the difference in capability?

| Capability | Edge Gateway | ext-authz (Istio) |
|-----------|-------------|-------------------|
| Policy enforcement | ✅ | ✅ |
| Token exchange (OBO) | ✅ | ✅ |
| Credential brokering | ✅ | ✅ |
| Shadow verdicts | ✅ | ✅ |
| Audit logging | ✅ | ✅ |
| Transparent (no app changes) | ✅ | ✅ |
| mTLS between services | ❌ (use with mesh) | ✅ (Istio provides) |
| Traffic management | Basic | Full (Istio) |

### Q: Can both coexist?
**Yes.** In the same cluster, some namespaces can use Istio + ext-authz while others use Edge Gateway sidecars. Both talk to the same relay, and all decisions appear in the same Web UI.

### Q: What about AWS App Mesh or Linkerd?
The ext-authz adapter works with any Envoy-based mesh. For non-Envoy meshes (like Linkerd), use the Edge Gateway.

---

## Quick Reference

```bash
# ─── AWS Control Plane ───
# Start:   docker compose up -d postgres vault policy-engine token-service
#          credential-broker discovery-service relay web
# Health:  curl http://<AWS_IP>:3001/health
# UI:      http://<AWS_IP>:3100

# ─── Local Environment ───
# Start:   CENTRAL_URL=http://<AWS_IP>:3005 docker compose -f docker-compose.local.yml up --build
# Health:  curl http://localhost:3005/health
# Traffic: curl http://localhost:8080/

# ─── Operations ───
# Force sync:     curl -X POST http://localhost:3005/api/v1/relay/sync
# Relay status:   curl http://localhost:3005/api/v1/relay/status
# All envs:       curl http://<AWS_IP>:3005/api/v1/relay/environments
# Decisions:      curl http://<AWS_IP>:3001/api/v1/access/decisions/live
# Switch mode:    PUT http://localhost:15000/mode {"mode":"enforce"}
```
