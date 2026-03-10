# Workload Identity Platform — Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        WEB UI (:3100)                           │
│                 Workload Identity Manager                       │
└──────────┬────────────────┬────────────────┬────────────────────┘
           │                │                │
    ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐
    │  Policy     │  │  Discovery  │  │  Token      │
    │  Engine     │  │  Service    │  │  Service    │
    │  :3001      │  │  :3004      │  │  :3000      │
    └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
           │                │                │
           └───────┬────────┴────────┬───────┘
                   │                 │
            ┌──────▼──────┐   ┌──────▼──────┐
            │  PostgreSQL │   │  Vault      │
            │  :5432      │   │  :8200      │
            └─────────────┘   └─────────────┘

┌─────────────────── DATA PLANE ───────────────────────┐
│                                                       │
│  Option A: Service Mesh (Istio/Envoy)                │
│  ┌───────────┐    ┌───────────┐                      │
│  │ App Pod   │    │ App Pod   │                      │
│  │ ┌───────┐ │    │ ┌───────┐ │                      │
│  │ │ Envoy ├─┼────┼─┤ Envoy │ │                      │
│  │ └───┬───┘ │    │ └───┬───┘ │                      │
│  └─────┼─────┘    └─────┼─────┘                      │
│        └───────┬────────┘                             │
│          ┌─────▼─────┐                                │
│          │ ext-authz  │  ← gRPC ext_authz adapter     │
│          │ adapter    │     :9191 / :8080              │
│          └───────────┘                                │
│                                                       │
│  Option B: Non-Mesh (edge-gateway sidecar)           │
│  ┌────────────────────┐                               │
│  │ App Pod            │                               │
│  │ ┌──────┐ ┌───────┐│                               │
│  │ │ App  ├─┤ Edge  ││  ← transparent HTTP proxy     │
│  │ │      │ │Gateway││    + iptables redirect        │
│  │ └──────┘ └───────┘│                                │
│  └────────────────────┘                               │
└───────────────────────────────────────────────────────┘
```

## Services

| Service | Port | Purpose |
|---------|------|---------|
| **Web UI** | 3100 | React dashboard — workloads, policies, auth events |
| **Policy Engine** | 3001 | NHI governance — 34 policy templates, Rego compiler |
| **Discovery Service** | 3003 (→3004) | NHI auto-discovery — AWS/GCP/Azure/K8s/Docker scanners |
| **Token Service** | 3000 | JIT token exchange, chain tracking, trust gate |
| **Credential Broker** | 3002 | Vault/AWS/GCP/Azure credential provider |
| **Audit Service** | 3003 | Audit log persistence |
| **ext-authz Adapter** | 9191/8080 | gRPC ext_authz for Envoy/Istio (cloud/mesh mode) |
| **Edge Gateway** | 15001/15000 | Transparent HTTP proxy (on-prem/non-mesh mode) |
| **PostgreSQL** | 5432 | State store |
| **Vault** | 8200 | Secrets engine |

---

## 1. Local Development (Docker Compose)

### Prerequisites
- Docker Desktop
- Node.js 18+ (for web UI)

### Start Full Stack

```bash
# From project root
docker compose -f services/ext-authz-adapter/deploy/local/docker-compose.yml up --build
```

This starts: postgres, vault, policy-engine, token-service, credential-broker,
discovery-service, ext-authz-adapter, envoy-frontend, envoy-backend,
demo-frontend, demo-backend, web UI.

### Start Web UI

The web UI runs best natively (for hot reload):

```bash
cd web/workload-identity-manager
npm install
npm run dev
```

Open http://localhost:3100

### Verify

```bash
# Health checks
curl http://localhost:8080/healthz          # ext-authz adapter
curl http://localhost:3001/health           # policy engine
curl http://localhost:3000/health           # token service
curl http://localhost:3004/api/v1/stats     # discovery service

# End-to-end test (flows through Envoy + ext_authz)
curl http://localhost:10000/call | jq .

# Adapter metrics
curl http://localhost:8080/metrics | jq .
```

---

## 2. AWS/EKS Cloud Deployment

### Prerequisites
- AWS account with EKS cluster
- kubectl configured for the cluster
- Terraform 1.5+
- Docker (for building images)
- Istio installed on the cluster (for ext-authz mode)

### Step 1: Infrastructure (Terraform)

```bash
cd services/ext-authz-adapter/deploy/aws/terraform

terraform init
terraform plan \
  -var="cluster_name=YOUR_EKS_CLUSTER" \
  -var="account_id=YOUR_AWS_ACCOUNT_ID" \
  -var="vpc_id=YOUR_VPC_ID" \
  -var="private_subnet_ids=[\"subnet-xxx\",\"subnet-yyy\"]" \
  -var="eks_oidc_provider_arn=arn:aws:iam::ACCOUNT:oidc-provider/oidc.eks.REGION.amazonaws.com/id/CLUSTER_ID" \
  -var="eks_oidc_provider_url=oidc.eks.REGION.amazonaws.com/id/CLUSTER_ID"

terraform apply
```

This creates:
- `wid-system` namespace (Istio-injection enabled)
- IRSA roles for ext-authz-adapter and control plane (no static credentials)
- RDS PostgreSQL with IAM auth (no passwords)
- ECR repositories for all service images
- Security groups and CloudWatch log groups

### Step 2: Build and Push Images

```bash
# Get ECR login
AWS_ACCOUNT=YOUR_ACCOUNT_ID
AWS_REGION=us-east-1
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com

ECR=$AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/wid

# Build and push from project root
# ext-authz adapter (needs project root context for shared/)
docker build -f services/ext-authz-adapter/Dockerfile -t $ECR/ext-authz-adapter:latest .
docker push $ECR/ext-authz-adapter:latest

# Control plane services
for svc in policy-sync-service token-service credential-broker audit-service discovery-service; do
  docker build -t $ECR/$svc:latest services/$svc/
  docker push $ECR/$svc:latest
done

# Web UI
docker build -t $ECR/web:latest web/workload-identity-manager/
docker push $ECR/web:latest
```

### Step 3: Configure Secrets

```bash
# Database credentials (from Terraform output)
kubectl -n wid-system create secret generic wid-db-credentials \
  --from-literal=DATABASE_URL="postgresql://wid_user:PASSWORD@RDS_ENDPOINT:5432/workload_identity"

# JWT secret for token service
kubectl -n wid-system create secret generic wid-jwt-secret \
  --from-literal=JWT_SECRET=$(openssl rand -hex 32)
```

### Step 4: Deploy Kubernetes Manifests

```bash
# Update image references in eks-manifests.yaml
# Replace ACCOUNT_ID and CLUSTER placeholders
sed -i "s/ACCOUNT_ID/$AWS_ACCOUNT/g" services/ext-authz-adapter/deploy/aws/eks-manifests.yaml
sed -i "s/CLUSTER/$CLUSTER_NAME/g" services/ext-authz-adapter/deploy/aws/eks-manifests.yaml

kubectl apply -f services/ext-authz-adapter/deploy/aws/eks-manifests.yaml
```

### Step 5: Configure Istio ext_authz

```yaml
# Add to Istio mesh config (istioctl or IstioOperator)
meshConfig:
  extensionProviders:
  - name: wid-ext-authz
    envoyExtAuthzGrpc:
      service: ext-authz-adapter.wid-system.svc.cluster.local
      port: 9191
      timeout: 0.5s
```

Then apply an AuthorizationPolicy to target namespaces:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: wid-protect
  namespace: YOUR_APP_NAMESPACE
spec:
  action: CUSTOM
  provider:
    name: wid-ext-authz
  rules:
  - {} # All traffic in this namespace goes through WID
```

### Step 6: Verify Cloud Deployment

```bash
# Check all pods
kubectl -n wid-system get pods

# Check adapter health
kubectl -n wid-system port-forward svc/ext-authz-adapter 8080:8080
curl http://localhost:8080/healthz
curl http://localhost:8080/metrics | jq .

# Check policy engine
kubectl -n wid-system port-forward svc/policy-engine 3001:3001
curl http://localhost:3001/health

# Access web UI
kubectl -n wid-system port-forward svc/web 3100:3100
# Open http://localhost:3100
```

---

## 3. Non-Mesh Deployment (Edge Gateway)

For environments without a service mesh (VMs, plain K8s, on-prem):

### Kubernetes (Sidecar)

```bash
# See the example sidecar manifest
cat services/edge-gateway/deploy/k8s/sidecar-example.yaml

# Add edge-gateway as a sidecar to your app deployment:
# - init container sets up iptables redirect
# - edge-gateway container runs alongside your app
# - all outbound traffic transparently routed through gateway
```

### VM/Bare Metal

```bash
# Install as a systemd service
npm install -g @wid/edge-gateway

# Configure
cat > /etc/wid/gateway.env << EOF
POLICY_SERVICE_URL=http://policy-engine:3001
TOKEN_SERVICE_URL=http://token-service:3000
DEFAULT_MODE=audit
FAIL_BEHAVIOR=open
EOF

# Set up iptables redirect
edge-gateway --generate-iptables | sudo bash

# Start
systemctl start wid-edge-gateway
```

---

## 4. Rollout Strategy

### Phase 1: Audit Mode (default)

```
DEFAULT_MODE=audit
DEFAULT_FAIL_BEHAVIOR=open
```

All traffic is allowed. The adapter evaluates policies and logs what WOULD be
denied as `x-wid-shadow-verdict: deny`. Check metrics and audit logs.

### Phase 2: Enforce Per-Workload

```yaml
# Override specific high-risk workloads to enforce
WORKLOAD_OVERRIDES: |
  {
    "spiffe://cluster/ns/prod/sa/payment-service": {
      "mode": "enforce",
      "fail": "closed"
    }
  }
```

### Phase 3: Full Enforce

```
DEFAULT_MODE=enforce
DEFAULT_FAIL_BEHAVIOR=open    # still fail-open for safety
```

### Phase 4: Fail-Closed

```
DEFAULT_MODE=enforce
DEFAULT_FAIL_BEHAVIOR=closed  # deny if policy engine is unreachable
```

---

## Environment Variables

### ext-authz Adapter

| Variable | Default | Description |
|----------|---------|-------------|
| `DEPLOY_MODE` | `local` | `local` or `aws` |
| `GRPC_PORT` | `9191` | gRPC server port |
| `ADMIN_PORT` | `8080` | Admin/metrics API port |
| `POLICY_SERVICE_URL` | `http://localhost:3001` | Policy engine URL |
| `TOKEN_SERVICE_URL` | `http://localhost:3000` | Token service URL |
| `DEFAULT_MODE` | `audit` | `audit`, `enforce`, or `passthrough` |
| `DEFAULT_FAIL_BEHAVIOR` | `open` | `open` or `closed` |
| `CACHE_ENABLED` | `true` | Policy cache |
| `CACHE_TTL_MS` | `30000` | Cache TTL (ms) |
| `CRED_BUFFER_ENABLED` | `true` | Credential buffer for outages |
| `CP_TIMEOUT_MS` | `300` | Control plane call timeout |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Edge Gateway

| Variable | Default | Description |
|----------|---------|-------------|
| `OUTBOUND_PORT` | `15001` | Outbound proxy port |
| `INBOUND_PORT` | `15006` | Inbound proxy port |
| `ADMIN_PORT` | `15000` | Admin/metrics API port |
| `APP_PORT` | `8080` | Local app port |
| `DEFAULT_MODE` | `audit` | `audit`, `enforce`, or `passthrough` |
| `FAIL_BEHAVIOR` | `open` | `open` or `closed` |

---

## Monitoring

### Prometheus Metrics

Both data-plane modes expose Prometheus-compatible metrics:

```bash
# ext-authz adapter
curl http://localhost:8080/metrics

# edge-gateway
curl http://localhost:15000/metrics
```

Key metrics:
- `wid_extauthz_total_total` — total decisions
- `wid_extauthz_allowed_total` — allowed
- `wid_extauthz_denied_total` — denied
- `wid_extauthz_cached_total` — cache hits
- `wid_extauthz_latency_p50/p95/p99` — decision latency

### Grafana Dashboard

Import the metrics into Grafana with a Prometheus data source targeting
the adapter's `/metrics` endpoint.

### Alerts

Recommended alerts:
- `wid_extauthz_denied_total` spike → potential attack or misconfigured policy
- Circuit breaker tripped → control plane unreachable
- p99 latency > 50ms → performance degradation
- Cache hit rate < 50% → policies changing too frequently
