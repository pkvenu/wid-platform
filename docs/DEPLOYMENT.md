# Workload Identity Defense (WID) Platform — Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        WEB UI (:3100)                           │
│                 Workload Identity Defense                       │
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

## 5. Spoke mTLS Federation Setup

Spokes (relay services in remote environments) authenticate to the hub using mutual TLS.
Three options in order of preference:

### Prerequisites

- `openssl` 1.1+ (all options)
- SPIRE 1.8+ (Option A only)

### Option A: SPIRE-Based (Recommended)

If your environment already runs SPIRE, configure the SPIRE agent to issue SVIDs for the relay workload.

1. **Register the relay entry** with the SPIRE server:

```bash
spire-server entry create \
  -spiffeID spiffe://wid-platform/relay/<env-name> \
  -parentID spiffe://wid-platform/agent/<node-id> \
  -selector k8s:pod-label:app=wid-relay   # or unix:uid, docker:label, etc.
```

2. **Point relay env vars at the SPIRE agent socket**:

```bash
RELAY_CERT_PATH=/run/spire/agent/sockets/svid.pem
RELAY_KEY_PATH=/run/spire/agent/sockets/svid_key.pem
RELAY_CA_BUNDLE_PATH=/run/spire/agent/sockets/bundle.pem
RELAY_SPIFFE_ID=spiffe://wid-platform/relay/<env-name>
```

The relay will auto-rotate certs via the SPIRE Workload API.

### Option B: Bootstrap Flow (Without SPIRE)

Use the built-in federation CA for environments without SPIRE.

**Step 1 — Generate Federation CA:**

```bash
deploy/certs/generate-federation-ca.sh
# Outputs: federation-ca.key, federation-ca.crt (valid 5 years)
```

**Step 2 — Deploy CA to the hub:**

```bash
# On the hub (policy-sync-service)
export FEDERATION_CA_KEY_PATH=/etc/wid/certs/federation-ca.key
export FEDERATION_CA_CERT_PATH=/etc/wid/certs/federation-ca.crt
```

**Step 3 — Generate relay cert:**

```bash
# Option 1: CLI flag during install
deploy/install.sh --with-relay-cert --env-name staging --hub-url https://hub.wid.example.com

# Option 2: API call (requires bootstrap token)
curl -X POST https://hub.wid.example.com/api/v1/federation/bootstrap \
  -H "Authorization: Bearer $FEDERATION_BOOTSTRAP_TOKEN" \
  -d '{"envName": "staging"}' \
  -o relay-certs.json
```

**Step 4 — Configure relay env vars:**

```bash
RELAY_CERT_PATH=/etc/wid/certs/relay.pem
RELAY_KEY_PATH=/etc/wid/certs/relay-key.pem
RELAY_CA_BUNDLE_PATH=/etc/wid/certs/federation-ca.crt
RELAY_SPIFFE_ID=spiffe://wid-platform/relay/staging
```

### Option C: API Key Fallback

For dev/test environments where mTLS is not required:

```bash
CENTRAL_API_KEY=<your-api-key>
```

No certificate configuration needed. The relay authenticates via the `X-API-Key` header.
This is the existing behavior and is **not recommended for production**.

### Verification

After configuring mTLS, verify federation status:

```bash
# List connected relays and their mTLS status
curl -s https://hub.wid.example.com/api/v1/federation/relays \
  -H "Cookie: token=<admin-jwt>" | jq .

# Check recent federation events (cert rotations, handshakes)
curl -s https://hub.wid.example.com/api/v1/federation/events \
  -H "Cookie: token=<admin-jwt>" | jq .

# Health endpoint includes mTLS section
curl -s https://hub.wid.example.com/health | jq '.mtls'
# Expected: { "enabled": true, "activeCerts": 1, "caExpiry": "2031-..." }
```

---

## 6. Azure Spoke Deployment (Container Apps)

### Prerequisites
- Azure CLI (`az`) installed and logged in
- Terraform 1.5+
- Docker (for building images)

### Deploy with Terraform

```bash
cd deploy/azure/terraform/spoke

# Initialize
terraform init

# Review plan
terraform plan \
  -var="environment_name=azure-eastus" \
  -var="central_url=http://34.120.74.81" \
  -var="azure_region=eastus"

# Apply
terraform apply
```

This creates:
- Resource Group with VNET (10.2.0.0/16) + Container Apps subnet
- User-Assigned Managed Identity (AcrPull + Key Vault Secrets User)
- Azure Container Registry (image scanning enabled)
- Azure Key Vault (secrets stored securely, accessed via MI)
- Container Apps Environment (integrated with VNET + Log Analytics)
- Relay container app (spoke mode, mTLS + webhook ready)
- N edge-gateway container apps (one per workload config)
- Azure Monitor alert rules (relay health, container restarts, memory)

### Build and Push Images

```bash
# Login to ACR (use the ACR name from terraform output)
ACR=$(terraform output -raw acr_login_server)
az acr login --name $(terraform output -raw acr_login_server | cut -d. -f1)

# Build and push from project root
docker build --platform linux/amd64 -t $ACR/relay-service:latest -f services/relay-service/Dockerfile .
docker push $ACR/relay-service:latest

docker build --platform linux/amd64 -t $ACR/edge-gateway:latest -f services/edge-gateway/Dockerfile .
docker push $ACR/edge-gateway:latest

# Force container restart
az containerapp revision restart --name $(terraform output -raw relay_app_name) \
  --resource-group $(terraform output -raw resource_group_name)
```

### Verify

```bash
# Relay health
curl -s https://$(terraform output -raw relay_fqdn)/health | jq .

# Check federation registration at hub
curl -s http://34.120.74.81/api/v1/federation/relays | jq .

# Gateway health (example for servicenow gateway)
curl -s https://$(terraform output -json gateway_urls | jq -r '.servicenow')/health | jq .
```

### Key Differences from AWS Spoke

| Aspect | AWS (ECS Fargate) | Azure (Container Apps) |
|--------|-------------------|------------------------|
| Auth | IAM roles | Managed Identity |
| Secrets | Secrets Manager | Key Vault |
| Networking | VPC + NAT + ALB | VNET + Container Apps ingress |
| Registry | ECR | ACR |
| Monitoring | CloudWatch | Log Analytics + Monitor Alerts |
| Scaling | ECS service count | Container Apps min/max replicas |

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

### Relay Service (mTLS)

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_CERT_PATH` | — | Path to relay TLS certificate (PEM) |
| `RELAY_KEY_PATH` | — | Path to relay TLS private key (PEM) |
| `RELAY_CA_BUNDLE_PATH` | — | Path to CA bundle for verifying the hub |
| `RELAY_SPIFFE_ID` | — | SPIFFE ID for this relay (e.g. `spiffe://wid-platform/relay/staging`) |
| `WEBHOOK_ENABLED` | `false` | Enable webhook listener for push-based policy updates |
| `WEBHOOK_PORT` | `8443` | Port for the webhook HTTPS listener |
| `FEDERATION_PUSH_SECRET` | — | HMAC secret for validating hub-pushed events |
| `FEDERATION_CA_KEY_PATH` | — | (Hub only) Path to federation CA private key |
| `FEDERATION_CA_CERT_PATH` | — | (Hub only) Path to federation CA certificate |
| `FEDERATION_BOOTSTRAP_TOKEN` | — | One-time token for relay cert bootstrap (Option B) |

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
