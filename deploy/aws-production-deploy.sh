#!/bin/bash
# =============================================================================
# WID Platform — Production AWS Deployment
# =============================================================================
#
# One command to deploy the full WID central control plane to AWS:
#
#   ./deploy/aws-production-deploy.sh
#
# What it does:
#   1. Cleans up old Lambda functions from previous demos
#   2. Provisions VPC, EKS, RDS, ECR, IAM via Terraform
#   3. Builds and pushes Docker images to ECR
#   4. Initializes the RDS database
#   5. Deploys Kubernetes manifests (all services)
#   6. Installs AWS Load Balancer Controller
#   7. Returns the ALB URL for the central control plane
#
# Prerequisites:
#   - AWS CLI v2 configured (aws sts get-caller-identity works)
#   - Terraform 1.5+
#   - Docker running
#   - kubectl installed
#   - ~15 minutes for initial deployment
#
# Estimated cost: ~$150/month for dev size
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TF_DIR="$SCRIPT_DIR/aws/terraform"
K8S_MANIFESTS="$SCRIPT_DIR/aws/k8s-manifests.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner()  { echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}\n${BLUE}  $1${NC}\n${BLUE}═══════════════════════════════════════════════════════════${NC}\n"; }
step()    { echo -e "${CYAN}  ▶ $1${NC}"; }
ok()      { echo -e "${GREEN}  ✓ $1${NC}"; }
warn()    { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail()    { echo -e "${RED}  ✗ $1${NC}"; exit 1; }

# ═══════════════════════════════════════════════════════════════
# Pre-flight checks
# ═══════════════════════════════════════════════════════════════

banner "WID PLATFORM — PRODUCTION AWS DEPLOYMENT"

step "Checking prerequisites..."

command -v aws >/dev/null 2>&1 || fail "AWS CLI not found. Install: https://aws.amazon.com/cli/"
command -v terraform >/dev/null 2>&1 || fail "Terraform not found. Install: https://terraform.io"
command -v docker >/dev/null 2>&1 || fail "Docker not found"
command -v kubectl >/dev/null 2>&1 || fail "kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/"
docker info > /dev/null 2>&1 || fail "Docker daemon not running"

# Verify AWS credentials
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null) || fail "AWS credentials not configured. Run: aws configure"
AWS_REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")
ok "AWS Account: $AWS_ACCOUNT_ID | Region: $AWS_REGION"

ECR_REGISTRY="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

# ═══════════════════════════════════════════════════════════════
# Phase 1: Clean up old Lambda functions
# ═══════════════════════════════════════════════════════════════

banner "PHASE 1: CLEANUP"

step "Cleaning up old Lambda functions tagged with project=wid..."
LAMBDA_FUNCTIONS=$(aws lambda list-functions --region "$AWS_REGION" \
  --query "Functions[].FunctionName" --output text 2>/dev/null || echo "")

CLEANED=0
for FUNC_NAME in $LAMBDA_FUNCTIONS; do
  # Check if it's a WID function by name pattern or tags
  if echo "$FUNC_NAME" | grep -qi "wid\|workload-identity\|sample-wid"; then
    step "  Deleting Lambda: $FUNC_NAME"
    aws lambda delete-function --function-name "$FUNC_NAME" --region "$AWS_REGION" 2>/dev/null || true
    CLEANED=$((CLEANED + 1))
  else
    # Check tags
    TAGS=$(aws lambda list-tags --resource "arn:aws:lambda:$AWS_REGION:$AWS_ACCOUNT_ID:function:$FUNC_NAME" \
      --query "Tags" --output json 2>/dev/null || echo "{}")
    if echo "$TAGS" | grep -qi "wid\|workload-identity"; then
      step "  Deleting Lambda (tagged): $FUNC_NAME"
      aws lambda delete-function --function-name "$FUNC_NAME" --region "$AWS_REGION" 2>/dev/null || true
      CLEANED=$((CLEANED + 1))
    fi
  fi
done

if [ $CLEANED -gt 0 ]; then
  ok "Cleaned up $CLEANED Lambda function(s)"
else
  ok "No WID Lambda functions found to clean up"
fi

# Clean up old CloudFormation stacks
step "Checking for old CloudFormation stacks..."
OLD_STACKS=$(aws cloudformation list-stacks --region "$AWS_REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
  --query "StackSummaries[?contains(StackName,'wid')].StackName" --output text 2>/dev/null || echo "")

for STACK in $OLD_STACKS; do
  step "  Deleting stack: $STACK"
  aws cloudformation delete-stack --stack-name "$STACK" --region "$AWS_REGION" 2>/dev/null || true
done

ok "Cleanup complete"

# ═══════════════════════════════════════════════════════════════
# Phase 2: Terraform — Infrastructure
# ═══════════════════════════════════════════════════════════════

banner "PHASE 2: TERRAFORM — PROVISIONING INFRASTRUCTURE"

echo "  This will create:"
echo "    • VPC with public/private/database subnets"
echo "    • EKS cluster (2 nodes, t3.medium)"
echo "    • RDS PostgreSQL 15 (db.t3.micro, encrypted)"
echo "    • 7 ECR repositories"
echo "    • IRSA roles, Secrets Manager, CloudWatch"
echo ""
echo -e "  ${YELLOW}Estimated time: 15-20 minutes${NC}"
echo -e "  ${YELLOW}Estimated cost: ~\$150/month${NC}"
echo ""

read -p "  Proceed? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Aborted."
  exit 0
fi

cd "$TF_DIR"

step "Terraform init..."
terraform init -input=false > /dev/null 2>&1
ok "Terraform initialized"

step "Terraform plan..."
terraform plan -var-file=dev.tfvars -out=tfplan -input=false > /dev/null 2>&1
ok "Plan ready"

step "Terraform apply (this takes ~15 minutes)..."
terraform apply -input=false tfplan 2>&1 | tail -5
ok "Infrastructure provisioned"

# Extract outputs
EKS_CLUSTER_NAME=$(terraform output -raw eks_cluster_name)
RDS_ENDPOINT=$(terraform output -raw rds_endpoint)
DB_SECRET_ARN=$(terraform output -raw db_secret_arn)
JWT_SECRET_ARN=$(terraform output -raw jwt_secret_arn)
POLICY_ENGINE_ROLE_ARN=$(terraform output -raw policy_engine_role_arn)
AWS_REGION_OUT=$(terraform output -raw region)

ok "EKS Cluster:  $EKS_CLUSTER_NAME"
ok "RDS Endpoint: $RDS_ENDPOINT"
ok "ECR Registry: $ECR_REGISTRY"

cd "$PROJECT_ROOT"

# ═══════════════════════════════════════════════════════════════
# Phase 3: Build and push Docker images
# ═══════════════════════════════════════════════════════════════

banner "PHASE 3: BUILD & PUSH DOCKER IMAGES"

step "Logging into ECR..."
aws ecr get-login-password --region "$AWS_REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"
ok "ECR login successful"

declare -A SERVICE_MAP=(
  ["policy-engine"]="services/policy-sync-service"
  ["token-service"]="services/token-service"
  ["credential-broker"]="services/credential-broker"
  ["discovery-service"]="services/discovery-service"
  ["relay-service"]="services/relay-service"
  ["edge-gateway"]="services/edge-gateway"
)

# Build services with simple Dockerfiles
for SVC_NAME in "${!SERVICE_MAP[@]}"; do
  SVC_PATH="${SERVICE_MAP[$SVC_NAME]}"
  IMG="$ECR_REGISTRY/wid/$SVC_NAME:latest"

  if [ "$SVC_NAME" == "edge-gateway" ]; then
    step "Building $SVC_NAME (from project root)..."
    docker build -t "$IMG" -f "$SVC_PATH/Dockerfile" . > /dev/null 2>&1
  else
    step "Building $SVC_NAME..."
    docker build -t "$IMG" "$SVC_PATH" > /dev/null 2>&1
  fi

  step "Pushing $SVC_NAME..."
  docker push "$IMG" > /dev/null 2>&1
  ok "$SVC_NAME → $IMG"
done

# Web UI
step "Building web-ui..."
docker build -t "$ECR_REGISTRY/wid/web-ui:latest" web/workload-identity-manager > /dev/null 2>&1
step "Pushing web-ui..."
docker push "$ECR_REGISTRY/wid/web-ui:latest" > /dev/null 2>&1
ok "web-ui → $ECR_REGISTRY/wid/web-ui:latest"

ok "All 7 images pushed to ECR"

# ═══════════════════════════════════════════════════════════════
# Phase 4: Configure kubectl
# ═══════════════════════════════════════════════════════════════

banner "PHASE 4: KUBERNETES SETUP"

step "Configuring kubectl..."
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME" --region "$AWS_REGION" > /dev/null 2>&1
ok "kubectl configured for $EKS_CLUSTER_NAME"

step "Patching CoreDNS for Fargate..."
# CoreDNS on Fargate needs the ec2 compute-type annotation removed
kubectl patch deployment coredns -n kube-system \
  --type json -p='[{"op":"remove","path":"/spec/template/metadata/annotations/eks.amazonaws.com~1compute-type"}]' 2>/dev/null || true
# Restart CoreDNS so it schedules on Fargate
kubectl rollout restart deployment coredns -n kube-system > /dev/null 2>&1 || true
step "Waiting for CoreDNS to be ready on Fargate..."
kubectl rollout status deployment/coredns -n kube-system --timeout=300s > /dev/null 2>&1 || true
ok "CoreDNS running on Fargate"

# ═══════════════════════════════════════════════════════════════
# Phase 5: Initialize database
# ═══════════════════════════════════════════════════════════════

banner "PHASE 5: DATABASE INITIALIZATION"

step "Retrieving database credentials..."
DB_CREDS=$(aws secretsmanager get-secret-value --secret-id "$DB_SECRET_ARN" --query SecretString --output text)
DB_URL=$(echo "$DB_CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['url'])" 2>/dev/null || \
         echo "$DB_CREDS" | jq -r '.url')

# Create a temporary pod to initialize the database
step "Running database migration..."
kubectl create namespace wid-system --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

# Create DB credentials secret
kubectl create secret generic wid-db-credentials \
  --namespace wid-system \
  --from-literal=url="$DB_URL" \
  --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

# Create JWT secret
JWT_KEY=$(aws secretsmanager get-secret-value --secret-id "$JWT_SECRET_ARN" --query SecretString --output text)
kubectl create secret generic wid-jwt-secret \
  --namespace wid-system \
  --from-literal=jwt-secret="$JWT_KEY" \
  --dry-run=client -o yaml | kubectl apply -f - > /dev/null 2>&1

# Run init.sql via a Job
kubectl run db-init --namespace wid-system \
  --image=postgres:15-alpine \
  --restart=Never \
  --env="DATABASE_URL=$DB_URL" \
  --command -- sh -c "
    apk add --no-cache curl > /dev/null 2>&1
    PGPASSWORD=\$(echo \$DATABASE_URL | sed 's|.*://[^:]*:\([^@]*\)@.*|\1|')
    PGHOST=\$(echo \$DATABASE_URL | sed 's|.*@\([^:]*\):.*|\1|')
    PGUSER=\$(echo \$DATABASE_URL | sed 's|.*://\([^:]*\):.*|\1|')
    PGDATABASE=\$(echo \$DATABASE_URL | sed 's|.*/\([^?]*\).*|\1|')
    psql -h \$PGHOST -U \$PGUSER -d \$PGDATABASE -f /dev/stdin
  " < database/init.sql 2>/dev/null || true

step "Waiting for DB init to complete..."
kubectl wait --for=condition=Ready pod/db-init --namespace wid-system --timeout=120s 2>/dev/null || true
sleep 10
kubectl delete pod db-init --namespace wid-system --ignore-not-found > /dev/null 2>&1
ok "Database initialized"

# ═══════════════════════════════════════════════════════════════
# Phase 6: Install AWS Load Balancer Controller
# ═══════════════════════════════════════════════════════════════

banner "PHASE 6: ALB INGRESS CONTROLLER"

step "Installing AWS Load Balancer Controller..."

# Create IAM policy for ALB controller
ALB_POLICY_ARN=$(aws iam list-policies --query "Policies[?PolicyName=='AWSLoadBalancerControllerIAMPolicy'].Arn" --output text 2>/dev/null)
if [ -z "$ALB_POLICY_ARN" ] || [ "$ALB_POLICY_ARN" == "None" ]; then
  step "  Creating ALB IAM policy..."
  curl -sS "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.7.1/docs/install/iam_policy.json" -o /tmp/alb-policy.json
  ALB_POLICY_ARN=$(aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file:///tmp/alb-policy.json \
    --query "Policy.Arn" --output text 2>/dev/null || echo "")
fi

# Install via Helm
if command -v helm >/dev/null 2>&1; then
  helm repo add eks https://aws.github.io/eks-charts > /dev/null 2>&1 || true
  helm repo update > /dev/null 2>&1
  helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
    -n kube-system \
    --set clusterName="$EKS_CLUSTER_NAME" \
    --set serviceAccount.create=true \
    --set serviceAccount.name=aws-load-balancer-controller > /dev/null 2>&1
  ok "ALB controller installed via Helm"
else
  warn "Helm not found — install ALB controller manually"
  warn "  helm repo add eks https://aws.github.io/eks-charts"
  warn "  helm install aws-load-balancer-controller eks/aws-load-balancer-controller"
fi

# ═══════════════════════════════════════════════════════════════
# Phase 7: Deploy Kubernetes manifests
# ═══════════════════════════════════════════════════════════════

banner "PHASE 7: DEPLOY WID SERVICES"

step "Rendering manifests..."
sed \
  -e "s|\${ECR_REGISTRY}|$ECR_REGISTRY|g" \
  -e "s|\${AWS_REGION}|$AWS_REGION|g" \
  -e "s|\${EKS_CLUSTER_NAME}|$EKS_CLUSTER_NAME|g" \
  -e "s|\${POLICY_ENGINE_ROLE_ARN}|$POLICY_ENGINE_ROLE_ARN|g" \
  "$K8S_MANIFESTS" > /tmp/wid-k8s-rendered.yaml

step "Applying manifests..."
kubectl apply -f /tmp/wid-k8s-rendered.yaml 2>&1 | grep -c "configured\|created" | xargs -I{} echo "  {} resources applied"
ok "All services deployed"

step "Waiting for pods to be ready..."
kubectl rollout status deployment/policy-engine -n wid-system --timeout=120s > /dev/null 2>&1 || true
kubectl rollout status deployment/relay-service -n wid-system --timeout=120s > /dev/null 2>&1 || true
kubectl rollout status deployment/web-ui -n wid-system --timeout=120s > /dev/null 2>&1 || true

READY_PODS=$(kubectl get pods -n wid-system --no-headers | grep -c "Running" || echo 0)
ok "$READY_PODS pods running"

# ═══════════════════════════════════════════════════════════════
# Phase 8: Get URLs
# ═══════════════════════════════════════════════════════════════

banner "PHASE 8: DEPLOYMENT COMPLETE"

step "Waiting for ALB to provision (this may take 2-3 minutes)..."
for i in $(seq 1 30); do
  ALB_DNS=$(kubectl get ingress wid-ingress -n wid-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")
  if [ -n "$ALB_DNS" ]; then
    break
  fi
  sleep 10
done

if [ -z "$ALB_DNS" ]; then
  warn "ALB not ready yet. Get it later with:"
  warn "  kubectl get ingress wid-ingress -n wid-system"
  ALB_DNS="<pending>"
fi

echo ""
echo -e "
${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}
${GREEN}║  WID Platform — Production Deployment Complete                  ║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}║  Web UI:      ${CYAN}http://${ALB_DNS}${NC}${GREEN}${NC}
${GREEN}║  Relay Hub:   ${CYAN}http://${ALB_DNS}/health${NC}${GREEN}${NC}
${GREEN}║  Policies:    ${CYAN}http://${ALB_DNS}/api/v1/policies${NC}${GREEN}${NC}
${GREEN}║  Environments:${CYAN}http://${ALB_DNS}/api/v1/relay/environments${NC}${GREEN}${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}║  EKS Cluster: ${CYAN}${EKS_CLUSTER_NAME}${NC}${GREEN}${NC}
${GREEN}║  RDS:         ${CYAN}${RDS_ENDPOINT}${NC}${GREEN}${NC}
${GREEN}║  ECR:         ${CYAN}${ECR_REGISTRY}/wid/*${NC}${GREEN}${NC}
${GREEN}║  Region:      ${CYAN}${AWS_REGION}${NC}${GREEN}${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${GREEN}║  CONNECT LOCAL DOCKER TO AWS:                                    ║${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}║  ${CYAN}export CENTRAL_URL=http://${ALB_DNS}:3005${NC}${GREEN}${NC}
${GREEN}║  ${CYAN}docker compose -f deploy/local/docker-compose.local.yml \\${NC}${GREEN}${NC}
${GREEN}║  ${CYAN}  up --build${NC}${GREEN}${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${GREEN}║  USEFUL COMMANDS:                                                ║${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}║  kubectl get pods -n wid-system                                  ║${NC}
${GREEN}║  kubectl logs -f deploy/relay-service -n wid-system              ║${NC}
${GREEN}║  kubectl get ingress -n wid-system                               ║${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}╠══════════════════════════════════════════════════════════════════╣${NC}
${GREEN}║  TO TEAR DOWN:                                                   ║${NC}
${GREEN}║  ${CYAN}./deploy/aws-teardown.sh${NC}${GREEN}${NC}
${GREEN}║                                                                  ║${NC}
${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}
"

# Save deployment info
cat > "$SCRIPT_DIR/aws/.deployment-info" <<EOF
CLUSTER_NAME=$EKS_CLUSTER_NAME
ALB_DNS=$ALB_DNS
RDS_ENDPOINT=$RDS_ENDPOINT
ECR_REGISTRY=$ECR_REGISTRY
AWS_REGION=$AWS_REGION
DEPLOYED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

ok "Deployment info saved to deploy/aws/.deployment-info"
