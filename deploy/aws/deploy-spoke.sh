#!/usr/bin/env bash
# =============================================================================
# deploy-spoke.sh — Build, push, and deploy WID spoke to AWS ECS Fargate
# =============================================================================
# Usage:
#   ./deploy-spoke.sh                        # Full deploy (build + push + terraform)
#   ./deploy-spoke.sh --build-only           # Build and push images only
#   ./deploy-spoke.sh --terraform-only       # Terraform apply only (images must exist)
#   ./deploy-spoke.sh --destroy              # Tear down all spoke resources
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TF_DIR="$SCRIPT_DIR/terraform/spoke"

# ── Defaults (override via env vars or terraform.tfvars) ─────────────────────

AWS_REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="${PROJECT_NAME:-wid}"

# ── Parse args ───────────────────────────────────────────────────────────────

BUILD_ONLY=false
TF_ONLY=false
DESTROY=false

for arg in "$@"; do
  case "$arg" in
    --build-only)     BUILD_ONLY=true ;;
    --terraform-only) TF_ONLY=true ;;
    --destroy)        DESTROY=true ;;
    --help|-h)
      echo "Usage: $0 [--build-only|--terraform-only|--destroy]"
      exit 0
      ;;
  esac
done

# ── Preflight checks ────────────────────────────────────────────────────────

echo "=== WID AWS Spoke Deployment ==="

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform not found"; exit 1; }

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
if [ -z "$ACCOUNT_ID" ]; then
  echo "ERROR: Not authenticated to AWS. Run 'aws configure' or set AWS_PROFILE."
  exit 1
fi

ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
echo "  Account:  $ACCOUNT_ID"
echo "  Region:   $AWS_REGION"
echo "  Registry: $ECR_REGISTRY"
echo ""

# ── Destroy ──────────────────────────────────────────────────────────────────

if [ "$DESTROY" = true ]; then
  echo "=== Destroying spoke resources ==="
  cd "$TF_DIR"
  terraform destroy -auto-approve
  echo "=== Spoke destroyed ==="
  exit 0
fi

# ── Build and push images ───────────────────────────────────────────────────

build_and_push() {
  echo "=== Building and pushing images ==="

  # Login to ECR
  aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin "$ECR_REGISTRY"

  # Create ECR repos if they don't exist (terraform may not have run yet)
  for repo in "${PROJECT_NAME}/relay-service" "${PROJECT_NAME}/edge-gateway"; do
    aws ecr describe-repositories --repository-names "$repo" --region "$AWS_REGION" 2>/dev/null || \
      aws ecr create-repository --repository-name "$repo" --region "$AWS_REGION" --image-scanning-configuration scanOnPush=true
  done

  # Build relay-service
  echo "  Building relay-service..."
  docker build \
    --platform linux/amd64 \
    -t "${ECR_REGISTRY}/${PROJECT_NAME}/relay-service:latest" \
    -f "$REPO_ROOT/services/relay-service/Dockerfile" \
    "$REPO_ROOT/services/relay-service"

  # Build edge-gateway
  echo "  Building edge-gateway..."
  docker build \
    --platform linux/amd64 \
    -t "${ECR_REGISTRY}/${PROJECT_NAME}/edge-gateway:latest" \
    -f "$REPO_ROOT/services/edge-gateway/Dockerfile" \
    "$REPO_ROOT/services/edge-gateway"

  # Push
  echo "  Pushing relay-service..."
  docker push "${ECR_REGISTRY}/${PROJECT_NAME}/relay-service:latest"

  echo "  Pushing edge-gateway..."
  docker push "${ECR_REGISTRY}/${PROJECT_NAME}/edge-gateway:latest"

  echo "=== Images pushed ==="
}

# ── Terraform apply ─────────────────────────────────────────────────────────

terraform_apply() {
  echo "=== Running Terraform ==="
  cd "$TF_DIR"

  terraform init -upgrade

  terraform plan -out=spoke.tfplan

  echo ""
  echo "Review the plan above. Proceeding with apply..."
  echo ""

  terraform apply spoke.tfplan
  rm -f spoke.tfplan

  echo ""
  echo "=== Terraform apply complete ==="
  echo ""

  # Print outputs
  echo "=== Spoke Deployment Summary ==="
  terraform output -json spoke_summary 2>/dev/null | python3 -m json.tool 2>/dev/null || \
    terraform output spoke_summary
}

# ── Execute ──────────────────────────────────────────────────────────────────

if [ "$TF_ONLY" = true ]; then
  terraform_apply
elif [ "$BUILD_ONLY" = true ]; then
  build_and_push
else
  build_and_push
  terraform_apply
fi

echo ""
echo "=== Done ==="
echo ""
echo "Verify spoke health:"
echo "  ALB_URL=\$(terraform -chdir=$TF_DIR output -raw alb_url)"
echo "  curl \$ALB_URL/health"
echo ""
echo "Check GCP hub registration:"
echo "  curl http://34.120.74.81/api/v1/relay/environments"
