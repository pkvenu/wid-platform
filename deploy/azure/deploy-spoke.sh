#!/usr/bin/env bash
# =============================================================================
# deploy-spoke.sh — Build, push, and deploy WID spoke to Azure Container Apps
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

AZURE_REGION="${AZURE_REGION:-eastus}"
ACR_NAME="${ACR_NAME:-widspoke}"

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

echo "=== WID Azure Spoke Deployment ==="

command -v az >/dev/null 2>&1 || { echo "ERROR: az CLI not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v terraform >/dev/null 2>&1 || { echo "ERROR: terraform not found"; exit 1; }

# Verify Azure login
SUBSCRIPTION=$(az account show --query name --output tsv 2>/dev/null)
if [ -z "$SUBSCRIPTION" ]; then
  echo "ERROR: Not authenticated to Azure. Run 'az login'."
  exit 1
fi

ACR_LOGIN_SERVER="${ACR_NAME}.azurecr.io"
echo "  Subscription: $SUBSCRIPTION"
echo "  Region:       $AZURE_REGION"
echo "  ACR:          $ACR_LOGIN_SERVER"
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

  # Login to ACR
  az acr login --name "$ACR_NAME" 2>/dev/null || {
    echo "ACR does not exist yet — will be created by Terraform."
    echo "Run with --terraform-only first, then --build-only."
    exit 1
  }

  # Build relay-service
  echo "  Building relay-service..."
  docker build \
    --platform linux/amd64 \
    -t "${ACR_LOGIN_SERVER}/relay-service:latest" \
    -f "$REPO_ROOT/services/relay-service/Dockerfile" \
    "$REPO_ROOT/services/relay-service"

  # Build edge-gateway
  echo "  Building edge-gateway..."
  docker build \
    --platform linux/amd64 \
    -t "${ACR_LOGIN_SERVER}/edge-gateway:latest" \
    -f "$REPO_ROOT/services/edge-gateway/Dockerfile" \
    "$REPO_ROOT/services/edge-gateway"

  # Push
  echo "  Pushing relay-service..."
  docker push "${ACR_LOGIN_SERVER}/relay-service:latest"

  echo "  Pushing edge-gateway..."
  docker push "${ACR_LOGIN_SERVER}/edge-gateway:latest"

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
  # For Azure, terraform must run first to create ACR
  terraform_apply
  build_and_push

  # Force new revision after pushing images
  echo "=== Restarting containers with new images ==="
  cd "$TF_DIR"
  RG=$(terraform output -raw resource_group_name)

  az containerapp revision restart \
    --name "$(terraform output -raw relay_fqdn | cut -d. -f1)" \
    --resource-group "$RG" 2>/dev/null || true

  echo "Container Apps will pull latest images on next revision."
fi

echo ""
echo "=== Done ==="
echo ""
echo "Verify spoke health:"
echo "  RELAY_URL=\$(terraform -chdir=$TF_DIR output -raw relay_url)"
echo "  curl \$RELAY_URL/health"
echo ""
echo "Check GCP hub registration:"
echo "  curl http://34.120.74.81/api/v1/relay/environments"
