#!/bin/bash
# =============================================================================
# AWS EKS Deployment Script
# =============================================================================
#
# Usage:
#   ./setup-aws.sh --account-id 123456789012 --region us-east-1 --cluster my-eks
#
# Prerequisites:
#   - AWS CLI configured with sufficient permissions
#   - kubectl configured for your EKS cluster
#   - Docker installed and running
#   - Istio installed on the cluster
#   - Terraform applied (deploy/aws/terraform/)
# =============================================================================

set -euo pipefail

# ── Parse args ──
ACCOUNT_ID=""
REGION="us-east-1"
CLUSTER_NAME=""
MODE="deploy"  # deploy | dry-run | rollback

while [[ $# -gt 0 ]]; do
  case $1 in
    --account-id) ACCOUNT_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --cluster) CLUSTER_NAME="$2"; shift 2 ;;
    --dry-run) MODE="dry-run"; shift ;;
    --rollback) MODE="rollback"; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "$ACCOUNT_ID" || -z "$CLUSTER_NAME" ]]; then
  echo "Usage: $0 --account-id <id> --cluster <name> [--region <region>] [--dry-run] [--rollback]"
  exit 1
fi

ECR_BASE="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
TAG=$(git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)

echo "═══════════════════════════════════════════════════"
echo "  WID Platform — AWS EKS Deployment"
echo "═══════════════════════════════════════════════════"
echo "  Account:  ${ACCOUNT_ID}"
echo "  Region:   ${REGION}"
echo "  Cluster:  ${CLUSTER_NAME}"
echo "  Tag:      ${TAG}"
echo "  Mode:     ${MODE}"
echo "═══════════════════════════════════════════════════"

# ── Rollback ──
if [[ "$MODE" == "rollback" ]]; then
  echo "Rolling back: removing all AuthorizationPolicies..."
  kubectl get authorizationpolicy -A -l app.kubernetes.io/part-of=wid-platform -o name | \
    xargs -r kubectl delete || true
  echo "Rollback complete. ext_authz adapter still running but not called."
  echo "To fully remove: kubectl delete namespace wid-system"
  exit 0
fi

# ── ECR Login ──
echo "Logging into ECR..."
aws ecr get-login-password --region "${REGION}" | \
  docker login --username AWS --password-stdin "${ECR_BASE}"

# ── Build and push images ──
SERVICES=("ext-authz-adapter" "policy-engine" "token-service" "credential-broker")
# Contexts relative to services/ext-authz-adapter/deploy/aws/
CONTEXTS=("../../" "../../../policy-sync-service" "../../../token-service" "../../../credential-broker")
DOCKERFILES=("Dockerfile" "Dockerfile" "Dockerfile" "Dockerfile")

for i in "${!SERVICES[@]}"; do
  SVC="${SERVICES[$i]}"
  CTX="${CONTEXTS[$i]}"
  IMG="${ECR_BASE}/wid/${SVC}:${TAG}"

  echo ""
  echo "Building ${SVC}..."
  docker build -t "${IMG}" -f "${CTX}/Dockerfile" "${CTX}"

  if [[ "$MODE" != "dry-run" ]]; then
    echo "Pushing ${IMG}..."
    docker push "${IMG}"
    # Also tag as latest
    docker tag "${IMG}" "${ECR_BASE}/wid/${SVC}:latest"
    docker push "${ECR_BASE}/wid/${SVC}:latest"
  fi
done

if [[ "$MODE" == "dry-run" ]]; then
  echo ""
  echo "Dry run complete. Images built but not pushed."
  exit 0
fi

# ── Apply manifests ──
echo ""
echo "Applying Kubernetes manifests..."
MANIFEST_FILE="$(dirname "$0")/eks-manifests.yaml"

# Replace placeholders
sed -e "s|ACCOUNT_ID|${ACCOUNT_ID}|g" \
    -e "s|REGION|${REGION}|g" \
    -e "s|CLUSTER_NAME|${CLUSTER_NAME}|g" \
    -e "s|CLUSTER|${CLUSTER_NAME}|g" \
    "${MANIFEST_FILE}" | kubectl apply -f -

# ── Wait for rollout ──
echo ""
echo "Waiting for deployments..."
kubectl rollout status deployment/ext-authz-adapter -n wid-system --timeout=120s
kubectl rollout status deployment/policy-engine -n wid-system --timeout=120s
kubectl rollout status deployment/token-service -n wid-system --timeout=120s

# ── Verify ──
echo ""
echo "Verifying adapter health..."
ADAPTER_POD=$(kubectl get pod -n wid-system -l app=ext-authz-adapter -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n wid-system "${ADAPTER_POD}" -- wget -qO- http://localhost:8080/healthz

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Deployment complete!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Next steps:"
echo "  1. Register ext_authz in Istio mesh config:"
echo "     kubectl edit configmap istio -n istio-system"
echo "     Add extensionProviders: wid-policy-engine → ext-authz-adapter.wid-system:9191"
echo ""
echo "  2. Enable enforcement on a namespace (start with audit mode):"
echo "     kubectl apply -f authorization-policy.yaml -n <namespace>"
echo ""
echo "  3. Monitor:"
echo "     kubectl port-forward svc/ext-authz-adapter -n wid-system 8080:8080"
echo "     curl http://localhost:8080/metrics"
echo ""
echo "  Rollback:"
echo "     kubectl delete authorizationpolicy wid-protect -n <namespace>"
echo "     (Instant — zero traffic impact)"
echo ""
