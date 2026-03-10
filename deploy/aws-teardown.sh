#!/bin/bash
# =============================================================================
# WID Platform — AWS Teardown
# =============================================================================
# Terminates the EC2 instance and cleans up all AWS resources.
#
# Usage:
#   ./deploy/aws-teardown.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_INFO="$SCRIPT_DIR/.aws-deployment"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "\n${YELLOW}WID Platform — AWS Teardown${NC}\n"

if [ -f "$DEPLOY_INFO" ]; then
  source "$DEPLOY_INFO"
  echo -e "  Instance:  ${CYAN}$INSTANCE_ID${NC}"
  echo -e "  IP:        ${CYAN}$PUBLIC_IP${NC}"
  echo -e "  Region:    ${CYAN}$REGION${NC}"
  echo ""
else
  echo -e "${YELLOW}No deployment info found. Looking for WID instances...${NC}"
  REGION="${AWS_REGION:-us-east-1}"
fi

# Terminate instance
if [ -n "${INSTANCE_ID:-}" ]; then
  echo -e "  Terminating instance ${CYAN}$INSTANCE_ID${NC}..."
  aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" --region "$REGION" >/dev/null 2>&1 || true
  echo -e "  ${GREEN}✓ Instance terminating${NC}"
fi

# Also find any other WID instances
OTHER=$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=tag:Name,Values=wid-central-control-plane" "Name=instance-state-name,Values=running,pending,stopping" \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)

if [ -n "$OTHER" ]; then
  echo -e "  Found additional WID instances: $OTHER"
  aws ec2 terminate-instances --instance-ids $OTHER --region "$REGION" >/dev/null 2>&1 || true
  echo -e "  ${GREEN}✓ Terminated${NC}"
fi

# Optionally delete security group (wait for instances to terminate first)
echo ""
read -p "  Delete security group '$SG_NAME'? (y/N): " DELETE_SG
if [ "${DELETE_SG:-n}" = "y" ]; then
  echo "  Waiting for instances to fully terminate..."
  sleep 30
  SG_NAME="wid-platform-sg"
  SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=group-name,Values=$SG_NAME" \
    --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
  if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
    aws ec2 delete-security-group --group-id "$SG_ID" --region "$REGION" 2>/dev/null || true
    echo -e "  ${GREEN}✓ Security group deleted${NC}"
  fi
fi

# Optionally delete key pair
read -p "  Delete SSH key pair '$KEY_NAME'? (y/N): " DELETE_KEY
if [ "${DELETE_KEY:-n}" = "y" ]; then
  KEY_NAME="${KEY_NAME:-wid-platform-key}"
  aws ec2 delete-key-pair --key-name "$KEY_NAME" --region "$REGION" 2>/dev/null || true
  rm -f "$HOME/.ssh/${KEY_NAME}.pem"
  echo -e "  ${GREEN}✓ Key pair deleted${NC}"
fi

# Clean up Lambda functions
echo ""
echo "  Cleaning up Lambda functions..."
LAMBDA_FUNCTIONS=$(aws lambda list-functions --region "$REGION" \
  --query 'Functions[?starts_with(FunctionName, `wid-`) || starts_with(FunctionName, `workload-identity`) || starts_with(FunctionName, `WID`)].FunctionName' \
  --output text 2>/dev/null || true)
if [ -n "$LAMBDA_FUNCTIONS" ]; then
  for fn in $LAMBDA_FUNCTIONS; do
    aws lambda delete-function --function-name "$fn" --region "$REGION" 2>/dev/null || true
    echo -e "  ${GREEN}✓ Deleted Lambda: $fn${NC}"
  done
else
  echo -e "  ${GREEN}✓ No Lambda functions to clean up${NC}"
fi

# Remove deployment info
rm -f "$DEPLOY_INFO"

echo -e "\n${GREEN}Teardown complete.${NC}\n"
