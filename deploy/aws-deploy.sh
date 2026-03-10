#!/bin/bash
# =============================================================================
# WID Platform — One-Command AWS Deployment
# =============================================================================
#
# Deploys the central control plane to an EC2 instance and returns the URLs.
# Also cleans up any existing Lambda functions from previous demos.
#
# Usage:
#   chmod +x deploy/aws-deploy.sh
#   ./deploy/aws-deploy.sh
#
# Prerequisites:
#   - AWS CLI v2 configured (aws configure)
#   - An SSH key pair in AWS (or we'll create one)
#   - Permissions: EC2, Lambda, IAM, SecurityGroups
#
# What this script does:
#   1. Cleans up old Lambda functions (from previous demos)
#   2. Creates a security group (or reuses existing)
#   3. Launches an EC2 instance (t3.medium, Ubuntu 22.04)
#   4. Installs Docker on the instance
#   5. Uploads the project code
#   6. Starts the central control plane
#   7. Waits for services to be healthy
#   8. Prints the URLs
#
# Estimated time: 5-7 minutes
# Estimated cost: ~$0.04/hour (t3.medium)
#
# =============================================================================

set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════

REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${WID_INSTANCE_TYPE:-t3.medium}"
KEY_NAME="${WID_KEY_NAME:-wid-platform-key}"
SG_NAME="wid-platform-sg"
INSTANCE_NAME="wid-central-control-plane"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner()  { echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}\n${BLUE}  $1${NC}\n${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"; }
step()    { echo -e "${CYAN}  ▶ $1${NC}"; }
ok()      { echo -e "${GREEN}  ✓ $1${NC}"; }
warn()    { echo -e "${YELLOW}  ⚠ $1${NC}"; }
fail()    { echo -e "${RED}  ✗ $1${NC}"; }

# ═══════════════════════════════════════════════════════════════
# Pre-flight
# ═══════════════════════════════════════════════════════════════

banner "WID PLATFORM — AWS DEPLOYMENT"

step "Checking AWS CLI..."
if ! command -v aws &>/dev/null; then
  fail "AWS CLI not found. Install: https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
if [ -z "$ACCOUNT_ID" ]; then
  fail "AWS not configured. Run: aws configure"
  exit 1
fi
ok "AWS Account: $ACCOUNT_ID | Region: $REGION"

# ═══════════════════════════════════════════════════════════════
# PHASE 0: Clean up old Lambda functions
# ═══════════════════════════════════════════════════════════════

banner "PHASE 0: CLEANUP"

step "Cleaning up old Lambda functions..."
LAMBDA_FUNCTIONS=$(aws lambda list-functions --region "$REGION" --query 'Functions[?starts_with(FunctionName, `wid-`) || starts_with(FunctionName, `workload-identity`) || starts_with(FunctionName, `WID`)].FunctionName' --output text 2>/dev/null || true)

if [ -n "$LAMBDA_FUNCTIONS" ]; then
  for fn in $LAMBDA_FUNCTIONS; do
    step "Deleting Lambda: $fn"
    aws lambda delete-function --function-name "$fn" --region "$REGION" 2>/dev/null || true
    ok "Deleted: $fn"
  done
else
  ok "No WID Lambda functions found"
fi

# Also clean up any Lambda-related IAM roles
step "Cleaning up Lambda execution roles..."
LAMBDA_ROLES=$(aws iam list-roles --query 'Roles[?starts_with(RoleName, `wid-lambda`) || starts_with(RoleName, `WID-Lambda`)].RoleName' --output text 2>/dev/null || true)
if [ -n "$LAMBDA_ROLES" ]; then
  for role in $LAMBDA_ROLES; do
    # Detach policies first
    POLICIES=$(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true)
    for policy in $POLICIES; do
      aws iam detach-role-policy --role-name "$role" --policy-arn "$policy" 2>/dev/null || true
    done
    aws iam delete-role --role-name "$role" 2>/dev/null || true
    ok "Deleted role: $role"
  done
else
  ok "No WID Lambda roles found"
fi

# Clean up old EC2 instances with our name
step "Checking for existing WID instances..."
OLD_INSTANCES=$(aws ec2 describe-instances \
  --region "$REGION" \
  --filters "Name=tag:Name,Values=$INSTANCE_NAME" "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true)

if [ -n "$OLD_INSTANCES" ]; then
  warn "Found existing WID instance(s): $OLD_INSTANCES"
  echo -e "  ${YELLOW}Terminating old instance(s)...${NC}"
  aws ec2 terminate-instances --instance-ids $OLD_INSTANCES --region "$REGION" >/dev/null 2>&1 || true
  aws ec2 wait instance-terminated --instance-ids $OLD_INSTANCES --region "$REGION" 2>/dev/null || true
  ok "Old instances terminated"
fi

ok "Cleanup complete"

# ═══════════════════════════════════════════════════════════════
# PHASE 1: Create SSH Key Pair
# ═══════════════════════════════════════════════════════════════

banner "PHASE 1: SSH KEY PAIR"

KEY_FILE="$HOME/.ssh/${KEY_NAME}.pem"

if aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" &>/dev/null; then
  ok "Key pair '$KEY_NAME' already exists"
  if [ ! -f "$KEY_FILE" ]; then
    warn "Key file not found at $KEY_FILE"
    warn "If you can't SSH in, delete the key pair and re-run:"
    warn "  aws ec2 delete-key-pair --key-name $KEY_NAME --region $REGION"
  fi
else
  step "Creating key pair: $KEY_NAME"
  mkdir -p "$HOME/.ssh"
  aws ec2 create-key-pair \
    --key-name "$KEY_NAME" \
    --region "$REGION" \
    --query 'KeyMaterial' \
    --output text > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  ok "Key saved to: $KEY_FILE"
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 2: Security Group
# ═══════════════════════════════════════════════════════════════

banner "PHASE 2: SECURITY GROUP"

# Get default VPC
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" --filters "Name=is-default,Values=true" --query 'Vpcs[0].VpcId' --output text 2>/dev/null || true)
if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
  fail "No default VPC found in $REGION. Create one or set VPC_ID manually."
  exit 1
fi
ok "VPC: $VPC_ID"

# Create or reuse security group
SG_ID=$(aws ec2 describe-security-groups \
  --region "$REGION" \
  --filters "Name=group-name,Values=$SG_NAME" "Name=vpc-id,Values=$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)

if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  step "Creating security group: $SG_NAME"
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "WID Platform - Central Control Plane" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" \
    --query 'GroupId' --output text)

  # SSH
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null

  # Web UI
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3100 --cidr 0.0.0.0/0 >/dev/null

  # Relay (federation endpoint)
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3005 --cidr 0.0.0.0/0 >/dev/null

  # Policy Engine
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3001 --cidr 0.0.0.0/0 >/dev/null

  # Token Service
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3000 --cidr 0.0.0.0/0 >/dev/null

  # Credential Broker
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3002 --cidr 0.0.0.0/0 >/dev/null

  # Discovery Service
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --region "$REGION" \
    --protocol tcp --port 3004 --cidr 0.0.0.0/0 >/dev/null

  ok "Security group created: $SG_ID"
  ok "Ports open: 22 (SSH), 3000-3005 (services), 3100 (Web UI)"
else
  ok "Security group exists: $SG_ID"
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 3: Launch EC2 Instance
# ═══════════════════════════════════════════════════════════════

banner "PHASE 3: LAUNCH EC2 INSTANCE"

# Get latest Ubuntu 22.04 AMI
step "Finding Ubuntu 22.04 AMI..."
AMI_ID=$(aws ec2 describe-images \
  --region "$REGION" \
  --owners 099720109477 \
  --filters \
    "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-server-*" \
    "Name=architecture,Values=arm64" \
    "Name=state,Values=available" \
  --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
  --output text 2>/dev/null || true)

# Fallback to x86 if arm64 not available
if [ "$AMI_ID" = "None" ] || [ -z "$AMI_ID" ]; then
  AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners 099720109477 \
    --filters \
      "Name=name,Values=ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-*-server-*" \
      "Name=architecture,Values=x86_64" \
      "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)
fi
ok "AMI: $AMI_ID"

# User data script — installs Docker and starts the platform
USER_DATA=$(cat <<'USERDATA'
#!/bin/bash
set -e

# Install Docker
apt-get update -y
apt-get install -y docker.io docker-compose-v2 git
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# Signal that Docker is ready
touch /tmp/docker-ready

# The deploy script will SCP the code and start services separately
USERDATA
)

step "Launching $INSTANCE_TYPE instance..."
INSTANCE_ID=$(aws ec2 run-instances \
  --region "$REGION" \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":30,"VolumeType":"gp3"}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME},{Key=Project,Value=wid-platform}]" \
  --user-data "$USER_DATA" \
  --query 'Instances[0].InstanceId' \
  --output text)

ok "Instance launched: $INSTANCE_ID"

step "Waiting for instance to be running..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"

PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids "$INSTANCE_ID" \
  --region "$REGION" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text)

ok "Instance running: $PUBLIC_IP"

# ═══════════════════════════════════════════════════════════════
# PHASE 4: Wait for Docker & Upload Code
# ═══════════════════════════════════════════════════════════════

banner "PHASE 4: SETUP INSTANCE"

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o ServerAliveInterval=5 -i $KEY_FILE"

step "Waiting for SSH to be available..."
MAX_RETRIES=30
for i in $(seq 1 $MAX_RETRIES); do
  if ssh $SSH_OPTS ubuntu@"$PUBLIC_IP" "echo ok" &>/dev/null; then
    ok "SSH is ready"
    break
  fi
  if [ "$i" -eq "$MAX_RETRIES" ]; then
    fail "SSH timeout after ${MAX_RETRIES} attempts"
    echo -e "  Try manually: ssh $SSH_OPTS ubuntu@$PUBLIC_IP"
    exit 1
  fi
  sleep 10
done

step "Waiting for Docker to install (user-data script)..."
for i in $(seq 1 30); do
  if ssh $SSH_OPTS ubuntu@"$PUBLIC_IP" "test -f /tmp/docker-ready" &>/dev/null; then
    ok "Docker is installed"
    break
  fi
  if [ "$i" -eq 30 ]; then
    warn "Docker install taking long, checking manually..."
    ssh $SSH_OPTS ubuntu@"$PUBLIC_IP" "sudo apt-get install -y docker.io docker-compose-v2 && sudo systemctl start docker && sudo usermod -aG docker ubuntu"
  fi
  sleep 10
done

# Package project for upload (exclude node_modules, .git)
step "Packaging project for upload..."
ARCHIVE="/tmp/wid-platform.tar.gz"
cd "$PROJECT_DIR"
tar czf "$ARCHIVE" \
  --exclude='node_modules' \
  --exclude='.git' \
  --exclude='*.lock' \
  --exclude='.DS_Store' \
  --exclude='__pycache__' \
  .

ARCHIVE_SIZE=$(du -h "$ARCHIVE" | cut -f1)
ok "Archive created: $ARCHIVE_SIZE"

step "Uploading to EC2..."
scp $SSH_OPTS "$ARCHIVE" ubuntu@"$PUBLIC_IP":~/wid-platform.tar.gz
ok "Upload complete"

step "Extracting on instance..."
ssh $SSH_OPTS ubuntu@"$PUBLIC_IP" << 'REMOTE'
  mkdir -p ~/wip
  cd ~/wip
  tar xzf ~/wid-platform.tar.gz
  rm ~/wid-platform.tar.gz
REMOTE
ok "Code extracted"

# ═══════════════════════════════════════════════════════════════
# PHASE 5: Start Central Control Plane
# ═══════════════════════════════════════════════════════════════

banner "PHASE 5: START CENTRAL CONTROL PLANE"

step "Building and starting services..."
ssh $SSH_OPTS ubuntu@"$PUBLIC_IP" << 'REMOTE'
  cd ~/wip

  # Need to use sudo for docker until next login refreshes groups
  sudo docker compose -f deploy/central/docker-compose.central.yml up --build -d 2>&1 | tail -20

  echo ""
  echo "Waiting for services to be healthy..."

  # Wait for postgres
  for i in $(seq 1 30); do
    if sudo docker compose -f deploy/central/docker-compose.central.yml exec -T postgres pg_isready -U wid_user -d workload_identity &>/dev/null; then
      echo "  ✓ PostgreSQL is ready"
      break
    fi
    sleep 3
  done

  # Wait for policy engine
  for i in $(seq 1 30); do
    if curl -sf http://localhost:3001/health &>/dev/null; then
      echo "  ✓ Policy Engine is healthy"
      break
    fi
    sleep 3
  done

  # Wait for relay
  for i in $(seq 1 20); do
    if curl -sf http://localhost:3005/health &>/dev/null; then
      echo "  ✓ Relay (hub) is healthy"
      break
    fi
    sleep 3
  done

  # Wait for web UI
  for i in $(seq 1 20); do
    if curl -sf http://localhost:3100 &>/dev/null; then
      echo "  ✓ Web UI is serving"
      break
    fi
    sleep 3
  done

  # Trigger initial discovery
  sleep 5
  curl -sf -X POST http://localhost:3004/api/v1/workloads/scan &>/dev/null || true
  echo "  ✓ Discovery scan triggered"

  echo ""
  echo "All services started!"
REMOTE

# ═══════════════════════════════════════════════════════════════
# PHASE 6: Verify
# ═══════════════════════════════════════════════════════════════

banner "PHASE 6: VERIFICATION"

step "Checking services from outside..."

sleep 5

# Check each service
for svc_port in "Policy Engine:3001" "Relay:3005" "Token Service:3000"; do
  svc=$(echo "$svc_port" | cut -d: -f1)
  port=$(echo "$svc_port" | cut -d: -f2)
  if curl -sf "http://$PUBLIC_IP:$port/health" &>/dev/null; then
    ok "$svc is reachable"
  else
    warn "$svc not yet reachable on port $port (may need a moment)"
  fi
done

if curl -sf "http://$PUBLIC_IP:3100" &>/dev/null; then
  ok "Web UI is reachable"
else
  warn "Web UI not yet reachable (Vite dev server may need a moment)"
fi

# Save deployment info
DEPLOY_INFO="$PROJECT_DIR/deploy/.aws-deployment"
cat > "$DEPLOY_INFO" << EOF
# WID Platform — AWS Deployment Info
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
REGION=$REGION
KEY_FILE=$KEY_FILE
SG_ID=$SG_ID
KEY_NAME=$KEY_NAME
CENTRAL_URL=http://$PUBLIC_IP:3005
EOF

# Clean up temp archive
rm -f "$ARCHIVE"

# ═══════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════

banner "DEPLOYMENT COMPLETE"

echo -e "
  ${GREEN}Your WID Central Control Plane is running on AWS!${NC}

  ┌─────────────────────────────────────────────────────────────┐
  │  AWS INSTANCE                                               │
  │                                                             │
  │  Instance:     ${CYAN}$INSTANCE_ID${NC}
  │  Public IP:    ${CYAN}$PUBLIC_IP${NC}
  │  Region:       ${CYAN}$REGION${NC}
  │  Type:         ${CYAN}$INSTANCE_TYPE${NC}
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  URLS                                                       │
  │                                                             │
  │  Web UI:       ${CYAN}http://$PUBLIC_IP:3100${NC}
  │  Policy Engine:${CYAN} http://$PUBLIC_IP:3001/health${NC}
  │  Relay (hub):  ${CYAN}http://$PUBLIC_IP:3005/health${NC}
  │  Token Service:${CYAN} http://$PUBLIC_IP:3000/health${NC}
  │  Environments: ${CYAN}http://$PUBLIC_IP:3005/api/v1/relay/environments${NC}
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  CONNECT YOUR LOCAL ENVIRONMENT                             │
  │                                                             │
  │  ${YELLOW}CENTRAL_URL=http://$PUBLIC_IP:3005 \\${NC}
  │  ${YELLOW}  docker compose -f deploy/local/docker-compose.local.yml \\${NC}
  │  ${YELLOW}  up --build${NC}
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  SSH ACCESS                                                 │
  │                                                             │
  │  ${YELLOW}ssh -i $KEY_FILE ubuntu@$PUBLIC_IP${NC}
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  TEARDOWN                                                   │
  │                                                             │
  │  ${YELLOW}./deploy/aws-teardown.sh${NC}
  │  or manually:                                               │
  │  ${YELLOW}aws ec2 terminate-instances --instance-ids $INSTANCE_ID${NC}
  │                                                             │
  └─────────────────────────────────────────────────────────────┘
"

echo -e "${GREEN}Deployment info saved to: deploy/.aws-deployment${NC}"
echo ""
