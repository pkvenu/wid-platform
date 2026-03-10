#!/bin/bash
# =============================================================================
# WID Platform — One-Click GCP Deployment
# =============================================================================
# Usage: ./deploy-gcp.sh
#
# Deploys the entire WID platform to GCP Cloud Run:
#   1. Enables GCP APIs
#   2. Terraform apply (VPC, Cloud SQL, Artifact Registry, Secrets, Cloud Run, LB)
#   3. Builds & pushes Docker images (linux/amd64)
#   4. Runs database migrations via Cloud SQL (temporary public IP)
#   5. Updates inter-service URLs
#   6. Verifies all health checks
#   7. Prints access URLs
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - gcloud auth application-default login (for Terraform)
#   - terraform >= 1.5 installed
#   - docker running
#   - psql installed (brew install libpq && brew link --force libpq)
#
# =============================================================================

set -e

# ── Configuration ─────────────────────────────────────────────
PROJECT_ID="${GCP_PROJECT_ID:-wid-platform}"
REGION="${GCP_REGION:-us-central1}"
ENVIRONMENT="${WID_ENVIRONMENT:-dev}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR"
DB_NAME="workload_identity"
DB_USER="wid_admin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Helper functions ──────────────────────────────────────────
log()   { echo -e "${BLUE}[WID]${NC} $1"; }
ok()    { echo -e "${GREEN}[✅]${NC} $1"; }
warn()  { echo -e "${YELLOW}[⚠️]${NC} $1"; }
err()   { echo -e "${RED}[❌]${NC} $1"; exit 1; }
step()  { echo -e "\n${CYAN}═══════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════${NC}\n"; }

timer_start() { STEP_START=$(date +%s); }
timer_end()   { local elapsed=$(($(date +%s) - STEP_START)); echo -e "  ${BLUE}⏱  ${elapsed}s${NC}"; }

# ── Preflight checks ─────────────────────────────────────────
step "Step 0: Preflight checks"

command -v gcloud >/dev/null 2>&1    || err "gcloud CLI not found. Install: brew install --cask google-cloud-sdk"
command -v terraform >/dev/null 2>&1 || err "terraform not found. Install: brew install terraform"
command -v docker >/dev/null 2>&1    || err "docker not found. Install: brew install --cask docker"
command -v psql >/dev/null 2>&1      || err "psql not found. Install: brew install libpq && brew link --force libpq"
docker info >/dev/null 2>&1          || err "Docker daemon not running. Start Docker Desktop."

# Verify GCP auth
gcloud config get-value project >/dev/null 2>&1 || err "Not authenticated. Run: gcloud auth login"

# Set project
gcloud config set project "$PROJECT_ID" --quiet
ok "Project: $PROJECT_ID | Region: $REGION | Environment: $ENVIRONMENT"

# ── Step 0.5: Pre-deploy security scan ──────────────────────
if [ -f "$PROJECT_ROOT/scripts/security-scan.sh" ]; then
  step "Step 0.5: Pre-deploy security scan"
  timer_start

  if "$PROJECT_ROOT/scripts/security-scan.sh" --skip-trivy; then
    ok "Security scan passed"
  else
    err "Security scan failed. Fix critical issues before deploying."
  fi

  timer_end
fi

# ── Step 1: Enable GCP APIs ──────────────────────────────────
step "Step 1: Enable GCP APIs"
timer_start

APIS=(
  run.googleapis.com
  sqladmin.googleapis.com
  artifactregistry.googleapis.com
  cloudbuild.googleapis.com
  servicenetworking.googleapis.com
  compute.googleapis.com
  secretmanager.googleapis.com
  vpcaccess.googleapis.com
)

log "Enabling ${#APIS[@]} APIs..."
gcloud services enable "${APIS[@]}" --project="$PROJECT_ID" --quiet
ok "All APIs enabled"
timer_end

# ── Step 2: Terraform Init & Apply ───────────────────────────
step "Step 2: Terraform — Infrastructure"
timer_start

cd "$TERRAFORM_DIR"

log "Initializing Terraform..."
terraform init -input=false -no-color > /dev/null 2>&1

log "Applying infrastructure (VPC, Cloud SQL, Artifact Registry, Secrets, Cloud Run, LB)..."
log "This takes ~10-15 minutes on first run (Cloud SQL is slow)..."
terraform apply -var-file="${ENVIRONMENT}.tfvars" -auto-approve -input=false

# Capture outputs
ALB_IP=$(terraform output -raw load_balancer_ip 2>/dev/null || echo "pending")
REGISTRY=$(terraform output -raw artifact_registry)
CLOUD_RUN_URLS=$(terraform output -json cloud_run_urls 2>/dev/null || echo "{}")

ok "Infrastructure deployed"
timer_end

# ── Step 3: Build & Push Docker Images ───────────────────────
step "Step 3: Build & push Docker images (linux/amd64)"
timer_start

cd "$PROJECT_ROOT"

log "Authenticating Docker to Artifact Registry..."
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet 2>/dev/null

declare -A SERVICE_PATHS=(
  ["policy-engine"]="services/policy-sync-service"
  ["token-service"]="services/token-service"
  ["credential-broker"]="services/credential-broker"
  ["discovery-service"]="services/discovery-service"
  ["relay-service"]="services/relay-service"
  ["web-ui"]="web/workload-identity-manager"
)

for service in "${!SERVICE_PATHS[@]}"; do
  path="${SERVICE_PATHS[$service]}"
  if [ -d "$path" ]; then
    log "Building $service from $path..."
    docker build --platform linux/amd64 -t "$REGISTRY/$service:latest" "$path" --quiet
    log "Pushing $service..."
    docker push "$REGISTRY/$service:latest" --quiet
    ok "$service pushed"
  else
    warn "Skipping $service — directory $path not found"
  fi
done

ok "All images built and pushed"
timer_end

# ── Step 4: Re-apply Terraform (Cloud Run needs images) ──────
step "Step 4: Terraform — Deploy Cloud Run services"
timer_start

cd "$TERRAFORM_DIR"
log "Re-applying to create/update Cloud Run services with pushed images..."
terraform apply -var-file="${ENVIRONMENT}.tfvars" -auto-approve -input=false

# Re-capture outputs (Cloud Run URLs now available)
ALB_IP=$(terraform output -raw load_balancer_ip 2>/dev/null || echo "pending")
CLOUD_RUN_URLS=$(terraform output -json cloud_run_urls 2>/dev/null || echo "{}")

ok "Cloud Run services deployed"
timer_end

# ── Step 5: Database Migration ────────────────────────────────
step "Step 5: Database migration"
timer_start

INIT_SQL="$PROJECT_ROOT/database/init.sql"

if [ ! -f "$INIT_SQL" ]; then
  warn "No init.sql found at $INIT_SQL — skipping migration"
else
  log "Temporarily enabling Cloud SQL public IP for migration..."

  # Get public IPv4
  MY_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s https://api.ipify.org 2>/dev/null)
  if [ -z "$MY_IP" ]; then
    warn "Could not determine public IP. Skipping DB migration."
    warn "Run manually: psql \$DATABASE_URL -f database/init.sql"
  else
    INSTANCE_NAME="wid-${ENVIRONMENT}-postgres"

    # Enable public IP
    gcloud sql instances patch "$INSTANCE_NAME" \
      --assign-ip \
      --authorized-networks="$MY_IP/32" \
      --project="$PROJECT_ID" \
      --quiet 2>/dev/null

    log "Waiting for Cloud SQL to update..."
    sleep 30

    # Get public IP
    PUBLIC_IP=$(gcloud sql instances describe "$INSTANCE_NAME" \
      --project="$PROJECT_ID" \
      --format="value(ipAddresses[0].ipAddress)" 2>/dev/null)

    # Get DB password from secret
    DB_URL=$(gcloud secrets versions access latest \
      --secret="wid-${ENVIRONMENT}-database-url" \
      --project="$PROJECT_ID" 2>/dev/null)
    DB_PASS=$(echo "$DB_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p')

    if [ -n "$PUBLIC_IP" ] && [ -n "$DB_PASS" ]; then
      log "Running migration against $PUBLIC_IP..."
      PGPASSWORD="$DB_PASS" psql -h "$PUBLIC_IP" -U "$DB_USER" -d "$DB_NAME" -f "$INIT_SQL" 2>&1 | tail -5

      ok "Database migration complete"
    else
      warn "Could not get Cloud SQL public IP or password. Migration skipped."
    fi

    # Disable public IP
    log "Disabling Cloud SQL public IP..."
    gcloud sql instances patch "$INSTANCE_NAME" \
      --no-assign-ip \
      --clear-authorized-networks \
      --project="$PROJECT_ID" \
      --quiet 2>/dev/null

    ok "Cloud SQL public IP disabled"
  fi
fi

timer_end

# ── Step 6: Health Checks ─────────────────────────────────────
step "Step 6: Health checks"
timer_start

# Extract Cloud Run URLs
declare -A CR_URLS
for service in policy-engine relay-service web-ui token-service credential-broker discovery-service; do
  url=$(echo "$CLOUD_RUN_URLS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$service',''))" 2>/dev/null || echo "")
  CR_URLS[$service]="$url"
done

HEALTHY=0
TOTAL=0

# Check public services
for service in policy-engine relay-service web-ui; do
  url="${CR_URLS[$service]}"
  if [ -n "$url" ]; then
    TOTAL=$((TOTAL + 1))
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url/health" --max-time 10 2>/dev/null || echo "000")
    if [ "$status" = "200" ]; then
      ok "$service — healthy ($url)"
      HEALTHY=$((HEALTHY + 1))
    else
      warn "$service — HTTP $status ($url)"
    fi
  fi
done

# Check internal services (expect 403 from outside — that's correct)
for service in token-service credential-broker discovery-service; do
  url="${CR_URLS[$service]}"
  if [ -n "$url" ]; then
    TOTAL=$((TOTAL + 1))
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url/health" --max-time 10 2>/dev/null || echo "000")
    if [ "$status" = "403" ]; then
      ok "$service — secured (403 = IAM auth required, correct)"
      HEALTHY=$((HEALTHY + 1))
    elif [ "$status" = "200" ]; then
      ok "$service — healthy ($url)"
      HEALTHY=$((HEALTHY + 1))
    else
      warn "$service — HTTP $status ($url)"
    fi
  fi
done

# Check LB
if [ "$ALB_IP" != "pending" ]; then
  LB_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$ALB_IP/health" --max-time 10 2>/dev/null || echo "000")
  if [ "$LB_STATUS" = "200" ]; then
    ok "Load Balancer — healthy (http://$ALB_IP)"
  else
    warn "Load Balancer — HTTP $LB_STATUS (may take 5-10 min to propagate)"
  fi
fi

timer_end

# ── Step 7: Demo Agents (deployed separately) ────────────────
step "Step 7: Demo agents"
log "Demo agents are deployed from the separate wid-demo-agents repo."
log "Run: cd ../wid-demo-agents && ./deploy/deploy.sh --platform=cloudrun --project=$PROJECT_ID"

# ── Step 8: IAM grants for discovery ──────────────────────────
step "Step 8: IAM grants for discovery"
timer_start

SA="wid-${ENVIRONMENT}-run@${PROJECT_ID}.iam.gserviceaccount.com"

log "Granting roles/run.viewer to $SA..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA" \
  --role="roles/run.viewer" \
  --quiet 2>/dev/null && ok "run.viewer granted" || warn "run.viewer grant failed (may already exist)"

timer_end

# ── Summary ───────────────────────────────────────────────────
step "Deployment Complete!"

echo -e "${GREEN}  Core Services: $HEALTHY/$TOTAL healthy${NC}"
echo ""
echo -e "  ${CYAN}Web UI:${NC}         http://$ALB_IP"
echo -e "  ${CYAN}Relay API:${NC}      http://$ALB_IP/api/v1/relay/environments"
echo -e "  ${CYAN}Policy API:${NC}     http://$ALB_IP/api/v1/policies"
echo -e "  ${CYAN}Health:${NC}         http://$ALB_IP/health"
echo ""
echo -e "  ${CYAN}Direct Cloud Run URLs:${NC}"
for service in policy-engine relay-service web-ui token-service credential-broker discovery-service; do
  url="${CR_URLS[$service]}"
  if [ -n "$url" ]; then
    echo -e "    $service: $url"
  fi
done
echo ""
echo -e "  ${CYAN}Artifact Registry:${NC} $REGISTRY"
echo ""
echo -e "  ${CYAN}Demo Agents:${NC} Deploy separately from wid-demo-agents repo:"
echo -e "    cd ../wid-demo-agents && ./deploy/deploy.sh --platform=cloudrun --project=$PROJECT_ID"
echo ""
echo -e "  ${YELLOW}To destroy:${NC} cd $TERRAFORM_DIR && terraform destroy -var-file=${ENVIRONMENT}.tfvars"
echo ""
