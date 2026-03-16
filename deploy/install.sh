#!/bin/bash
# =============================================================================
# WID Platform — Clean Install Script
# =============================================================================
#
# Deploys the Workload Identity Defense (WID) Platform in hub-and-spoke mode:
#   Phase 1: Central control plane (simulated AWS on this machine)
#   Phase 2: Local data plane with sample workloads + Edge Gateways
#   Phase 3: Verify end-to-end federation
#
# Usage:
#   chmod +x deploy/install.sh
#   ./deploy/install.sh
#
# Prerequisites:
#   - Docker and Docker Compose v2
#   - Node.js 18+ (for web UI dev server)
#   - curl and jq
#
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CENTRAL_DIR="$SCRIPT_DIR/central"
LOCAL_DIR="$SCRIPT_DIR/local"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
  echo ""
  echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
  echo ""
}

print_step() {
  echo -e "${CYAN}  ▶ $1${NC}"
}

print_ok() {
  echo -e "${GREEN}  ✓ $1${NC}"
}

print_warn() {
  echo -e "${YELLOW}  ⚠ $1${NC}"
}

print_fail() {
  echo -e "${RED}  ✗ $1${NC}"
}

wait_for_service() {
  local url=$1
  local name=$2
  local max_attempts=${3:-30}
  local attempt=0

  while [ $attempt -lt $max_attempts ]; do
    if curl -sf "$url" > /dev/null 2>&1; then
      print_ok "$name is healthy"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  print_fail "$name failed to start (tried $max_attempts times)"
  return 1
}

# ═══════════════════════════════════════════════════════════════
# Pre-flight checks
# ═══════════════════════════════════════════════════════════════

print_banner "WORKLOAD IDENTITY PLATFORM — CLEAN INSTALL"

echo "This script will deploy:"
echo ""
echo "  Phase 1: Central Control Plane"
echo "    • PostgreSQL, Vault, Policy Engine, Token Service"
echo "    • Credential Broker, Discovery Service, WID Relay"
echo "    • Web UI (unified dashboard)"
echo ""
echo "  Phase 2: Local Data Plane"
echo "    • WID Relay (connects to central)"
echo "    • Sample frontend + Edge Gateway sidecar"
echo "    • Sample backend + Edge Gateway sidecar"
echo ""
echo "  No Istio or service mesh required."
echo ""

print_step "Checking prerequisites..."

command -v docker >/dev/null 2>&1 || { print_fail "Docker not found. Install: https://docs.docker.com/get-docker/"; exit 1; }
command -v curl >/dev/null 2>&1 || { print_fail "curl not found"; exit 1; }
docker info > /dev/null 2>&1 || { print_fail "Docker daemon not running. Start Docker Desktop."; exit 1; }
print_ok "Docker is running"

if command -v jq >/dev/null 2>&1; then
  print_ok "jq is available"
else
  print_warn "jq not found — install for prettier output (brew install jq)"
fi

# ═══════════════════════════════════════════════════════════════
# PHASE 1: Central Control Plane
# ═══════════════════════════════════════════════════════════════

print_banner "PHASE 1: CENTRAL CONTROL PLANE"

print_step "Stopping any existing containers..."
docker compose -f "$CENTRAL_DIR/docker-compose.central.yml" down 2>/dev/null || true
docker compose -f "$LOCAL_DIR/docker-compose.local.yml" down 2>/dev/null || true

print_step "Starting central control plane..."
docker compose -f "$CENTRAL_DIR/docker-compose.central.yml" up --build -d 2>&1 | tail -5

echo ""
print_step "Waiting for services to be healthy..."
echo ""

wait_for_service "http://localhost:5432" "PostgreSQL" 20 2>/dev/null || \
  wait_for_service "http://localhost:3001/health" "PostgreSQL (via policy-engine)" 30

wait_for_service "http://localhost:3001/health" "Policy Engine"
wait_for_service "http://localhost:3000/health" "Token Service"
wait_for_service "http://localhost:3005/health" "Relay (central hub)"

echo ""
print_step "Running database discovery..."
sleep 5  # Give discovery service time to start and scan
curl -sf -X POST http://localhost:3004/api/v1/workloads/scan > /dev/null 2>&1 || true

CENTRAL_URL="http://host.docker.internal:3005"
print_ok "Central control plane is running"
echo ""
echo -e "  ${GREEN}Policy Engine:  http://localhost:3001/health${NC}"
echo -e "  ${GREEN}Relay (hub):    http://localhost:3005/health${NC}"
echo -e "  ${GREEN}Web UI:         http://localhost:3100${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════
# PHASE 2: Local Data Plane
# ═══════════════════════════════════════════════════════════════

print_banner "PHASE 2: LOCAL DATA PLANE"

print_step "Starting local relay + sample workloads with Edge Gateways..."

# On Mac/Windows Docker Desktop, containers can reach host via host.docker.internal
# On Linux, use the docker bridge IP
if docker info 2>/dev/null | grep -q "Operating System:.*Docker Desktop\|Operating System:.*macOS\|Operating System:.*Windows"; then
  CENTRAL_URL="http://host.docker.internal:3005"
else
  # Linux: use docker bridge gateway IP
  CENTRAL_URL="http://$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'):3005"
fi

print_step "Central URL for local relay: $CENTRAL_URL"

CENTRAL_URL="$CENTRAL_URL" docker compose -f "$LOCAL_DIR/docker-compose.local.yml" up --build -d 2>&1 | tail -5

echo ""
print_step "Waiting for local services..."
echo ""

wait_for_service "http://localhost:3006/health" "Local Relay" 20 || {
  # Relay port conflict with central — use 3006 or check
  print_warn "Port 3005 may conflict with central relay on same machine"
  print_warn "For true hybrid, run central and local on different machines"
}

sleep 3
wait_for_service "http://localhost:15000/healthz" "Frontend Edge Gateway" 20
wait_for_service "http://localhost:15010/healthz" "Backend Edge Gateway" 20

echo ""
print_ok "Local data plane is running"
echo ""
echo -e "  ${GREEN}Local Relay:        http://localhost:3006/api/v1/relay/status${NC}"
echo -e "  ${GREEN}Frontend (via GW):  http://localhost:8080${NC}"
echo -e "  ${GREEN}Backend (via GW):   http://localhost:8081${NC}"
echo -e "  ${GREEN}Frontend GW Admin:  http://localhost:15000/healthz${NC}"
echo -e "  ${GREEN}Backend GW Admin:   http://localhost:15010/healthz${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════
# PHASE 3: Verify End-to-End
# ═══════════════════════════════════════════════════════════════

print_banner "PHASE 3: VERIFICATION"

echo ""
print_step "1. Testing frontend through Edge Gateway..."
FRONTEND_RESPONSE=$(curl -sf http://localhost:8080/ 2>/dev/null || echo "FAILED")
if echo "$FRONTEND_RESPONSE" | grep -q "Sample Frontend"; then
  print_ok "Frontend accessible through Edge Gateway"
else
  print_warn "Frontend not responding yet (may still be starting)"
fi

echo ""
print_step "2. Testing backend through Edge Gateway..."
BACKEND_RESPONSE=$(curl -sf http://localhost:8081/ 2>/dev/null || echo "FAILED")
if echo "$BACKEND_RESPONSE" | grep -q "backend"; then
  print_ok "Backend accessible through Edge Gateway"
else
  print_warn "Backend not responding yet (may still be starting)"
fi

echo ""
print_step "3. Checking relay federation..."
RELAY_STATUS=$(curl -sf http://localhost:3006/health 2>/dev/null || echo "{}")
CENTRAL_REACHABLE=$(echo "$RELAY_STATUS" | grep -o '"central_reachable":[a-z]*' | cut -d: -f2 || echo "unknown")
if [ "$CENTRAL_REACHABLE" = "true" ]; then
  print_ok "Local relay connected to central control plane"
else
  print_warn "Local relay not yet connected to central (expected if both on same machine)"
  print_warn "In production, central and local run on separate machines"
fi

echo ""
print_step "4. Generating sample traffic..."
for i in $(seq 1 5); do
  curl -sf http://localhost:8080/ > /dev/null 2>&1 || true
  curl -sf http://localhost:8081/ > /dev/null 2>&1 || true
done
print_ok "Sent 10 requests through Edge Gateways"

echo ""
print_step "5. Checking gateway metrics..."
GW_METRICS=$(curl -sf http://localhost:15000/metrics 2>/dev/null || echo "{}")
if echo "$GW_METRICS" | grep -q "total"; then
  print_ok "Edge Gateway is recording decisions"
else
  print_warn "No metrics yet — gateway may need a moment"
fi

# ═══════════════════════════════════════════════════════════════
# COMPLETE
# ═══════════════════════════════════════════════════════════════

print_banner "INSTALLATION COMPLETE"

echo "
  ${GREEN}Your Workload Identity Defense (WID) Platform is running!${NC}

  ┌─────────────────────────────────────────────────────────────┐
  │  CENTRAL CONTROL PLANE                                      │
  │                                                             │
  │  Web UI:          ${CYAN}http://localhost:3100${NC}                    │
  │  Policy Engine:   ${CYAN}http://localhost:3001/health${NC}              │
  │  Token Service:   ${CYAN}http://localhost:3000/health${NC}              │
  │  Discovery:       ${CYAN}http://localhost:3004/api/v1/stats${NC}        │
  │  Relay (hub):     ${CYAN}http://localhost:3005/health${NC}              ${NC}              │
  │  Environments:    ${CYAN}http://localhost:3005/api/v1/relay/environments${NC}
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  LOCAL DATA PLANE (no service mesh!)                        │
  │                                                             │
  │  Sample Frontend: ${CYAN}http://localhost:8080${NC}                     │
  │  Sample Backend:  ${CYAN}http://localhost:8081${NC}                     │
  │  Frontend GW:     ${CYAN}http://localhost:15000/metrics${NC}             │
  │  Backend GW:      ${CYAN}http://localhost:15010/metrics${NC}             │
  │                                                             │
  ├─────────────────────────────────────────────────────────────┤
  │  NEXT STEPS                                                 │
  │                                                             │
  │  1. Open Web UI:  ${CYAN}http://localhost:3100${NC}                     │
  │     • Workloads page → see discovered NHIs                  │
  │     • Policies page → create access policies                │
  │     • Authorization → see live decisions                    │
  │                                                             │
  │  2. Create a policy:                                        │
  │     curl -X POST http://localhost:3001/api/v1/policies \\    │
  │       -H 'Content-Type: application/json' \\                │
  │       -d '{\"name\":\"frontend-to-backend\", ...}'            │
  │                                                             │
  │  3. Switch to enforce mode:                                 │
  │     curl -X POST http://localhost:15000/mode \\              │
  │       -H 'Content-Type: application/json' \\                │
  │       -d '{\"mode\":\"enforce\"}'                             │
  │                                                             │
  │  4. Add another environment:                                │
  │     CENTRAL_URL=http://<AWS_IP>:3005 \\                     │
  │     docker compose -f deploy/local/docker-compose.local.yml \\│
  │       up --build                                            │
  │                                                             │
  └─────────────────────────────────────────────────────────────┘

  ${YELLOW}Architecture (no service mesh required):${NC}

    Central (AWS)                Local (Docker)
    ┌────────────────┐          ┌──────────────────────┐
    │ Policy Engine  │◄─sync───│ WID Relay            │
    │ Token Service  │          │  (policy cache +     │
    │ Web UI         │◄─audit──│   audit forwarder)   │
    │ PostgreSQL     │          │         │            │
    └────────────────┘          │    ┌────▼─────┐      │
                                │    │ Edge     │      │
                                │    │ Gateway  │      │
                                │    │(sidecar) │      │
                                │    └────┬─────┘      │
                                │    ┌────▼─────┐      │
                                │    │ Your App │      │
                                │    └──────────┘      │
                                └──────────────────────┘
"

echo -e "${YELLOW}To stop everything:${NC}"
echo "  docker compose -f deploy/central/docker-compose.central.yml down"
echo "  docker compose -f deploy/local/docker-compose.local.yml down"
echo ""
echo -e "${YELLOW}To stop and remove all data:${NC}"
echo "  docker compose -f deploy/central/docker-compose.central.yml down -v"
echo "  docker compose -f deploy/local/docker-compose.local.yml down"
echo ""
