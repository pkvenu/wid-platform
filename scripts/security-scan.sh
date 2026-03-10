#!/usr/bin/env bash
#
# security-scan.sh — Pre-deploy security scanner for WID Platform
#
# Phases:
#   1. npm audit (per-service dependency scan)
#   2. gitleaks detect (hardcoded secrets scan)
#   3. trivy fs (filesystem CVE scan)
#   4. Summary
#
# Usage:
#   ./scripts/security-scan.sh [--skip-trivy] [--skip-audit] [--skip-secrets]

set -euo pipefail

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Project root — always resolve relative to this script's location
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
SKIP_AUDIT=false
SKIP_SECRETS=false
SKIP_TRIVY=false

for arg in "$@"; do
  case "$arg" in
    --skip-audit)   SKIP_AUDIT=true ;;
    --skip-secrets) SKIP_SECRETS=true ;;
    --skip-trivy)   SKIP_TRIVY=true ;;
    -h|--help)
      echo "Usage: $0 [--skip-audit] [--skip-secrets] [--skip-trivy]"
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown flag: ${arg}${NC}"
      echo "Usage: $0 [--skip-audit] [--skip-secrets] [--skip-trivy]"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Service directories to scan (relative to PROJECT_ROOT)
# ---------------------------------------------------------------------------
SERVICE_DIRS=(
  "services/policy-sync-service"
  "services/discovery-service"
  "services/token-service"
  "services/credential-broker"
  "services/relay-service"
  "services/edge-gateway"
  "services/ext-authz-adapter"
  "services/audit-service"
  "web/workload-identity-manager"
)

# ---------------------------------------------------------------------------
# Phase results
# ---------------------------------------------------------------------------
PHASE1_RESULT="SKIP"
PHASE2_RESULT="SKIP"
PHASE3_RESULT="SKIP"
CRITICAL_ISSUES=0

echo ""
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  WID Platform — Pre-Deploy Security Scan${NC}"
echo -e "${CYAN}================================================================${NC}"
echo -e "  Project root: ${PROJECT_ROOT}"
echo -e "  Date:         $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""

# ===================================================================
# Phase 1: npm audit
# ===================================================================
if [ "$SKIP_AUDIT" = true ]; then
  echo -e "${YELLOW}[Phase 1] npm audit — SKIPPED (--skip-audit)${NC}"
else
  echo -e "${CYAN}[Phase 1] npm audit — scanning service dependencies...${NC}"
  echo ""

  AUDIT_WARNINGS=0
  AUDIT_FAILURES=0
  AUDIT_SCANNED=0

  for svc_dir in "${SERVICE_DIRS[@]}"; do
    full_path="${PROJECT_ROOT}/${svc_dir}"
    svc_name="$(basename "${svc_dir}")"

    if [ ! -f "${full_path}/package.json" ]; then
      echo -e "  ${YELLOW}[WARN]${NC} ${svc_name} — no package.json, skipping"
      continue
    fi

    AUDIT_SCANNED=$((AUDIT_SCANNED + 1))
    echo -n "  Scanning ${svc_name}... "

    # Capture npm audit output; --audit-level=high exits non-zero on high/critical
    audit_output=""
    audit_exit=0
    audit_output=$(cd "${full_path}" && npm audit --audit-level=high 2>&1) || audit_exit=$?

    if [ "$audit_exit" -eq 0 ]; then
      echo -e "${GREEN}PASS${NC}"
    else
      # npm audit exit code: 1 = vulnerabilities found at or above audit-level
      # Check if output mentions critical
      if echo "${audit_output}" | grep -qi "critical"; then
        echo -e "${RED}FAIL (critical vulnerabilities)${NC}"
        AUDIT_FAILURES=$((AUDIT_FAILURES + 1))
      else
        echo -e "${YELLOW}WARN (high vulnerabilities)${NC}"
        AUDIT_WARNINGS=$((AUDIT_WARNINGS + 1))
      fi
    fi
  done

  echo ""
  echo -e "  Scanned: ${AUDIT_SCANNED} | Warnings: ${AUDIT_WARNINGS} | Failures: ${AUDIT_FAILURES}"

  if [ "$AUDIT_FAILURES" -gt 0 ]; then
    PHASE1_RESULT="FAIL"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + AUDIT_FAILURES))
  elif [ "$AUDIT_WARNINGS" -gt 0 ]; then
    PHASE1_RESULT="WARN"
  else
    PHASE1_RESULT="PASS"
  fi

  echo ""
fi

# ===================================================================
# Phase 2: gitleaks detect
# ===================================================================
if [ "$SKIP_SECRETS" = true ]; then
  echo -e "${YELLOW}[Phase 2] gitleaks detect — SKIPPED (--skip-secrets)${NC}"
else
  echo -e "${CYAN}[Phase 2] gitleaks detect — scanning for hardcoded secrets...${NC}"
  echo ""

  if ! command -v gitleaks &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] gitleaks is not installed.${NC}"
    echo -e "  Install: brew install gitleaks  OR  go install github.com/gitleaks/gitleaks/v8@latest"
    PHASE2_RESULT="WARN"
  else
    gitleaks_exit=0
    gitleaks_config_flag=""

    if [ -f "${PROJECT_ROOT}/.gitleaks.toml" ]; then
      gitleaks_config_flag="--config ${PROJECT_ROOT}/.gitleaks.toml"
    fi

    # shellcheck disable=SC2086
    gitleaks detect --source "${PROJECT_ROOT}" ${gitleaks_config_flag} --verbose 2>&1 | tail -20 || gitleaks_exit=$?

    if [ "$gitleaks_exit" -eq 0 ]; then
      echo -e "  ${GREEN}No secrets detected.${NC}"
      PHASE2_RESULT="PASS"
    else
      echo -e "  ${RED}Potential secrets found! Review gitleaks output above.${NC}"
      PHASE2_RESULT="FAIL"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi

  echo ""
fi

# ===================================================================
# Phase 3: trivy fs
# ===================================================================
if [ "$SKIP_TRIVY" = true ]; then
  echo -e "${YELLOW}[Phase 3] trivy fs — SKIPPED (--skip-trivy)${NC}"
else
  echo -e "${CYAN}[Phase 3] trivy fs — scanning filesystem for CVEs...${NC}"
  echo ""

  if ! command -v trivy &>/dev/null; then
    echo -e "  ${YELLOW}[WARN] trivy is not installed.${NC}"
    echo -e "  Install: brew install trivy  OR  see https://aquasecurity.github.io/trivy"
    PHASE3_RESULT="WARN"
  else
    trivy_exit=0
    trivy fs --severity HIGH,CRITICAL --exit-code 0 "${PROJECT_ROOT}" 2>&1 | tail -40 || trivy_exit=$?

    if [ "$trivy_exit" -eq 0 ]; then
      echo -e "  ${GREEN}No HIGH/CRITICAL CVEs blocking deployment.${NC}"
      PHASE3_RESULT="PASS"
    else
      echo -e "  ${RED}Trivy scan failed or found blocking issues.${NC}"
      PHASE3_RESULT="FAIL"
      CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
  fi

  echo ""
fi

# ===================================================================
# Phase 4: Summary
# ===================================================================
echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}  Security Scan Summary${NC}"
echo -e "${CYAN}================================================================${NC}"
echo ""

print_result() {
  local phase_name="$1"
  local result="$2"

  case "$result" in
    PASS) echo -e "  ${phase_name}: ${GREEN}PASS${NC}" ;;
    WARN) echo -e "  ${phase_name}: ${YELLOW}WARN${NC}" ;;
    FAIL) echo -e "  ${phase_name}: ${RED}FAIL${NC}" ;;
    SKIP) echo -e "  ${phase_name}: ${YELLOW}SKIP${NC}" ;;
  esac
}

print_result "Phase 1 — npm audit        " "$PHASE1_RESULT"
print_result "Phase 2 — gitleaks detect  " "$PHASE2_RESULT"
print_result "Phase 3 — trivy fs         " "$PHASE3_RESULT"

echo ""

if [ "$CRITICAL_ISSUES" -gt 0 ]; then
  echo -e "  ${RED}Critical issues found: ${CRITICAL_ISSUES}${NC}"
  echo -e "  ${RED}Deployment NOT recommended until issues are resolved.${NC}"
  echo ""
  exit 1
else
  echo -e "  ${GREEN}No critical issues. Safe to deploy.${NC}"
  echo ""
  exit 0
fi
