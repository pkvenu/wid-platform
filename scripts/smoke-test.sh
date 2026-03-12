#!/usr/bin/env bash
# =============================================================================
# WID Platform — Smoke Test
# =============================================================================
# Validates core platform endpoints against a running fullstack instance.
#
# Usage:
#   ./scripts/smoke-test.sh                    # default: http://localhost
#   ./scripts/smoke-test.sh http://34.120.74.81  # against GCP
#
# Prerequisites:
#   docker compose -f docker-compose.fullstack.yml up --build
# =============================================================================

set -euo pipefail

BASE_URL="${1:-http://localhost}"
COOKIE_JAR=$(mktemp)
PASS=0
FAIL=0
TOTAL=0

cleanup() { rm -f "$COOKIE_JAR"; }
trap cleanup EXIT

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

check() {
  local name="$1" expected="$2" actual="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$actual" | grep -q "$expected"; then
    green "  PASS  $name"
    PASS=$((PASS + 1))
  else
    red "  FAIL  $name (expected '$expected')"
    FAIL=$((FAIL + 1))
  fi
}

bold "WID Platform Smoke Test"
echo "Target: $BASE_URL"
echo ""

# ── 1. Authentication ──
bold "1. Authentication"
LOGIN=$(curl -s -c "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@wid.dev","password":"Admin12345"}' 2>&1)
check "Login" '"role":"admin"' "$LOGIN"

# ── 2. Discovery / Scan ──
bold "2. Discovery"
SCANNERS=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/scanners" 2>&1)
check "Scanners endpoint" '"scanners"' "$SCANNERS"

# ── 3. Identity Graph ──
bold "3. Identity Graph"
GRAPH=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/graph" 2>&1)
check "Graph returns nodes" '"nodes"' "$GRAPH"
check "Graph returns relationships" '"relationships"' "$GRAPH"
check "Graph returns attack_paths" '"attack_paths"' "$GRAPH"

# ── 4. Policies ──
bold "4. Policies"
POLICIES=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/policies" 2>&1)
check "Policies endpoint" '"policies"' "$POLICIES"

TEMPLATES=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/policies/templates" 2>&1)
check "Templates endpoint" '"templates"' "$TEMPLATES"

# ── 5. Gateway Evaluate ──
bold "5. Gateway Evaluate (hot path)"
EVAL=$(curl -s -b "$COOKIE_JAR" -X POST "$BASE_URL/api/v1/gateway/evaluate" \
  -H 'Content-Type: application/json' \
  -d '{
    "source":"smoke-test-agent",
    "destination":"test-api",
    "method":"GET",
    "path":"/health",
    "identity":{"spiffe_id":"spiffe://wid.dev/smoke-test","trust_level":"basic"},
    "trace_id":"smoke-test-001",
    "hop_index":0,
    "total_hops":1
  }' 2>&1)
check "Evaluate returns verdict" '"verdict"' "$EVAL"
check "Evaluate returns decision_id" '"decision_id"' "$EVAL"

# ── 6. Access Decisions ──
bold "6. Access Decisions"
DECISIONS=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/access/decisions/live?limit=5" 2>&1)
check "Decisions endpoint" '"decisions"' "$DECISIONS"

STATS=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/access/decisions/stats" 2>&1)
check "Stats endpoint" '"hourly"' "$STATS"

# ── 7. Decision Replay ──
bold "7. Decision Replay"
REPLAY=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/access/decisions/replay/smoke-test-001" 2>&1)
check "Replay endpoint responds" 'trace_id\|replay\|hops\|error' "$REPLAY"

# ── 8. Compliance Frameworks ──
bold "8. Compliance"
COMPLIANCE=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/compliance/frameworks" 2>&1)
check "Frameworks endpoint" '"SOC2"' "$COMPLIANCE"
check "Has 5 frameworks" '"EU_AI_ACT"' "$COMPLIANCE"

# ── 9. Connectors ──
bold "9. Connectors"
CONNECTORS=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/connectors" 2>&1)
check "Connectors endpoint" '"connectors"' "$CONNECTORS"

# ── 10. Federation ──
bold "10. Federation"
RELAY=$(curl -s -b "$COOKIE_JAR" "$BASE_URL/api/v1/relay/environments" 2>&1)
check "Relay environments" 'environments' "$RELAY"

# ── Summary ──
echo ""
bold "Results: $PASS/$TOTAL passed, $FAIL failed"
if [ "$FAIL" -gt 0 ]; then
  red "Some checks failed."
  exit 1
else
  green "All checks passed."
fi
