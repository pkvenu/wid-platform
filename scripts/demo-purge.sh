#!/bin/bash
# =============================================================================
# Demo Purge — Nuclear reset: wipes users, connectors, workloads, policies
# =============================================================================
# Usage: ./scripts/demo-purge.sh
#   Returns the app to first-user registration state.
#   Uses bearer token auth (no login needed).
# =============================================================================

BASE_URL="${WID_BASE_URL:-http://34.120.74.81}"
RESET_TOKEN="${DEMO_RESET_TOKEN:-wid-demo-reset-2026}"

echo "Purging all data at $BASE_URL..."

RESULT=$(curl -s -X POST "$BASE_URL/api/v1/auth/demo-reset" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $RESET_TOKEN" \
  -d '{}')

echo "$RESULT" | python3 -m json.tool 2>/dev/null || echo "$RESULT"

# Check result
if echo "$RESULT" | grep -q '"reset": true\|"reset":true'; then
  echo ""
  echo "Done. Visit $BASE_URL to register a fresh account."
else
  echo ""
  echo "Purge may have failed. Check output above."
fi
