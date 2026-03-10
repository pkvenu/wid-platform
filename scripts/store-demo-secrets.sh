#!/bin/bash
# Store demo API keys in GCP Secret Manager
# Keys are read interactively — never appear in shell history or logs
set -euo pipefail

PROJECT="wid-platform"

store_secret() {
  local name="$1"
  local desc="$2"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $desc"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo -n "  Paste key (hidden): "
  read -s key
  echo " ✓"

  if [ -z "$key" ]; then
    echo "  ⚠ Skipped (empty)"
    return
  fi

  # Create or update secret
  if gcloud secrets describe "$name" --project="$PROJECT" &>/dev/null; then
    echo -n "$key" | gcloud secrets versions add "$name" --data-file=- --project="$PROJECT" 2>/dev/null
    echo "  ✓ Updated existing secret: $name"
  else
    echo -n "$key" | gcloud secrets create "$name" --data-file=- --project="$PROJECT" --replication-policy=automatic 2>/dev/null
    echo "  ✓ Created new secret: $name"
  fi

  # Grant access to Cloud Run service account
  gcloud secrets add-iam-policy-binding "$name" \
    --project="$PROJECT" \
    --member="serviceAccount:wid-dev-run@wid-platform.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet 2>/dev/null
  echo "  ✓ Access granted to Cloud Run SA"

  # Clear the variable
  key=""
}

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   WID Demo — Secure Credential Setup      ║"
echo "║   Keys are read silently (no echo)         ║"
echo "║   Stored in GCP Secret Manager             ║"
echo "╚═══════════════════════════════════════════╝"

store_secret "wid-demo-openai-key"    "1/4  OpenAI API Key (sk-proj-...)"
store_secret "wid-demo-stripe-key"    "2/4  Stripe Test Key (sk_test_...)"
store_secret "wid-demo-anthropic-key" "3/4  Anthropic API Key (sk-ant-...)"
store_secret "wid-demo-github-pat"    "4/4  GitHub PAT (github_pat_...)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓ All secrets stored in GCP Secret Manager"
echo ""
echo "  Verify:"
echo "  gcloud secrets list --project=$PROJECT --filter='name:wid-demo'"
echo ""
echo "  To read a secret (admin only):"
echo "  gcloud secrets versions access latest --secret=wid-demo-openai-key --project=$PROJECT"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
