#!/bin/bash
# =============================================================================
# WID — GCP Connector Setup
# =============================================================================
# Creates a read-only service account for WID discovery and downloads the key.
#
# Usage:
#   ./scripts/gcp-setup-connector.sh <PROJECT_ID>
#
# Example:
#   ./scripts/gcp-setup-connector.sh wid-platform
#
# After running, paste the contents of wid-sa-key.json into the WID wizard.
# =============================================================================

set -e

PROJECT_ID="${1:?Usage: $0 <PROJECT_ID>}"
SA_NAME="wid-discovery"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
KEY_FILE="wid-sa-key.json"

echo "Setting up WID discovery service account for project: $PROJECT_ID"
echo ""

# 1. Create service account
echo "[1/4] Creating service account: $SA_NAME"
gcloud iam service-accounts create "$SA_NAME" \
  --display-name="WID Discovery (read-only)" \
  --project="$PROJECT_ID" 2>/dev/null || echo "      (already exists)"

# 2. Grant Viewer role
echo "[2/4] Granting roles/viewer"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/viewer" \
  --quiet >/dev/null

# 3. Grant Security Reviewer role
echo "[3/4] Granting roles/iam.securityReviewer"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.securityReviewer" \
  --quiet >/dev/null

# 4. Download key
echo "[4/4] Downloading service account key"
gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --project="$PROJECT_ID"

echo ""
echo "Done! Key saved to: $KEY_FILE"
echo ""
echo "Next steps:"
echo "  1. Open the WID connector wizard"
echo "  2. Select Google Cloud Platform"
echo "  3. Enter Project ID: $PROJECT_ID"
echo "  4. Paste the contents of $KEY_FILE into the Service Account Key field"
echo ""
echo "To view the key:"
echo "  cat $KEY_FILE"
