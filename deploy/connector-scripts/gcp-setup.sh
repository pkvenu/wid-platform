#!/usr/bin/env bash
# =============================================================================
# WID GCP Connector Setup — Creates a read-only service account for discovery
# =============================================================================
# Usage:
#   ./gcp-setup.sh <PROJECT_ID>
#
# What it creates:
#   - Service account: wid-discovery@<project>.iam.gserviceaccount.com
#   - Roles: Viewer, Cloud Asset Viewer, IAM Security Reviewer
#   - JSON key: ./wid-discovery-key.json (upload this to WID)
#
# Requirements:
#   - gcloud CLI authenticated with Owner or IAM Admin role
#   - APIs enabled: iam.googleapis.com, cloudasset.googleapis.com
# =============================================================================

set -euo pipefail

PROJECT_ID="${1:-}"
SA_NAME="wid-discovery"
SA_DISPLAY="WID Discovery (read-only)"
KEY_FILE="wid-discovery-key.json"

if [ -z "$PROJECT_ID" ]; then
  echo "Usage: $0 <GCP_PROJECT_ID>"
  echo ""
  echo "Example: $0 my-project-123"
  exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  WID GCP Connector Setup"
echo "  Project: $PROJECT_ID"
echo "═══════════════════════════════════════════════════════"
echo ""

# 1. Enable required APIs
echo "1/4  Enabling required APIs..."
gcloud services enable iam.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable cloudasset.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable cloudresourcemanager.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable compute.googleapis.com --project="$PROJECT_ID" --quiet
gcloud services enable run.googleapis.com --project="$PROJECT_ID" --quiet
echo "     Done."

# 2. Create service account
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
echo "2/4  Creating service account: $SA_EMAIL"
if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
  echo "     Service account already exists."
else
  gcloud iam service-accounts create "$SA_NAME" \
    --project="$PROJECT_ID" \
    --display-name="$SA_DISPLAY" \
    --description="Read-only service account for WID workload discovery"
  echo "     Created."
fi

# 3. Bind IAM roles (read-only)
echo "3/4  Granting read-only roles..."
ROLES=(
  "roles/viewer"
  "roles/cloudasset.viewer"
  "roles/iam.securityReviewer"
)
for ROLE in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$ROLE" \
    --condition=None \
    --quiet &>/dev/null
  echo "     + $ROLE"
done

# 4. Create and download key
echo "4/4  Creating JSON key..."
if [ -f "$KEY_FILE" ]; then
  echo "     Key file $KEY_FILE already exists. Skipping."
else
  gcloud iam service-accounts keys create "$KEY_FILE" \
    --iam-account="$SA_EMAIL" \
    --project="$PROJECT_ID"
  echo "     Key saved to: $KEY_FILE"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup Complete"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Service Account: $SA_EMAIL"
echo "  Key File:        $KEY_FILE"
echo "  Roles:           Viewer, Cloud Asset Viewer, IAM Security Reviewer"
echo ""
echo "  Next: Upload $KEY_FILE in the WID Connectors page"
echo "  or paste its contents when creating a GCP connector."
echo ""
echo "  IMPORTANT: Store the key securely and delete the"
echo "  local file after uploading to WID."
echo "═══════════════════════════════════════════════════════"
