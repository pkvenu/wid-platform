#!/usr/bin/env bash
# =============================================================================
# WID Azure Connector Setup — Creates a read-only service principal for discovery
# =============================================================================
# Usage:
#   ./azure-setup.sh <SUBSCRIPTION_ID>
#
# What it creates:
#   - App Registration: wid-discovery
#   - Service Principal with Reader role at subscription scope
#   - Client secret (valid 1 year)
#
# Requirements:
#   - Azure CLI (az) authenticated
#   - Permissions: Application Administrator + User Access Administrator
# =============================================================================

set -euo pipefail

SUBSCRIPTION_ID="${1:-}"
APP_NAME="wid-discovery"

if [ -z "$SUBSCRIPTION_ID" ]; then
  echo "Usage: $0 <AZURE_SUBSCRIPTION_ID>"
  echo ""
  echo "Example: $0 12345678-1234-1234-1234-123456789012"
  exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  WID Azure Connector Setup"
echo "  Subscription: $SUBSCRIPTION_ID"
echo "═══════════════════════════════════════════════════════"
echo ""

# 1. Get tenant ID
echo "1/4  Getting tenant information..."
TENANT_ID=$(az account show --subscription "$SUBSCRIPTION_ID" --query tenantId -o tsv)
echo "     Tenant: $TENANT_ID"

# 2. Create app registration + service principal
echo "2/4  Creating app registration: $APP_NAME"
SP_OUTPUT=$(az ad sp create-for-rbac \
  --name "$APP_NAME" \
  --role "Reader" \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" \
  --years 1 \
  --output json)

CLIENT_ID=$(echo "$SP_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['appId'])")
CLIENT_SECRET=$(echo "$SP_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['password'])")

echo "     App ID: $CLIENT_ID"

# 3. Add additional read-only role assignments
echo "3/4  Adding Security Reader role..."
az role assignment create \
  --assignee "$CLIENT_ID" \
  --role "Security Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --output none 2>/dev/null || echo "     Security Reader already assigned or insufficient permissions."

echo "4/4  Adding Directory Reader role (Entra ID)..."
echo "     Note: Directory Reader requires Global Admin consent."
echo "     Run manually if needed:"
echo "       az ad app permission grant --id $CLIENT_ID --api 00000003-0000-0000-c000-000000000000 --scope Directory.Read.All"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup Complete"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "  Paste these values into the WID Connectors page:"
echo ""
echo "  Tenant ID:       $TENANT_ID"
echo "  Client ID:       $CLIENT_ID"
echo "  Client Secret:   $CLIENT_SECRET"
echo "  Subscription ID: $SUBSCRIPTION_ID"
echo ""
echo "  Roles: Reader, Security Reader"
echo "  Secret expires: 1 year from now"
echo ""
echo "  IMPORTANT: Store these credentials securely."
echo "  The client secret will not be shown again."
echo "═══════════════════════════════════════════════════════"
