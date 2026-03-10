#!/bin/bash
read -s -p "Paste Stripe test key: " SK
echo ""
echo -n "$SK" | gcloud secrets versions add wid-demo-stripe-key --data-file=- --project=wid-platform
SK=""
echo "✓ Updated"
