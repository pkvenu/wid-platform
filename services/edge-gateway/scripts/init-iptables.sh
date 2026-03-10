#!/bin/bash
# =============================================================================
# Edge Gateway — iptables Traffic Interception Init
# =============================================================================
# Run as an init container (Kubernetes) or on startup (VM) with NET_ADMIN.
# Redirects all TCP traffic through the gateway proxy.
#
# After this runs:
#   Inbound:  all TCP → :15006 (inbound handler)
#   Outbound: all TCP → :15001 (outbound handler)
#   Except:   gateway UID (1337), localhost, DNS, platform ports
# =============================================================================
set -e

GATEWAY_UID=${GATEWAY_UID:-1337}
OUTBOUND_PORT=${OUTBOUND_PORT:-15001}
INBOUND_PORT=${INBOUND_PORT:-15006}
EXCLUDE_PORTS=${EXCLUDE_PORTS:-"3000,3001,3002,3004,5432,8181,8200,15000,15001,15006"}

echo "══════════════════════════════════════════════════"
echo "  Edge Gateway — iptables Init"
echo "══════════════════════════════════════════════════"
echo "  Gateway UID:    $GATEWAY_UID"
echo "  Outbound port:  $OUTBOUND_PORT"
echo "  Inbound port:   $INBOUND_PORT"
echo "  Excluded ports: $EXCLUDE_PORTS"
echo "══════════════════════════════════════════════════"

# ── Inbound ──
iptables -t nat -N EDGE_INBOUND 2>/dev/null || iptables -t nat -F EDGE_INBOUND
iptables -t nat -A EDGE_INBOUND -p tcp -j REDIRECT --to-port $INBOUND_PORT
iptables -t nat -A PREROUTING -p tcp -j EDGE_INBOUND
echo "✅ Inbound: all TCP → :$INBOUND_PORT"

# ── Outbound ──
iptables -t nat -N EDGE_OUTBOUND 2>/dev/null || iptables -t nat -F EDGE_OUTBOUND
iptables -t nat -A EDGE_OUTBOUND -m owner --uid-owner $GATEWAY_UID -j RETURN
iptables -t nat -A EDGE_OUTBOUND -d 127.0.0.1/32 -j RETURN
iptables -t nat -A EDGE_OUTBOUND -d ::1/128 -j RETURN 2>/dev/null || true
iptables -t nat -A EDGE_OUTBOUND -p udp --dport 53 -j RETURN
iptables -t nat -A EDGE_OUTBOUND -p tcp --dport 53 -j RETURN

IFS=',' read -ra EXCLUDED <<< "$EXCLUDE_PORTS"
for port in "${EXCLUDED[@]}"; do
  iptables -t nat -A EDGE_OUTBOUND -p tcp --dport "$port" -j RETURN
done

iptables -t nat -A EDGE_OUTBOUND -p tcp -j REDIRECT --to-port $OUTBOUND_PORT
iptables -t nat -A OUTPUT -p tcp -j EDGE_OUTBOUND
echo "✅ Outbound: all TCP → :$OUTBOUND_PORT (except UID $GATEWAY_UID)"

echo ""
echo "NAT rules:"
iptables -t nat -L -n --line-numbers 2>/dev/null | head -50
echo ""
echo "✅ Traffic interception configured"
