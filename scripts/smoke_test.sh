#!/usr/bin/env bash
set -euo pipefail

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PLANE_URL="${PLANE_URL:-http://localhost:8443}"
GW_URL="${GW_URL:-http://localhost:8080}"
SECRET="${CLUSTER_SECRET:-change-me-cluster-super-secret}"
NETWORK_ID="00000000-0000-0000-0000-000000000002"

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}           ZRO Docker Stack Smoke Tests             ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Step 1: Healthcheck
echo -n "Checking Control Plane Health ($PLANE_URL/health)... "
HEALTH_RESP=$(curl -s -w "\n%{http_code}" "$PLANE_URL/health")
HTTP_CODE=$(echo "$HEALTH_RESP" | tail -n1)
BODY=$(echo "$HEALTH_RESP" | head -n-1)

if [ "$HTTP_CODE" -eq 200 ]; then
    echo -e "${GREEN}OK (200)${NC}"
else
    echo -e "${RED}FAILED ($HTTP_CODE)${NC}"
    echo "$BODY"
    exit 1
fi

# Step 2: Edge PoP Verification
echo -n "Checking Edge PoPs Catalog ($PLANE_URL/api/v1/pops)... "
POPS_RESP=$(curl -s "$PLANE_URL/api/v1/pops")
if echo "$POPS_RESP" | grep -q "KH" && echo "$POPS_RESP" | grep -q "SG"; then
    echo -e "${GREEN}OK (Active Edge PoPs: KH, SG, etc. found)${NC}"
else
    echo -e "${RED}FAILED: Edge PoPs missing${NC}"
    echo "$POPS_RESP"
    exit 1
fi

# Step 3: Node Enrollment
echo -n "Generating node enrollment token & registering node... "
if [ -f "./bin/zro" ]; then
    TOKEN=$(./bin/zro token --secret "$SECRET" --network-id "$NETWORK_ID" --hostname "smoke-node-01" | tail -n1)
    PUBKEY=$(./bin/zro keygen | grep "Public Key:" | awk '{print $3}')
else
    # Fallback to Go run if binary not in bin
    TOKEN=$(go run ./cmd/zro token --secret "$SECRET" --network-id "$NETWORK_ID" --hostname "smoke-node-01" | tail -n1)
    PUBKEY=$(go run ./cmd/zro keygen | grep "Public Key:" | awk '{print $3}')
fi

ENROLL_PAYLOAD=$(cat <<EOF
{
  "token": "$TOKEN",
  "public_key": "$PUBKEY",
  "hostname": "smoke-node-01",
  "node_type": "peer",
  "tags": ["tag:smoke", "env:ci"],
  "endpoints": ["127.0.0.1:51820"]
}
EOF
)

ENROLL_RESP=$(curl -s -X POST -H "Content-Type: application/json" -d "$ENROLL_PAYLOAD" "$PLANE_URL/api/v1/enroll")
if echo "$ENROLL_RESP" | grep -q "overlay_ipv4"; then
    ASSIGNED_IP=$(echo "$ENROLL_RESP" | grep -o '"overlay_ipv4":"[^"]*' | cut -d'"' -f4)
    echo -e "${GREEN}OK (Assigned IPless Overlay: $ASSIGNED_IP)${NC}"
else
    echo -e "${RED}FAILED: Node enrollment rejected${NC}"
    echo "$ENROLL_RESP"
    exit 1
fi

# Step 4: Latency Probe Report (Smart Routing)
echo -n "Submitting smart routing latency probe to Control Plane... "
NODE_ID=$(echo "$ENROLL_RESP" | grep -o '"node_id":"[^"]*' | cut -d'"' -f4)
PROBE_PAYLOAD=$(cat <<EOF
{
  "node_id": "$NODE_ID",
  "pop_code": "KH",
  "rtt": 5000000,
  "packet_loss": 0.0
}
EOF
)

PROBE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$PROBE_PAYLOAD" "$PLANE_URL/api/v1/probes")
if [ "$PROBE_CODE" -eq 202 ]; then
    echo -e "${GREEN}OK (202 Accepted)${NC}"
else
    echo -e "${RED}FAILED: Probe returned $PROBE_CODE${NC}"
    exit 1
fi

# Step 5: Gateway Status
echo -n "Checking Ingress Gateway ($GW_URL)... "
GW_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$GW_URL" || true)
if [ "$GW_CODE" -ne 000 ]; then
    echo -e "${GREEN}OK (Gateway active on port, status: $GW_CODE)${NC}"
else
    echo -e "${YELLOW}Warning: Gateway port not listening on $GW_URL (skip if not exposed)${NC}"
fi

echo -e "${BLUE}====================================================${NC}"
echo -e "${GREEN}   🎉 ALL ZRO PRODUCTION SMOKE TESTS PASSED!       ${NC}"
echo -e "${BLUE}====================================================${NC}"
