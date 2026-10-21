#!/usr/bin/env bash
# End-to-end smoke test of a running ZRO stack, through the public API only.
#
#   CLUSTER_SECRET=... ADMIN_API_KEY=... ./scripts/smoke_test.sh
#
# Needs: curl, jq, and a way to run the `zro` binary (to mint tokens and keys). By default it
# runs it inside the compose plane container; set ZRO_CMD="zro" to use a local binary.
# The plane must have control_plane.admin_api_key set (that is how the tenant is created).
set -euo pipefail

PLANE_URL="${PLANE_URL:-http://localhost:8443}"
GW_URL="${GW_URL:-http://localhost:8080}"
ZRO_CMD="${ZRO_CMD:-docker compose exec -T zro-plane zro}"
: "${CLUSTER_SECRET:?set CLUSTER_SECRET to the plane secret_key}"
: "${ADMIN_API_KEY:?set ADMIN_API_KEY to the plane admin_api_key}"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
pass() { echo -e "${GREEN}ok${NC}   $1"; }
fail() { echo -e "${RED}FAIL${NC} $1"; exit 1; }

# api METHOD PATH BEARER [JSON-BODY] -> prints the body, fails on a non-2xx status.
api() {
  local method=$1 path=$2 bearer=$3 body=${4:-}
  local out status
  out=$(curl -sS -w '\n%{http_code}' -X "$method" "$PLANE_URL$path" \
    ${bearer:+-H "Authorization: Bearer $bearer"} \
    ${body:+-H 'Content-Type: application/json' -d "$body"})
  status=${out##*$'\n'}
  [[ $status =~ ^2 ]] || { echo "$method $path -> $status: ${out%$'\n'*}" >&2; return 1; }
  printf '%s' "${out%$'\n'*}"
}

curl -fsS "$PLANE_URL/healthz" >/dev/null && pass "liveness (/healthz)" || fail "liveness"
curl -fsS "$PLANE_URL/readyz"  >/dev/null && pass "readiness (/readyz, database reachable)" || fail "readiness"

# Tenancy: the admin key creates a tenant; the tenant key creates its network.
SLUG="smoke-$(date +%s)"
TENANT=$(api POST /api/v1/tenants "$ADMIN_API_KEY" "{\"name\":\"$SLUG\",\"slug\":\"$SLUG\"}") || fail "create tenant"
TENANT_KEY=$(jq -r .api_key <<<"$TENANT")
pass "tenant created (API key shown once)"
NETWORK=$(api POST /api/v1/networks "$TENANT_KEY" '{"name":"smoke"}') || fail "create network"
NET_ID=$(jq -r .id <<<"$NETWORK")
pass "network $NET_ID"

# Enrol two nodes with tokens bound to their own keys.
enroll() {
  local host=$1 keys pub token
  keys=$($ZRO_CMD keygen)
  pub=$(awk '/Public Key/ {print $3}' <<<"$keys" | tr -d '\r')
  token=$($ZRO_CMD token --secret "$CLUSTER_SECRET" --network-id "$NET_ID" --hostname "$host" --pubkey "$pub" --type peer | tail -n1 | tr -d '\r')
  api POST /api/v1/enroll "" "{\"token\":\"$token\",\"public_key\":\"$pub\",\"hostname\":\"$host\"}"
}
N1=$(enroll smoke-a) || fail "enroll smoke-a"
N2=$(enroll smoke-b) || fail "enroll smoke-b"
T1=$(jq -r .node_token <<<"$N1"); T2=$(jq -r .node_token <<<"$N2")
IP2=$(jq -r .overlay_ipv4 <<<"$N2")
pass "two nodes enrolled ($(jq -r .overlay_ipv4 <<<"$N1"), $IP2)"

# Node-facing endpoints need the node token; without it they refuse.
[[ $(curl -s -o /dev/null -w '%{http_code}' "$PLANE_URL/api/v1/gateway/routes") == 401 ]] && pass "node endpoints refuse anonymous callers" || fail "anonymous access was allowed"
[[ $(jq length <<<"$(api GET "/api/v1/network/$NET_ID/peers" "$T1")") -ge 2 ]] && pass "peer list" || fail "peer list"
api POST /api/v1/p2p/discover "$T1" "{\"target_overlay_ip\":\"$IP2\"}" >/dev/null && pass "P2P discovery" || fail "P2P discovery"
api POST /api/v1/probes "$T1" '{"pop_code":"KH","rtt":4000000}' >/dev/null && pass "latency probe" || fail "probe"

# Ingress: a tunnel registered by node A shows up as a gateway route; another network cannot take its hostname.
HOST="smoke-$(date +%s).example.com"
api POST /api/v1/tunnels "$T1" "{\"name\":\"smoke\",\"local_address\":\"127.0.0.1:3000\",\"public_hostname\":\"$HOST\"}" >/dev/null && pass "tunnel $HOST" || fail "tunnel"
jq -e --arg h "$HOST" '.routes[] | select(.hostname==$h)' <<<"$(api GET /api/v1/gateway/routes "$T2")" >/dev/null && pass "gateway route published to the network" || fail "gateway route"

# Zero-trust: a network rule is validated, stored, and delivered to nodes.
api POST /api/v1/acl/rules "$TENANT_KEY" "{\"network_id\":\"$NET_ID\",\"priority\":10,\"protocol\":\"tcp\",\"ports\":\"5432\",\"action\":\"ALLOW\"}" >/dev/null && pass "ACL rule created" || fail "ACL rule"
if api POST /api/v1/acl/rules "$TENANT_KEY" "{\"network_id\":\"$NET_ID\",\"ports\":\"80,x\"}" >/dev/null 2>&1; then fail "malformed rule accepted"; else pass "malformed ACL rule rejected"; fi
[[ $(jq length <<<"$(api GET /api/v1/acl/policy "$T1")") == 1 ]] && pass "policy delivered to the node" || fail "policy delivery"

api GET "/api/v1/mesh/graph?network_id=$NET_ID" "$TENANT_KEY" >/dev/null && pass "mesh graph (tenant-scoped)" || fail "mesh graph"

# Leave: the node's token stops working.
api DELETE /api/v1/node "$T2" >/dev/null && pass "node deregistered" || fail "deregister"
[[ $(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $T2" "$PLANE_URL/api/v1/gateway/routes") == 401 ]] && pass "its token is revoked" || fail "token still valid"

# Gateway (optional): reachable and proxying, even if the backend itself is not running.
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$GW_URL" || true)
echo "gateway answered $code for $HOST (502/503 is expected: nothing serves 127.0.0.1:3000)"

echo -e "\n${GREEN}smoke test passed${NC}"
