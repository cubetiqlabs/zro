#!/usr/bin/env bash
# Self-contained mesh check on Linux containers: one plane (+Postgres), one edge PoP and two
# nodes on a private Docker network, then pings across the overlay.
#
#   docker build -t zro:dev . && ./scripts/mesh_smoke.sh
#
# Set P2P=false to force node-to-node traffic through the edge. Cleans up on exit.
set -euo pipefail

IMG="${IMG:-zro:dev}"
P2P="${P2P:-true}"
SEC="mesh-smoke-secret-0123456789abcdef0123456789abcdef"
NET=zro-smoke
EDGE_IP=""

cleanup() { docker rm -f smoke-pg smoke-plane smoke-edge smoke-n1 smoke-n2 >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker network create $NET >/dev/null
EDGE_IP=$(docker network inspect $NET -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}' | sed 's#0/24#10#')

docker run -d --name smoke-pg --network $NET -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=zro postgres:18-alpine >/dev/null
sleep 6
docker run -d --name smoke-plane --network $NET -p 127.0.0.1:18443:8443 \
  -e ZRO_CONTROL_PLANE_LISTEN_ADDR=:8443 -e ZRO_CONTROL_PLANE_PUBLIC_URL=http://smoke-plane:8443 \
  -e ZRO_CONTROL_PLANE_SECRET_KEY=$SEC -e ZRO_CONTROL_PLANE_EDGE_API_KEY=edgekey -e ZRO_CONTROL_PLANE_ADMIN_API_KEY=adminkey \
  -e ZRO_CONTROL_PLANE_DATABASE_DRIVER=postgres \
  -e 'ZRO_CONTROL_PLANE_DATABASE_DSN=postgres://postgres:pw@smoke-pg:5432/zro?sslmode=disable' \
  -e ZRO_CONTROL_PLANE_REQUIRE_AUTH=true "$IMG" plane >/dev/null
sleep 4

api() { curl -fsS -X POST "http://127.0.0.1:18443$1" -H 'Content-Type: application/json' "${@:3}" -d "$2"; }
KEY=$(api /api/v1/tenants '{"name":"Acme","slug":"acme"}' -H 'X-Admin-Key: adminkey' | jq -r .api_key)
NETID=$(api /api/v1/networks '{"name":"smoke"}' -H "Authorization: Bearer $KEY" | jq -r .id)

docker run -d --name smoke-edge --network $NET --ip "$EDGE_IP" --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv6.conf.all.forwarding=1 \
  -e ZRO_EDGE_POP_CODE=KH -e ZRO_EDGE_REGION=local -e ZRO_EDGE_PUBLIC_ENDPOINT="$EDGE_IP:51820" -e ZRO_EDGE_LISTEN_PORT=51820 \
  -e ZRO_EDGE_PLANE_ENDPOINT=http://smoke-plane:8443 -e ZRO_EDGE_EDGE_API_KEY=edgekey "$IMG" edge >/dev/null
sleep 5
for n in n1 n2; do
  TOK=$(docker exec smoke-plane zro token --network-id "$NETID" --secret $SEC --hostname $n | tail -1)
  docker run -d --name smoke-$n --network $NET --cap-add NET_ADMIN --device /dev/net/tun -e ZRO_NODE_ENABLE_P2P="$P2P" \
    "$IMG" join --plane http://smoke-plane:8443 --token "$TOK" --hostname $n >/dev/null
done
sleep 10

ok() { echo "ok   $1"; }
ping_ok() { docker exec "$1" ping -c2 -W2 "$2" >/dev/null 2>&1 || { echo "FAIL $1 -> $2 ($3)"; exit 1; }; ok "$1 -> $2 ($3)"; }
N1=$(docker exec smoke-n1 ip -4 -o addr show zro0 | awk '{print $4}' | cut -d/ -f1)
N2=$(docker exec smoke-n2 ip -4 -o addr show zro0 | awk '{print $4}' | cut -d/ -f1)
EDGE=$(docker exec smoke-edge ip -4 -o addr show zro-edge | awk '{print $4}' | cut -d/ -f1)
[ -n "$EDGE" ] || { echo "FAIL edge has no mesh address"; exit 1; }
ping_ok smoke-n1 "$N2" "node to node"
ping_ok smoke-n2 "$N1" "node to node"
ping_ok smoke-n1 "$EDGE" "node to edge"
ping_ok smoke-n2 "$EDGE" "node to edge"
