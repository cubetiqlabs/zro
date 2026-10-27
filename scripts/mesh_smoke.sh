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
    "$IMG" join --plane http://smoke-plane:8443 --token "$TOK" --hostname $n $([ $n = n2 ] && echo --ssh-user root) >/dev/null
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

# The local admin socket: status lists the peer, and zro ping reaches it.
docker exec smoke-n1 zro status | grep -q "^n2 " || { echo "FAIL zro status does not list n2"; docker exec smoke-n1 zro status; exit 1; }
ok "zro status lists peers"
docker exec smoke-n1 zro ping -n 1 n2 || { echo "FAIL zro ping n2"; exit 1; }
ok "zro ping n2"

# Zero trust: an unlisted TCP port is filtered until a network rule opens it.
docker exec -d smoke-n2 sh -c 'while true; do echo hi | nc -l -p 7000; done'
sleep 1
reach() { [ "$(docker exec smoke-n1 sh -c "nc -w 3 $N2 7000 </dev/null" 2>/dev/null)" = hi ]; }
if reach; then echo "FAIL port 7000 reachable under default deny"; exit 1; fi
ok "port 7000 filtered by default deny"
docker exec smoke-n2 zro allow 7000/tcp >/dev/null
reach || { echo "FAIL port 7000 filtered after zro allow"; exit 1; }
ok "zro allow 7000/tcp opens it"
docker exec smoke-n2 zro deny 7000/tcp >/dev/null
if reach; then echo "FAIL port 7000 reachable after zro deny"; exit 1; fi
ok "zro deny 7000/tcp closes it"
api /api/v1/acl/rules "{\"network_id\":\"$NETID\",\"priority\":10,\"source_tag\":\"*\",\"dest_tag\":\"*\",\"protocol\":\"tcp\",\"ports\":\"7000\",\"action\":\"ALLOW\"}" -H "Authorization: Bearer $KEY" >/dev/null
for _ in $(seq 1 10); do reach && break; sleep 1; done
reach || { echo "FAIL port 7000 still filtered after an ALLOW rule"; exit 1; }
ok "port 7000 open after a network ALLOW rule"
ping_ok smoke-n1 "$N2" "ping still allowed with rules present"

# A direct path that stops carrying traffic must fall back to the edge relay.
if [ "$P2P" = true ]; then
  N2_LAN=$(docker inspect smoke-n2 -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
  docker exec smoke-n1 zro status
  docker exec smoke-n1 iptables -I INPUT -s "$N2_LAN" -p udp -j DROP
  docker exec smoke-n1 iptables -I OUTPUT -d "$N2_LAN" -p udp -j DROP
  echo "..   blocked direct UDP n1<->n2; waiting for the watchdog"
  for _ in $(seq 1 45); do
    docker exec smoke-n1 ping -c1 -W2 "$N2" >/dev/null 2>&1 && docker exec smoke-n2 ping -c1 -W2 "$N1" >/dev/null 2>&1 && break
    sleep 2
  done
  docker exec smoke-n1 zro status
  ping_ok smoke-n1 "$N2" "after the direct path died"
  ping_ok smoke-n2 "$N1" "after the direct path died"
fi
# MagicDNS: each node answers <peer>.<dns_domain> on its own mesh address.
DOMAIN=$(curl -fsS "http://127.0.0.1:18443/api/v1/networks/$NETID" -H "Authorization: Bearer $KEY" | jq -r .dns_domain)
docker exec smoke-n1 nslookup "n2.$DOMAIN" "$N1" 2>/dev/null | grep -q "$N2" || { echo "FAIL MagicDNS n2.$DOMAIN"; docker exec smoke-n1 nslookup "n2.$DOMAIN" "$N1"; exit 1; }
ok "MagicDNS resolves n2.$DOMAIN"
docker exec smoke-n1 zro ping -n 1 "n2.$DOMAIN" >/dev/null || { echo "FAIL zro ping by FQDN"; exit 1; }
ok "zro ping n2.$DOMAIN"

# Built-in SSH: n2 opted in for root; the host key comes from the plane.
[ "$(docker exec smoke-n1 zro ssh root@n2 -- hostname)" = "$(docker exec smoke-n2 hostname)" ] || { echo "FAIL zro ssh command"; exit 1; }
ok "zro ssh root@n2 -- hostname"
rc=0; docker exec smoke-n1 zro ssh root@n2 -- 'exit 7' || rc=$?
[ $rc -eq 7 ] || { echo "FAIL zro ssh exit status ($rc)"; exit 1; }
ok "zro ssh passes the exit status"
docker exec -t smoke-n1 zro ssh -t root@n2 -- tty | grep -q /dev/pts/ || { echo "FAIL zro ssh pty"; exit 1; }
ok "zro ssh -t gets a terminal"
if docker exec smoke-n1 zro ssh nobody@n2 -- true 2>/dev/null; then echo "FAIL ssh as an ungranted user"; exit 1; fi
ok "ungranted user refused"
if docker exec smoke-n2 zro ssh root@n1 -- true 2>/dev/null; then echo "FAIL ssh to a node with SSH off"; exit 1; fi
ok "node without SSH refused"

# Lifecycle: a disabled node drops out of the mesh and comes back when enabled.
zro_plane() { docker exec -e ZRO_PLANE=http://127.0.0.1:8443 -e ZRO_API_KEY="$KEY" -e ZRO_NETWORK="$NETID" smoke-plane zro "$@"; }
zro_plane nodes list
zro_plane nodes disable n2 >/dev/null
for _ in $(seq 1 10); do docker exec smoke-n1 ping -c1 -W1 "$N2" >/dev/null 2>&1 || break; sleep 1; done
if docker exec smoke-n1 ping -c1 -W2 "$N2" >/dev/null 2>&1; then echo "FAIL disabled n2 still reachable"; exit 1; fi
ok "disabled n2 is cut off"
zro_plane nodes enable n2 >/dev/null
for _ in $(seq 1 30); do docker exec smoke-n1 ping -c1 -W1 "$N2" >/dev/null 2>&1 && break; sleep 1; done
ping_ok smoke-n1 "$N2" "n2 back after enable"
zro_plane audit -n 5
echo "mesh smoke passed"
