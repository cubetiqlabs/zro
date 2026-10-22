# ZRO Production Deployment Guide

ZRO is a high-performance, cloud-native global mesh networking and ether-switch engine built on userspace WireGuard, Go, and PostgreSQL. It delivers IPless overlay routing, zero-trust microsegmentation, Edge PoP smart delegation, and cloud-native ingress load balancing.

---

## 1. Architecture & Port Matrix

```
       Internet / Clients
               │
        ┌──────┴──────┐
        ▼             ▼
  ┌───────────┐ ┌───────────┐
  │ Gateway 1 │ │ Gateway 2 │  <-- L4/L7 Ingress Load Balancers (:80, :443)
  └─────┬─────┘ └─────┬─────┘
        │             │
════════╪═════════════╪═════════════════════════════════════════════════════
        │             │   WireGuard Encrypted Private Mesh Backbone (100.64.0.0/10)
        ▼             ▼
  ┌───────────┐ ┌───────────┐
  │ Edge PoP  │ │ Edge PoP  │  <-- Global Data Plane PoPs (51820/udp)
  │ (Cambodia)│ │(Singapore)│      Dynamic Heartbeats & STUN Hole Punching
  └─────┬─────┘ └─────┬─────┘
        │             │
        ├─────────────┼────────────────────────────────────────┐
        ▼             ▼                                        ▼
  ┌───────────┐ ┌───────────┐                            ┌───────────┐
  │  Node 1   │ │  Node 2   │ (P2P Direct or PoP Relay)  │  Control  │
  │ (Postgres)│ │(App Server│ ◄────────────────────────► │   Plane   │ (:8443)
  │:5432/tcp  │ │ Client)   │                            │ +Postgres │
  └───────────┘ └───────────┘                            └───────────┘
```

### Port Matrix

| Component | Port / Protocol | Exposure | Purpose |
| :--- | :--- | :--- | :--- |
| **Control Plane** | `8443/tcp` | Private / Internal | REST API & RFC 6455 WebSockets Event Hub |
| **Control Plane** | `9443/tcp` | Private / Internal | Optional gRPC service (off unless `grpc_listen_addr` is set; **TLS required**, see [gRPC](#grpc-optional)) |
| **PostgreSQL** | `5432/tcp` | Internal Only | State store (Tenants, Networks, Nodes, PoPs, ACLs) |
| **Edge PoPs** | `51820/udp` | **Public** | WireGuard UDP encapsulation, STUN, & Disco signaling |
| **Gateways** | `80/tcp`, `443/tcp` | **Public** | Ingress reverse proxy & ACME / Let's Encrypt TLS |
| **Client Nodes** | Ephemeral UDP | Outbound Only | STUN reflexive discovery & direct P2P hole punching |

---

## 2. Host Prerequisites & Kernel Tuning

Run on all Linux hosts (Edge PoPs, Gateways, Nodes):

```bash
# 1. Enable IP forwarding and UDP buffer optimizations
cat <<EOF | sudo tee /etc/sysctl.d/99-zro.conf
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
EOF
sudo sysctl --system

# 2. Ensure TUN and WireGuard kernel modules are active
sudo modprobe tun wireguard 2>/dev/null || true

# 3. Ensure /dev/net/tun exists (Major 10, Minor 200)
[ -c /dev/net/tun ] || sudo mknod /dev/net/tun c 10 200
sudo chmod 0666 /dev/net/tun
```

### TUN and route programming

ZRO configures the overlay interface itself at startup: it brings the link up,
assigns the enrolled overlay addresses, and routes the overlay prefixes (reported
by the plane, so they follow your network's CIDR) into the TUN device via `ip`.
The container image includes `iproute2`.

Hosts without `NET_ADMIN` or `/dev/net/tun` have two options. A node or gateway
can run with `interface_mode: netstack`, a fully functional userspace TCP/IP
stack (ingress tunnels, `ListenMesh`/`DialMesh` and the gateway proxy all work;
there is just no host interface). An edge PoP that cannot create a TUN forwards
between peers in userspace and logs a warning.

Edge PoPs with a kernel TUN additionally enable IPv4/IPv6 forwarding and route
each network's CIDR into it so they can relay traffic between peers. If the
container runtime blocks `/proc/sys` writes, set forwarding on the host and pass
the sysctls in.

---

## 3. Security Model (read this first)

| Credential | Held by | Grants |
| :--- | :--- | :--- |
| `secret_key` | Control plane only | Signs enrollment tokens. With `require_auth: true` the plane **refuses to start** if it is empty or the shipped default. |
| `admin_api_key` | Operator | Tenant administration (`/api/v1/tenants`) and `/metrics`. Both are disabled when it is empty. |
| Tenant API key | A tenant | Its own networks, ACL rules and mesh graph. Stored hashed; shown **once** when created or rotated. |
| `edge_api_key` | Edge operator | The **first** registration of a PoP. Registration returns that PoP's own credential (shown once, stored hashed, kept in the edge's `state_dir`); the shared key can no longer touch a claimed PoP. |
| Node token | One node | The node-facing API for its own network. Issued at enrollment, rotated on every re-enrollment, revoked when the node leaves. |
| Enrollment token | Handed to a node once | Joins one network as one role (`peer` or `gateway`), bound to a hostname and, ideally, the node's public key. Single use per key. |

Without `require_auth`, anonymous callers act as a throwaway development tenant that exists only on an empty database; as soon as a real tenant exists, anonymous tenant requests are refused.

Rules of thumb: set `require_auth: true`; generate every secret with `openssl rand -hex 32`; never put tokens in URLs (they are only accepted in the `Authorization` header); mount a persistent `state_dir` for every agent.

---

## 4. Production Deployment Topologies

### Option A: Distributed Cloud Cluster (Recommended for Production)

Deploy each role onto dedicated infrastructure across regions. Values used below:
```bash
export CLUSTER_SECRET=$(openssl rand -hex 32)   # signs enrollment tokens
export EDGE_API_KEY=$(openssl rand -hex 32)     # first-registration key for edges
export ADMIN_API_KEY=$(openssl rand -hex 32)    # tenant admin + /metrics
```

#### 1. Database (PostgreSQL 15+)
Provision Amazon RDS, GCP Cloud SQL, or HA PostgreSQL:
```sql
CREATE DATABASE zro;
CREATE USER zro WITH ENCRYPTED PASSWORD 'your-strong-db-password';
GRANT ALL PRIVILEGES ON DATABASE zro TO zro;
```
> The release binary and image are static (`CGO_ENABLED=0`) and need PostgreSQL. SQLite needs a cgo build (`make build-sqlite`) and is for local trials only.

Overlay addresses are unique per network through database constraints, so any number of plane replicas can share one database safely.

#### 2. Control Plane (HA API Server)
Run 2+ instances behind a private load balancer. `/healthz` is the liveness probe and `/readyz` the readiness probe (it pings the database):
```bash
docker run -d \
  --name zro-plane \
  --restart always \
  -p 8443:8443 \
  -e ZRO_MODE=plane \
  -e ZRO_CONTROL_PLANE_PUBLIC_URL="https://zro-plane.cubis.tech:443" \
  -e ZRO_CONTROL_PLANE_DATABASE_DRIVER="postgres" \
  -e ZRO_CONTROL_PLANE_DATABASE_DSN="$DATABASE_DSN" \
  -e ZRO_CONTROL_PLANE_SECRET_KEY="$CLUSTER_SECRET" \
  -e ZRO_CONTROL_PLANE_REQUIRE_AUTH=true \
  -e ZRO_CONTROL_PLANE_EDGE_API_KEY="$EDGE_API_KEY" \
  -e ZRO_CONTROL_PLANE_ADMIN_API_KEY="$ADMIN_API_KEY" \
  cubis/zro:latest plane
```
Terminate TLS at the load balancer (or in front of the plane); every credential above travels in headers.

Optional settings: `ZRO_CONTROL_PLANE_NODE_TTL` (default `168h`; a node silent for that long is removed and its address freed, `0` disables), `ZRO_CONTROL_PLANE_ALLOWED_ORIGINS` for browser WebSocket clients.

#### 3. Edge Data Plane PoPs (Multi-Region VPS / Bare Metal)
Deploy Edge nodes in each target geography (`KH`, `SG`, `US`, `HK`, `DE`). **Mount a state volume**: it keeps the PoP's WireGuard key and its own credential across restarts.
```bash
docker run -d \
  --name zro-edge \
  --restart always \
  --network host \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --device /dev/net/tun:/dev/net/tun \
  -v zro-edge-state:/var/lib/zro \
  -e ZRO_MODE=edge \
  -e ZRO_EDGE_POP_CODE="KH" \
  -e ZRO_EDGE_REGION="Asia/Phnom_Penh" \
  -e ZRO_EDGE_PUBLIC_ENDPOINT="auto" \
  -e ZRO_EDGE_LISTEN_PORT=51820 \
  -e ZRO_EDGE_STATE_DIR=/var/lib/zro \
  -e ZRO_EDGE_EDGE_API_KEY="$EDGE_API_KEY" \
  -e ZRO_EDGE_PLANE_ENDPOINT="https://zro-plane.cubis.tech:443" \
  cubis/zro:latest edge
```
> **Tip:** `ZRO_EDGE_PUBLIC_ENDPOINT=auto` discovers the public IPv4 via STUN. The relay (DERP) listens on the same port number over **TCP**, so open `51820/tcp` as well as `51820/udp` if you want UDP-blocked clients to fall back to it.
>
> **Lost the state volume?** The PoP is already claimed, so it is refused until an admin releases it: `curl -X POST -H "Authorization: Bearer $ADMIN_API_KEY" https://zro-plane.cubis.tech:443/api/v1/pops/KH/reset-key`. Without a kernel TUN (no `NET_ADMIN`/`/dev/net/tun`) the edge forwards in userspace and logs a warning; it works but with lower throughput.

#### 4. Dual Ingress Gateways (`gw1`, `gw2`) with Anycast/DNS Failover
A gateway joins the mesh like any node, with a **gateway** token (a peer token is refused). Create the network first (section 5), then:
```bash
zro token --secret "$CLUSTER_SECRET" --network-id "<NETWORK_ID>" --hostname gw1 --type gateway
```
Assign both Gateway public IPs to your public domain DNS (e.g. `api.example.com` -> `1.1.1.1`, `1.1.1.2`):
```bash
docker run -d \
  --name zro-gw \
  --restart always \
  --network host \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  -v zro-gw-state:/var/lib/zro \
  -v /var/lib/zro/certs:/certs \
  -e ZRO_MODE=gw \
  -e ZRO_GATEWAY_HOSTNAME="gw1" \
  -e ZRO_GATEWAY_STATE_DIR=/var/lib/zro \
  -e ZRO_GATEWAY_PLANE_ENDPOINT="https://zro-plane.cubis.tech:443" \
  -e ZRO_GATEWAY_ENROLLMENT_TOKEN="<GATEWAY_TOKEN>" \
  -e ZRO_GATEWAY_NETWORK_ID="<NETWORK_ID>" \
  -e ZRO_GATEWAY_LISTEN_HTTP=":80" \
  -e ZRO_GATEWAY_LISTEN_HTTPS=":443" \
  -e ZRO_GATEWAY_AUTO_TLS="true" \
  -e ZRO_GATEWAY_DOMAIN="example.com" \
  -e ZRO_GATEWAY_CERT_DIR="/certs" \
  cubis/zro:latest gw
```
Without an enrollment token the gateway never joins the mesh and serves only its static routes. A gateway routes to **its own network** only.

---

### Option B: Standalone All-In-One (Docker Compose)

For branch offices, edge servers, or staging environments. `CLUSTER_SECRET` and `EDGE_API_KEY` are required (compose refuses to start without them):
```bash
cp .env.example .env     # fill in CLUSTER_SECRET, EDGE_API_KEY, ADMIN_API_KEY
docker compose up -d
docker compose ps
```
The gateways start without a token. Once the plane is up, create a network (section 5), mint a gateway token per gateway, set `GATEWAY1_ENROLLMENT_TOKEN` / `GATEWAY2_ENROLLMENT_TOKEN` in `.env`, then `docker compose up -d zro-gw zro-gw2`.

> The images need no NAT rules: traffic is steered by WireGuard `AllowedIPs` and kernel routes, so there is no `iptables` dependency.

### gRPC (optional)
gRPC is off by default. To enable it, set `grpc_listen_addr` **and** TLS (`grpc_tls_cert` / `grpc_tls_key`; add `grpc_tls_client_ca` to require client certificates). The plane refuses a plaintext gRPC listener unless `grpc_insecure: true` is set explicitly. Agents opt in with `plane_transport: grpc` and `plane_grpc_endpoint: host:9443`; they verify the plane's certificate (`plane_ca_file` to pin a private CA) unless `plane_grpc_insecure: true`. Every RPC is authenticated; an RPC without an explicit access rule is denied.

---

## 5. Tenants, Networks and Node Setup

### Step 1: Create a tenant, then a network
The admin key creates tenants; each tenant manages only its own networks. The tenant API key is returned **once**.
```bash
curl -s -X POST https://zro-plane.cubis.tech:443/api/v1/tenants \
  -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Cubis","slug":"cubis"}'
# {"id":"...","slug":"cubis","api_key":"zro_key_..."}   <- store it now

export TENANT_KEY=zro_key_...
curl -s -X POST https://zro-plane.cubis.tech:443/api/v1/networks \
  -H "Authorization: Bearer $TENANT_KEY" -H "Content-Type: application/json" \
  -d '{"name":"Production Mesh","ipv4_cidr":"100.64.0.0/10","ipv6_cidr":"fd00:cafe::/64"}'
# {"id":"c85e3068ac0cb812", ...}
```
Rotate a key with `POST /api/v1/tenants/{id}/rotate-key` (admin key); the old key stops working immediately. The CLI equivalent is `zro network create --api-key "$TENANT_KEY"` (or `$ZRO_API_KEY`).

### Step 2: Generate a WireGuard key & enrollment token
```bash
zro keygen
# Private Key: <CLIENT_PRIVKEY>
# Public Key:  <CLIENT_PUBKEY>

zro token \
  --secret "$CLUSTER_SECRET" \
  --network-id "c85e3068ac0cb812" \
  --hostname "db-server-01" \
  --pubkey "<CLIENT_PUBKEY>" \
  --type peer            # or: gateway
```
The token is bound to the network, hostname, role and (with `--pubkey`) the key. Redeeming it with a different key is refused, and a hostname or role that does not match the token is refused. Expiry defaults to 24h (`--hours`).

### Step 3: Run the node with a "Default Deny All" policy
```yaml
mode: node
node:
  hostname: "db-server-01"
  network_id: "c85e3068ac0cb812"     # must match the token's network
  enrollment_token: "zro_tok_..."
  state_dir: "/var/lib/zro"          # keeps the identity: same node ID and overlay IP after a restart
  plane_endpoint: "https://zro-plane.cubis.tech:443"
  interface_mode: "tun"              # or "netstack" to run unprivileged, with no host interface
  interface_name: "zro0"
  enable_p2p: true
  default_deny: true                 # drops all incoming connections by default
  allowed_inbound_ports:
    - "5432/tcp"
  tags:
    - "role:db"
```
```bash
zro node -c /etc/zro/zro.yaml
```
Re-enrolling the same key (for example after a restart) returns the same node ID and address and a fresh node token. The agent saves its node token next to its key in `state_dir` (`node.token` / `gateway.token`, mode 0600) and presents it when re-enrolling; the plane refuses a re-enrollment that cannot, so a leaked enrollment token plus a (public) WireGuard key cannot take over a node. If that file is lost, the network owner removes the node (`DELETE /api/v1/nodes/{id}`) and it enrolls fresh. To remove a node, the owning tenant calls `DELETE /api/v1/nodes/{id}` (list them with `GET /api/v1/nodes?network_id=...`); its tunnels and overlay address are freed. A node can also deregister itself with `DELETE /api/v1/node` (node token), and nodes that disappear are reaped after `node_ttl`. Networks are renamed with `PATCH /api/v1/networks/{id}` (addressing is immutable) and deleted with `DELETE /api/v1/networks/{id}` once empty; an admin removes a PoP with `DELETE /api/v1/pops/{code}`.

`socks_listen: "127.0.0.1:1080"` additionally starts a SOCKS5 proxy into the overlay. It accepts only loopback listeners (it has no authentication) and only reaches overlay IP addresses, never the host network.

`interface_mode: netstack` runs a userspace TCP/IP stack: no `/dev/net/tun`, no capabilities, no host routes. Services then live on the overlay through the daemon (ingress tunnels, `ListenMesh`, `DialMesh`) rather than as host sockets.

---

## 6. Exposing Services via Multi-Node Ingress Tunnels

To expose internal services through the Ingress Gateways without public IPs (similar to Cloudflared):

```yaml
node:
  hostname: "api-backend-01"
  network_id: "c85e3068ac0cb812"
  enrollment_token: "zro_tok_..."
  tunnels:
    - name: "api-service"
      local_address: "127.0.0.1:3000"
      public_hostname: "api.example.com"
      protocol: "http"            # the gateway is an HTTP reverse proxy; tcp and grpc are rejected
```

The node listens on its **overlay address** at the tunnel's port and pipes each connection to `local_address`, so the service can stay bound to loopback. The port is opened in the node's inbound policy automatically (you configured the tunnel explicitly). A service already bound to `0.0.0.0` is reachable on the overlay address as is.

A hostname belongs to one network: several nodes of that network may share it (the gateway load-balances with health checks); any other network is refused. Gateways pick up changes through the event stream and drop routes the plane stops listing. List and remove tunnels with `GET /api/v1/tunnels` and `DELETE /api/v1/tunnels/{id}` (node token).

---

## 7. Microsegmentation & ACL Rules

Network-wide rules are managed by the tenant that owns the network and **enforced on each node** for inbound traffic:

```bash
# Allow the web tier to reach Postgres on 5432
curl -s -X POST https://zro-plane.cubis.tech:443/api/v1/acl/rules \
  -H "Authorization: Bearer $TENANT_KEY" -H "Content-Type: application/json" \
  -d '{
    "network_id": "c85e3068ac0cb812",
    "priority": 10,
    "source_tag": "role:web",
    "dest_tag": "role:db",
    "protocol": "tcp",
    "ports": "5432",
    "action": "ALLOW"
  }'

curl -s -H "Authorization: Bearer $TENANT_KEY" \
  "https://zro-plane.cubis.tech:443/api/v1/acl/rules?network_id=c85e3068ac0cb812"
```
Rules are validated on create (CIDRs, port lists such as `80,443,8000-8080`, protocol, action). Evaluation order: lowest `priority` number first, and a DENY wins a tie. For inbound traffic a node applies the network rules first: a matching **DENY** closes a port the node opened locally, a matching **ALLOW** opens one its `default_deny` would close, and traffic no rule matches falls back to the node's own `allowed_inbound_ports` / `default_deny`. Source tags come from the peer list, destination tags from the node's own `tags`. Nodes pick up changes live and keep the last good policy if the plane is unreachable.

---

## 8. Operational Health & Live Monitoring

### Probes and metrics
* `GET /healthz`: liveness (always 200 while the process serves).
* `GET /readyz`: readiness (503 if the database is unreachable). Use it for load balancer health checks.
* `GET /metrics`: Prometheus text (`zro_nodes`, `zro_nodes_active`, `zro_edge_pops_healthy`, `zro_tunnels`, `zro_event_subscribers`, `zro_build_info`, ...). Requires `Authorization: Bearer $ADMIN_API_KEY`; absent if no admin key is set.
* `zro version` prints the build; release images are stamped via `make docker`.

### View Real-Time Mesh Topology Graph
```bash
curl -s -H "Authorization: Bearer $TENANT_KEY" \
  "https://zro-plane.cubis.tech:443/api/v1/mesh/graph?network_id=c85e3068ac0cb812" | jq .
```
The graph is limited to the tenant's own network (naming another tenant's network is refused). It includes node status, overlay IPs, and `backbone_link`, `edge_mesh`, `p2p_direct` and `gateway_proxy` links.

### Subscribe to Real-Time Push Events
Events are filtered per tenant and network. Send the tenant API key (or a node token) in the `Authorization` header:
* **WebSocket**: `wss://zro-plane.cubis.tech:443/api/v1/ws` (cross-origin browsers need `allowed_origins`)
* **SSE**: `https://zro-plane.cubis.tech:443/api/v1/events`
* **gRPC stream** (if enabled): `StreamMeshEvents`

A subscriber that falls behind is disconnected rather than silently missing events; reconnect and resync.

### Automated Production Smoke Test
Drives the whole API with real credentials (needs `jq` and the `zro` binary):
```bash
PLANE_URL="https://zro-plane.cubis.tech:443" \
CLUSTER_SECRET="$CLUSTER_SECRET" ADMIN_API_KEY="$ADMIN_API_KEY" \
ZRO_CMD="zro" ./scripts/smoke_test.sh
```
Without `ZRO_CMD` it runs `zro` inside the compose plane container.

### Development & CI
`make race` is what CI runs (gofmt check, vet, `go test -race`, build), plus `govulncheck` and an image build. `make help` lists the rest.
