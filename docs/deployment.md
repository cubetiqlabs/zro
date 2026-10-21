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
  │ (Postgres)│ │(App Server│ ◄────────────────────────► │   Plane   │ (:8443, :9443)
  │:5432/tcp  │ │ Client)   │                            │ +Postgres │
  └───────────┘ └───────────┘                            └───────────┘
```

### Port Matrix

| Component | Port / Protocol | Exposure | Purpose |
| :--- | :--- | :--- | :--- |
| **Control Plane** | `8443/tcp` | Private / Internal | REST API & RFC 6455 WebSockets Event Hub |
| **Control Plane** | `9443/tcp` | Private / Internal | Binary gRPC Control Plane Service (`StreamMeshEvents`) |
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
assigns the enrolled overlay addresses, and installs host/subnet routes pointing
at the TUN device (via `ip`). The container image includes `iproute2`. On hosts
without `NET_ADMIN` or `/dev/net/tun`, the node/gateway falls back to an
in-memory TUN, which keeps control-plane and tests working but does not forward
host traffic.

Edge PoPs additionally enable IPv4/IPv6 forwarding and route the overlay CIDRs
into their TUN so they can relay traffic between peers. If the container runtime
blocks `/proc/sys` writes, set forwarding on the host and pass the sysctls in.

---

## 3. Production Deployment Topologies

### Option A: Distributed Cloud Cluster (Recommended for Production)

Deploy each role onto dedicated infrastructure across regions:

#### 1. Database (PostgreSQL 15+)
Provision Amazon RDS, GCP Cloud SQL, or HA PostgreSQL:
```sql
CREATE DATABASE zro;
CREATE USER zro WITH ENCRYPTED PASSWORD 'your-strong-db-password';
GRANT ALL PRIVILEGES ON DATABASE zro TO zro;
```

#### 2. Control Plane (HA API Server)
Run 2+ instances behind a private cloud load balancer:
```bash
# Generate a cryptographically secure cluster secret
export CLUSTER_SECRET=$(openssl rand -hex 32)
export DATABASE_DSN="postgres://zro:your-strong-db-password@postgres-ha.internal:5432/zro?sslmode=require"

docker run -d \
  --name zro-plane \
  --restart always \
  -p 8443:8443 -p 9443:9443 \
  -e ZRO_MODE=plane \
  -e ZRO_CONTROL_PLANE_LISTEN_ADDR=":8443" \
  -e ZRO_CONTROL_PLANE_GRPC_LISTEN_ADDR=":9443" \
  -e ZRO_CONTROL_PLANE_PUBLIC_URL="https://zro-plane.cubis.tech:443" \
  -e ZRO_CONTROL_PLANE_DATABASE_DRIVER="postgres" \
  -e ZRO_CONTROL_PLANE_DATABASE_DSN="$DATABASE_DSN" \
  -e ZRO_CONTROL_PLANE_SECRET_KEY="$CLUSTER_SECRET" \
  -e ZRO_CONTROL_PLANE_DEFAULT_CIDR_V4="100.64.0.0/10" \
  -e ZRO_CONTROL_PLANE_DEFAULT_CIDR_V6="fd00:cafe::/64" \
  cubis/zro:latest plane
```

#### 3. Edge Data Plane PoPs (Multi-Region VPS / Bare Metal)
Deploy Edge nodes in each target geography (`KH`, `SG`, `US`, `HK`, `DE`):
```bash
docker run -d \
  --name zro-edge \
  --restart always \
  --network host \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv6.conf.all.forwarding=1 \
  --device /dev/net/tun:/dev/net/tun \
  -e ZRO_MODE=edge \
  -e ZRO_EDGE_POP_CODE="KH" \
  -e ZRO_EDGE_REGION="Asia/Phnom_Penh" \
  -e ZRO_EDGE_PUBLIC_ENDPOINT="auto" \
  -e ZRO_EDGE_LISTEN_PORT=51820 \
  -e ZRO_EDGE_INTERFACE_NAME="zro-edge" \
  -e ZRO_EDGE_EDGE_API_KEY="$EDGE_API_KEY" \
  -e ZRO_EDGE_PLANE_ENDPOINT="https://zro-plane.cubis.tech:443" \
  cubis/zro:latest edge
```
> **Tip:** Setting `ZRO_EDGE_PUBLIC_ENDPOINT=auto` automatically discovers the public IPv4 via STUN and reflexive lookup.

#### 4. Dual Ingress Gateways (`gw1`, `gw2`) with Anycast/DNS Failover
Assign both Gateway public IPs to your public domain DNS (e.g. `api.example.com` -> `1.1.1.1`, `1.1.1.2`):
```bash
docker run -d \
  --name zro-gw \
  --restart always \
  --network host \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  --device /dev/net/tun:/dev/net/tun \
  -v /var/lib/zro/certs:/certs \
  -e ZRO_MODE=gw \
  -e ZRO_GATEWAY_HOSTNAME="gw1" \
  -e ZRO_GATEWAY_PLANE_ENDPOINT="https://zro-plane.cubis.tech:443" \
  -e ZRO_GATEWAY_LISTEN_HTTP=":80" \
  -e ZRO_GATEWAY_LISTEN_HTTPS=":443" \
  -e ZRO_GATEWAY_AUTO_TLS="true" \
  -e ZRO_GATEWAY_DOMAIN="example.com" \
  -e ZRO_GATEWAY_CERT_DIR="/certs" \
  cubis/zro:latest gw
```

---

### Option B: Standalone All-In-One (Docker Compose)

For branch offices, edge servers, or staging environments:

```bash
# 1. Start the stack
docker compose up -d

# 2. Check cluster status
docker compose ps
```

---

## 4. Client Node Setup & Zero-Trust Inbound Firewall

### Step 1: Provision Network (ZeroTier 16-hex ID)
```bash
curl -s -X POST https://zro-plane.cubis.tech:443/api/v1/networks \
  -H "Content-Type: application/json" \
  -d '{"name":"Production Mesh","ipv4_cidr":"100.64.0.0/10","ipv6_cidr":"fd00:cafe::/64"}'
# Returns: {"id":"c85e3068ac0cb812", ...}
```

### Step 2: Generate WireGuard Key & Enrollment Token
```bash
# Generate keypair on client machine
zro keygen
# Private Key: <CLIENT_PRIVKEY>
# Public Key:  <CLIENT_PUBKEY>

# Generate token bound to public key
zro token \
  --secret "$CLUSTER_SECRET" \
  --network-id "c85e3068ac0cb812" \
  --hostname "db-server-01" \
  --pubkey "<CLIENT_PUBKEY>"
# Returns: zro_tok_eyJhbGciOi...
```

### Step 3: Run Node with Zero-Trust "Default Deny All" Policy
Configure [`zro.yaml`](file:///Users/sombochea/projects/zro/zro.example.yaml):
```yaml
mode: node
node:
  hostname: "db-server-01"
  network_id: "c85e3068ac0cb812"
  enrollment_token: "zro_tok_eyJhbGciOi..."
  plane_endpoint: "https://zro-plane.cubis.tech:443"
  interface_name: "zro0"
  listen_port: 0 # Shared WireGuard/STUN UDP port; 0 = ephemeral
  enable_p2p: true
  default_deny: true # Drops all incoming connections by default
  allowed_inbound_ports:
    - "5432/tcp"     # Expose PostgreSQL to authenticated mesh nodes only
  tags:
    - "role:db"
    - "env:production"
```

Start the daemon:
```bash
zro node -c /etc/zro/zro.yaml
```

---

## 5. Exposing Services via Multi-Node Ingress Tunnels

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
      protocol: "http"
```

Gateways immediately pick up the route via the real-time event stream (`/api/v1/ws`) and load balance traffic across all nodes exposing `api.example.com` with active health checks.

---

## 6. Microsegmentation & ACL Rules

Enforce network-wide access control via the Control Plane API:

```bash
# Allow web tier to communicate with Postgres on port 5432
curl -s -X POST https://zro-plane.cubis.tech:443/api/v1/acl/rules \
  -H "Content-Type: application/json" \
  -d '{
    "network_id": "c85e3068ac0cb812",
    "priority": 10,
    "source_tag": "role:web",
    "dest_tag": "role:db",
    "protocol": "tcp",
    "ports": "5432",
    "action": "ALLOW"
  }'

# View all rules for the network
curl -s "https://zro-plane.cubis.tech:443/api/v1/acl/rules?network_id=c85e3068ac0cb812"
```

---

## 7. Operational Health & Live Monitoring

### View Real-Time Mesh Topology Graph
Inspect the live status of all Edge PoPs, Gateways, Nodes, and interconnect links:
```bash
curl -s "https://zro-plane.cubis.tech:443/api/v1/mesh/graph" | jq .
```
Response includes:
* `nodes`: Status (`online`/`offline`), last seen timestamps, allocated overlay IPs, and allowed ports.
* `edges`: Directed links for `backbone_link`, `edge_mesh`, `p2p_direct`, and `gateway_proxy`.
* `stats`: Online node counts, total links, and Edge PoP health.

### Subscribe to Real-Time Push Events
* **WebSocket**: `wss://zro-plane.cubis.tech:443/api/v1/ws`
* **SSE**: `https://zro-plane.cubis.tech:443/api/v1/events`
* **gRPC Stream**: `zro-plane.cubis.tech:9443` -> `StreamMeshEvents`

### Automated Production Smoke Test
Verify the deployment end-to-end:
```bash
PLANE_URL="https://zro-plane.cubis.tech:443" \
GW_URL="https://api.example.com" \
./scripts/smoke_test.sh
```
