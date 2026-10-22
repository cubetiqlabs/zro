# ZRO (Zero-Routing Overlay)

Enterprise-grade global networking fabric and virtual ether-switch built in Go. Integrates userspace WireGuard, smart routing, IPless nodes, zero-trust ACLs, and cloud-native load balancing.

---

## Architecture Overview

- **`zro-plane` (Control Plane)**: Central API, GORM + PostgreSQL persistence, deterministic overlay IPAM, and real-time delta config replication.
- **`zro-edge` (Global Data Plane PoPs)**: Public IP nodes (e.g., KH, SG, HK, US, DE) forming an inter-PoP WireGuard mesh backbone with STUN and fallback relaying.
- **`zro-node` (Client / Peer Agent)**: IPless nodes (no public IP required). Communicates direct P2P via STUN NAT hole punching with automatic fallback to nearest Edge PoP, plus `cloudflared`-style local service tunneling.
- **`zro-gw` (Ingress Gateway)**: L4/L7 reverse proxy and cloud-native load balancer (Round-Robin, LeastConn, Latency-smart).

---

## Quickstart

### 1. Install (or build)

```bash
curl -fsSL https://raw.githubusercontent.com/sombochea/zro/main/scripts/install.sh | sh   # Windows & Docker: docs/install.md
```

From source:
```bash
go build -o bin/zro ./cmd/zro
```

### 2. Generate WireGuard Keys
```bash
./bin/zro keygen
```

### 3. Generate Node Enrollment Token
```bash
./bin/zro token \
  --secret "my-cluster-secret" \
  --network-id "b7c2512a-7c2a-4864-b767-a4d45850cd15" \
  --hostname "node-01"
```

### 4. Run Components

**Start Control Plane:**
```bash
./bin/zro plane --config zro.yaml
```

**Start Edge PoP (Data Plane):**
```bash
./bin/zro edge --config zro.yaml
```

**Start Client / Peer Node:**
```bash
./bin/zro node --config zro.yaml
```

**Start Ingress Gateway:**
```bash
./bin/zro gw --config zro.yaml
```

---

## Documentation

- [Install and update](docs/install.md): installers for Linux/macOS/Windows, `zro update`, services.
- [Deployment](docs/deployment.md): standalone and cluster setups, security model, operations.
- [API guide](docs/api.md) and [OpenAPI spec](api/openapi/openapi.yaml): REST contract with worked examples.
- [Availability and failover](docs/ha-and-failover.md): rejoining, PoP re-homing, relay limits.

---

## Docker & Production Deployment

### 1. Local / Standalone Mesh Simulation (Docker Compose)
Starts PostgreSQL, Control Plane (`:8443`), Edge PoPs in Cambodia (`:51820/udp`) and Singapore (`:51821/udp`), and Ingress Gateway (`:8080`):
```bash
cp .env.example .env        # set CLUSTER_SECRET, EDGE_API_KEY (and ADMIN_API_KEY) - compose refuses to start without the first two
docker compose up -d
```

### 2. Run Production Smoke Tests
Drives the running stack through its authenticated API (needs `jq`):
```bash
CLUSTER_SECRET=... ADMIN_API_KEY=... ./scripts/smoke_test.sh
```

### 3. Production Cloud Cluster Deployment
For multi-server topologies (AWS, DigitalOcean, GCP, Bare-Metal):
- **Deploy Control Plane** (behind cloud load balancer connected to managed PostgreSQL):
  ```bash
  docker compose -f docker-compose.cluster.yml --profile plane up -d
  ```
- **Deploy Standalone Edge PoP** on a VPS with a public IP (uses host networking for line-rate WireGuard performance):
  ```bash
  POP_CODE=KH REGION=Asia/Phnom_Penh PUBLIC_ENDPOINT=173.1.1.1:51820 EDGE_API_KEY=... \
  docker compose -f docker-compose.cluster.yml --profile edge up -d
  ```
- **Deploy Ingress Gateway** with automatic TLS termination:
  ```bash
  docker compose -f docker-compose.cluster.yml --profile gateway up -d
  ```

---

## Running Tests

```bash
# Unit & integration tests
go test -v -race ./...

# Control plane + real edge + two nodes in one process (WireGuard, netstack, ACLs)
go test -v -race ./test/e2e/... ./test/smoke/...
```

`make help` lists the build, lint, vulnerability-scan and image targets. See
[`docs/deployment.md`](docs/deployment.md) for the security model and a full production guide.
