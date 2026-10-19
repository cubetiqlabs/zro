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

### 1. Build Binary
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

## Configuration

See [`zro.example.yaml`](zro.example.yaml) for full configuration parameters. All options can also be overridden using environment variables prefixed with `ZRO_` (e.g. `ZRO_CONTROL_PLANE_DATABASE_DSN`).

---

## Running Tests

```bash
go test -v -race ./...
```
