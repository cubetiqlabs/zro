# Getting started

Three steps: **run the control plane, make a network, join machines to it.**
Joining a machine needs only two things: the plane's URL and a token.

```
 operator                                     every other machine
 ────────                                     ───────────────────
 1. run the control plane (once)
 2. create a network, mint a token  ───────►  3. zro join --plane URL --token TOKEN
```

## 1. Run the control plane (operator, once)

On a server with Docker. The plane needs a public HTTPS URL, so put a TLS reverse proxy
(Caddy, nginx, a cloud load balancer) in front of port 8443.

```bash
git clone https://github.com/cubetiqlabs/zro && cd zro
cp .env.example .env
```

Edit `.env` and set these (generate each secret with `openssl rand -hex 32`):

| Variable | Value |
|---|---|
| `CLUSTER_SECRET` | signs enrollment tokens |
| `EDGE_API_KEY` | shared key for first-time PoP registration |
| `ADMIN_API_KEY` | lets you create tenants |
| `POSTGRES_PASSWORD` | use hex, e.g. `openssl rand -hex 24` |
| `PUBLIC_URL` | the HTTPS URL machines will use, e.g. `https://zro.example.com` |

```bash
docker compose -f docker-compose.prod.yml up -d
curl -fsS http://127.0.0.1:8443/readyz        # ready when this succeeds
```

For a quick local try without Docker: `zro plane` runs with SQLite and needs no setup (not for production).

## 2. Create a network and a join token (operator)

```bash
PLANE=https://zro.example.com
set -a; . ./.env; set +a

# A tenant owns networks. The api_key is shown ONCE; save it.
curl -s -X POST $PLANE/api/v1/tenants -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H 'Content-Type: application/json' -d '{"name":"Acme","slug":"acme"}'
export KEY=zro_key_...            # the api_key from the reply

# A network is the private overlay. CIDRs default if omitted; the reply holds its "id".
curl -s -X POST $PLANE/api/v1/networks -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' -d '{"name":"Production"}'
NET=...                           # the id from the reply
```

Now mint a token. Each token is **single use** (one per machine) and expires; pick whichever
way fits. All three produce the same `zro_tok_…` token.

| You have | Do this |
|---|---|
| shell access to the plane | `docker compose -f docker-compose.prod.yml exec plane zro token --network-id $NET --hostname web-1` |
| your tenant API key | `curl -sX POST $PLANE/api/v1/networks/$NET/tokens -H "X-API-Key: $KEY" -d '{"hostname":"web-1","hours":24}'` |
| the cluster secret only | open `$PLANE/ui/tokens`, or `curl -sX POST $PLANE/api/v1/tokens -H "X-Cluster-Secret: $CLUSTER_SECRET" -d '{"network_id":"'$NET'","hostname":"web-1"}'` |

The last two answer with the token and a ready-made command:

```json
{"token":"zro_tok_eyJuZXQi…","network_id":"a5b8112bcd5cdbd1","node_type":"peer",
 "expires_at":"2026-10-25T09:33:11Z",
 "join_command":"zro join --plane https://zro.example.com --token zro_tok_eyJuZXQi…"}
```

`zro token --plane $PLANE --api-key $KEY --network-id $NET` does the tenant-key call for you.
`hostname` (optional) locks the token to one machine name; `node_type` is `peer` (default) or `gateway`.
The secret form refuses to work until `CLUSTER_SECRET` is changed from the shipped placeholder, and
pauses for a minute after 10 wrong secrets.

## 3. Join a machine

Install the CLI (Linux/macOS; Windows and Docker in [install.md](install.md)):

```bash
curl -fsSL https://raw.githubusercontent.com/cubetiqlabs/zro/main/scripts/install.sh | sh
```

Join:

```bash
sudo zro join --plane https://zro.example.com --token zro_tok_...
```

You will see `Enrolled into overlay mesh overlay_ipv4=100.64.0.2`. That is the machine's
address on the network; other joined machines can reach it there.

No root, or no `/dev/net/tun` (containers, locked-down hosts)? Add `--netstack`; it runs
fully in userspace with no host interface:

```bash
zro join --plane https://zro.example.com --token zro_tok_... --netstack
```

Options (all optional): `--hostname NAME` (default: the machine's hostname).

### What happens on restart

The machine keeps its identity in `/var/lib/zro` (or `~/.local/state/zro` when not root), so
re-running `zro join` with the same flags returns the **same address**. The token may be
expired by then; it is only needed the first time.

### Keep it running

```bash
# systemd: see install.md "Running the node as a service", or:
docker run -d --restart always --cap-add NET_ADMIN --device /dev/net/tun \
  -v zro-state:/var/lib/zro ghcr.io/cubetiqlabs/zro \
  join --plane https://zro.example.com --token zro_tok_...
```

## 4. Check it works

Join a second machine with a second token, then from the first:

```bash
ping 100.64.0.3                       # the second machine's overlay address
ping 100.127.255.254                  # an edge PoP's own mesh address (see "Edge PoP" below)
```

`ping` (ICMP) is always allowed between mesh members: the inbound policy below applies to TCP ports.
It needs the default kernel interface; a `--netstack` machine speaks TCP only and cannot answer ping.
Traffic goes straight between machines when their NATs allow and through the nearest edge PoP otherwise.

By default machines **deny all inbound traffic**. Open what you need with an ACL rule
([api.md §4](api.md)) or, for one machine, `allowed_inbound_ports` in its config file
(`zro.example.yaml` lists every option).

## Running an edge PoP on a public host

Open **both** `51821/udp` and `51821/tcp` (TCP is the relay fallback for networks that block UDP).

```yaml
services:
  edge:
    image: ghcr.io/cubetiqlabs/zro:latest
    command: ["edge"]
    restart: always
    cap_add: [NET_ADMIN]
    devices: ["/dev/net/tun:/dev/net/tun"]
    sysctls: [net.ipv4.ip_forward=1, net.ipv6.conf.all.forwarding=1]  # not allowed with network_mode: host
    ports: ["51821:51821/udp", "51821:51821/tcp"]
    volumes: ["edge-state:/var/lib/zro"]
    environment:
      ZRO_EDGE_POP_CODE: KH
      ZRO_EDGE_PLANE_ENDPOINT: https://zro.example.com
      ZRO_EDGE_EDGE_API_KEY: <the plane's EDGE_API_KEY>
      ZRO_EDGE_LISTEN_PORT: 51821
      ZRO_EDGE_STATE_DIR: /var/lib/zro
volumes: {edge-state: {}}
```

With `network_mode: host`, run `sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1` on the host instead.
The edge logs `Edge mesh synchronized` once it has the node list, and `PoP mesh address assigned` with its own
address on the network (allocated from the top of the default overlay range, e.g. `100.127.255.254`; it appears
on the `zro-edge` interface). Networks created with a custom CIDR should sit inside the default range
(`100.64.0.0/10`) for nodes to reach the PoP addresses.

Nodes probe every PoP every 15s, follow the plane's choice of nearest PoP, and fail over by themselves when their
PoP stops answering; they also keep retrying enrollment while the plane is down.

## Troubleshooting

| Message | Fix |
|---|---|
| `enrollment rejected … 401` | token expired, wrong, or minted with a different `CLUSTER_SECRET` |
| `… 409` / token already used | tokens are single use; mint a new one |
| `hostname does not match token` | the token is locked to a name; pass `--hostname NAME` |
| `connection refused` / TLS errors | check `--plane` is the HTTPS URL and the proxy forwards to port 8443 |
| `operation not permitted` creating interface | run with `sudo`, or use `--netstack` |
| `Heartbeat … connection reset by peer` (edge behind Cloudflare/a proxy) | a proxy closed an idle connection; the edge retries on a fresh one automatically, so a single warning is harmless |
| edge works but machines cannot reach each other | the edge needs forwarding: set the two `sysctls` above; on a host with a firewall the edge adds its own `FORWARD` rule (needs `iptables`) |
| `ping` works to the edge but not to a machine | check both machines are enrolled in the **same network** and that UDP/TCP 51821 is open on the edge |
| plane exits at start | a required `.env` value is missing or weak (`CLUSTER_SECRET`) |

More: [deployment.md](deployment.md) (edges, gateways, HA), [api.md](api.md) (REST API).
