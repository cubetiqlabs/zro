# Control plane API

The REST API lives under `/api/v1`. The machine-readable contract is
[`api/openapi/openapi.yaml`](../api/openapi/openapi.yaml) (OpenAPI 3.1); a running plane
serves the same file at `GET /api/v1/openapi.yaml`, so you can load it into Swagger UI,
Redoc, Postman or a client generator:

```bash
curl -s https://PLANE/api/v1/openapi.yaml -o zro-openapi.yaml
npx @redocly/cli preview-docs zro-openapi.yaml        # browse it
npx @openapitools/openapi-generator-cli generate -i zro-openapi.yaml -g typescript-fetch -o ./zro-client
```

Examples below assume:

```bash
export PLANE=http://localhost:8080
export ADMIN_KEY=...     # control_plane.admin_api_key
```

## Who calls what

| Audience | Credential | Header | Typical calls |
|---|---|---|---|
| Operator | `admin_api_key` | `X-Admin-Key` | create tenants, remove PoPs |
| Tenant (web UI, scripts) | `zro_key_…` | `Authorization: Bearer` or `X-API-Key` | networks, nodes, ACLs, topology |
| Node / gateway | `zro_node_…` | `Authorization: Bearer` or `X-Node-Token` | enroll, probes, tunnels |
| Edge PoP | `zro_pop_…` | `X-Edge-Key` | register, heartbeat, sync |

## Conventions

**Errors** are always JSON, whatever the endpoint:

```json
{"error":{"code":"unauthorized","message":"unauthorized: invalid or inactive API key","request_id":"5bece6574dabc7ee"}}
```

`code` is one of `invalid_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`,
`rate_limited`, `internal`. Quote `request_id` (also the `X-Request-ID` response header)
when reporting a problem; send your own `X-Request-ID` to correlate with your logs.

**Pagination.** Tenant and admin lists take `?limit=` (1–500, default 100) and `?cursor=`:

```bash
curl -s "$PLANE/api/v1/nodes?network_id=$NET&limit=50" -H "Authorization: Bearer $KEY"
# {"items":[...],"next_cursor":"NTA"}   -> repeat with &cursor=NTA until next_cursor is absent
```

`/pops`, `/network/{id}/peers`, `/tunnels` and `/acl/policy` are read by nodes at startup
and return plain arrays.

**Not found vs forbidden.** A resource that belongs to another tenant answers `404`, so
IDs cannot be probed across tenants.

## Walkthrough: tenant → network → node

### 1. Create a tenant (operator)

```bash
curl -s -X POST $PLANE/api/v1/tenants -H "X-Admin-Key: $ADMIN_KEY" \
  -d '{"name":"Acme Corp","slug":"acme"}'
```
```json
{"id":"81d5e16f-946d-4a45-92ce-9fc8c9f439d3","name":"Acme Corp","slug":"acme","is_active":true,
 "created_at":"2026-10-22T09:33:11+07:00","api_key":"zro_key_a82193ba…"}
```

The `api_key` is shown **once**. Lose it and you rotate:
`POST /api/v1/tenants/{id}/rotate-key` (the old key dies immediately).

### 2. Create a network (tenant)

```bash
export KEY=zro_key_a82193ba…
curl -s -X POST $PLANE/api/v1/networks -H "Authorization: Bearer $KEY" \
  -d '{"name":"production","dns_domain":"prod.zro.internal"}'
```
```json
{"id":"a5b8112bcd5cdbd1","tenant_id":"81d5e16f-…","name":"production","slug":"production",
 "ipv4_cidr":"100.64.0.0/10","ipv6_cidr":"fd00:cafe::/64","dns_domain":"prod.zro.internal",
 "mtu":1420,"is_active":true,"created_at":"…","updated_at":"…"}
```

CIDRs are fixed at creation; `PATCH /api/v1/networks/{id}` changes only `name`,
`dns_domain` and `is_active`.

### 3. Mint an enrollment token and enroll a node

```bash
zro keygen                                   # prints a private and a public key
zro token --secret "$SECRET_KEY" --network-id a5b8112bcd5cdbd1 --hostname app-01 --hours 24
```

`zro node` does the next call for you; by hand it is:

```bash
curl -s -X POST $PLANE/api/v1/enroll -d '{
  "token": "zro_tok_eyJuZXQi…",
  "public_key": "OeCGN40+qI+UMcUQs/OxIvCteTiQMR86FddAF51k8Ts=",
  "hostname": "app-01",
  "tags": ["tag:web"],
  "endpoints": ["203.0.113.7:51820"]
}'
```
```json
{"node_id":"1eb43e8c-2cc6-4001-bea4-835ca8497097","network_id":"a5b8112bcd5cdbd1",
 "node_token":"zro_node_9d7dc65d…","overlay_ipv4":"100.64.0.2","overlay_ipv6":"fd00:cafe::6440:2",
 "dns_domain":"prod.zro.internal","mtu":1420,"allowed_ips":["100.64.0.2/32","fd00:cafe::6440:2/128"],
 "default_deny":true,"primary_pop":{…},"peers":[…],"acl_rules":[]}
```

Keep `node_token`: it authenticates every later node call.

**Rejoining after a restart.** Present the saved node token and the same key. No enrollment
token is needed, so this still works after the original one expired:

```bash
curl -s -X POST $PLANE/api/v1/enroll -H "Authorization: Bearer $NODE_TOKEN" \
  -d '{"public_key":"OeCGN40+…","hostname":"app-01"}'      # 200, same node_id and address, fresh node_token
```

Without the node token the same call is `401`; with an enrollment token but no node token for
a key that is already enrolled it is `409` (so a leaked token cannot take a node over).

### 4. Allow traffic with an ACL rule

Nodes default to deny. Allow `tag:web` to reach `tag:db` on 5432:

```bash
curl -s -X POST $PLANE/api/v1/acl/rules -H "Authorization: Bearer $KEY" -d '{
  "network_id":"a5b8112bcd5cdbd1","priority":10,
  "source_tag":"tag:web","dest_tag":"tag:db","protocol":"tcp","ports":"5432","action":"ALLOW"}'
```

Rules apply in ascending `priority` and reach nodes immediately. To change a rule, create
the new one, then `DELETE /api/v1/acl/rules/{id}` the old one.

### 5. Inspect

```bash
curl -s "$PLANE/api/v1/nodes?network_id=a5b8112bcd5cdbd1" -H "Authorization: Bearer $KEY"
curl -s "$PLANE/api/v1/nodes/1eb43e8c-…"                    -H "Authorization: Bearer $KEY"
curl -s "$PLANE/api/v1/mesh/graph?network_id=a5b8112bcd5cdbd1" -H "Authorization: Bearer $KEY"
curl -N "$PLANE/api/v1/events"                              -H "Authorization: Bearer $KEY"   # live changes (SSE)
```

## Live updates (for a web UI)

`GET /api/v1/events` (SSE) and `GET /api/v1/ws` (WebSocket) push changes scoped to the
caller's networks: `node_joined`, `node_left`, `node_rehomed`, `mesh_graph_updated`,
`acl_rules_updated`, `pop_status_changed`. Fetch the lists once, then apply events and
re-fetch `mesh/graph` on `mesh_graph_updated`.

```
event: node_rehomed
data: {"network_id":"a5b8112bcd5cdbd1","node_id":"1eb43e8c-…","from_pop":"KH","to_pop":"SG"}
```

Browsers cannot set headers on `EventSource`; use `fetch` streaming, or the WebSocket
endpoint, and list your UI's origin in `control_plane.allowed_origins`.

## Stability

`/api/v1` is additive: new fields and endpoints may appear, existing ones are not removed or
repurposed. Ignore unknown fields. Breaking changes would ship under `/api/v2`.
The spec is checked in CI: a test fails when a route is added without being documented.
