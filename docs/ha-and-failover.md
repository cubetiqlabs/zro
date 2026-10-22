# Availability and failover

## Rejoining without a fresh enrollment token

A node keeps its identity in `state_dir` (`node.key`, `node.token`). On restart it
re-enrolls presenting the saved node token, which the plane accepts instead of an enrollment
token: the node keeps its ID and address, even when the enrollment token in its config has
expired. A node whose `state_dir` was lost needs a new token (and its old record removed with
`DELETE /api/v1/nodes/{id}`).

## PoP failover and re-homing

Each node has a *home* PoP, chosen by latency at enrollment, and a backup. The node probes
its home every 15 s and reports the result (`POST /api/v1/probes`). When the home stops
answering, the node switches to the backup, and the plane, which scores PoPs from those
reports and ignores unhealthy ones, moves the node's home as well. It then emits
`node_rehomed` and `mesh_graph_updated`, and every edge re-plans its routes, so other PoPs
send the node's traffic to the new home instead of the dead one.

A healthy home is never displaced: nodes only probe their home, and PoPs without a recent
probe score as 500 ms.

## DERP relay limits

Nodes behind UDP-hostile networks reach the PoP over the TCP relay. Because any key in the
mesh may use it, the relay is bounded (set under `edge:`; `0` disables a limit):

| Key | Default | Meaning |
|---|---|---|
| `derp_max_conns` | 10000 | open relay connections, including ones still handshaking |
| `derp_max_conns_per_ip` | 256 | per source IP (a NAT shares one) |
| `derp_packets_per_sec` | 20000 | per session |
| `derp_bytes_per_sec` | 67108864 | per session (64 MiB/s) |

Over-rate packets are dropped, not queued or disconnected; WireGuard retransmits, so a
flooding client only hurts itself. Connection limits are checked before the handshake, so
they also cover floods of unauthenticated connections. Each is also an env var, for example
`ZRO_EDGE_DERP_MAX_CONNS_PER_IP=64`.
