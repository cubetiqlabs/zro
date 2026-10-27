# Access policy

Every machine on a network enforces its own inbound policy on each packet, in both the
kernel (`tun`) and userspace (`--netstack`) modes, so no OS firewall is involved.

## How a packet is judged

For traffic **arriving** at a machine, the first of these that applies wins:

1. **Replies** to a connection the machine opened are let in.
2. **Network rules** (set on the control plane), lowest `priority` first. On a tie a DENY wins.
   A matching ALLOW opens a port the machine itself keeps closed. A matching DENY closes one it opened.
3. **Ping** is answered, unless the machine sets `allow_ping: false`.
4. **The machine's own allow list** (`allow:` in its config, plus `zro allow`).
5. **`default_deny`**, which is `true` by default, so the packet is dropped.

Once a connection is allowed, the rest of it skips the checks. ICMP errors (unreachable,
too big) always pass so path MTU discovery keeps working.

## On a machine

```yaml
# zro.yaml (node section)
allow: [ssh, postgres, "8000-8100/tcp"]
default_deny: true     # drop what nothing allows
allow_ping: true
tags: ["tag:db", "env:prod"]
```

```bash
sudo zro allow https 9090/tcp     # live; kept in <state_dir>/policy.json
sudo zro deny 9090/tcp            # entries from the config file are only removed there
sudo zro policy
```

Services: `ssh` (22/tcp), `http` (80/tcp), `https` (443/tcp), `dns` (53), `ping`, `rdp` (3389/tcp),
`postgres` (5432/tcp), `mysql` (3306/tcp), `redis` (6379/tcp). Ports: `5432/tcp`, `80,443/tcp`,
`8000-8100/udp`, `53` (any protocol).

## On the network

A rule names its source and destination with one word each. The word can be:
- `*`
- an IP or a CIDR
- a tag, which is anything containing a colon (`tag:web`, `role:db`)
- a machine's hostname, which is resolved to that machine's mesh IP

`ports` takes a service name or a port list, as above.

```bash
export ZRO_PLANE=https://zro.example.com ZRO_API_KEY=zro_key_... ZRO_NETWORK=a5b8112bcd5cdbd1

zro acl add --name "web to db" --from tag:web --to tag:db --ports postgres
zro acl add --name "no contractor ssh" --from tag:contractor --ports ssh --action deny --priority 5
zro acl list
zro acl test web-1 db-1 postgres     # ALLOW (rule "web to db", priority 100)
zro acl test web-1 db-1 https        # no rule matches: the destination's own allow list decides
zro acl rm <rule-id>
```

### Policy as a file

Keep the whole policy in git and apply it at once. The rules are validated together and swapped
in one transaction, so a typo changes nothing:

```yaml
# policy.yaml
rules:
  - {name: admins, from: "tag:admin", priority: 10}
  - {name: no contractor ssh, from: "tag:contractor", ports: ssh, action: deny, priority: 5}
  - {name: web to db, from: "tag:web", to: "tag:db", ports: postgres}
  - {name: monitoring, from: "100.64.0.0/24", ports: "9100/tcp"}
```

```bash
zro acl apply -f policy.yaml
zro acl export > policy.yaml          # the current policy, in the same form
```

The same through the API: `PUT /api/v1/networks/{id}/policy` with `{"rules": [...]}`.
See [api.md](api.md#4-control-access).

### Tags

A machine's tags come from its config (`tags:`). An operator can set them from the plane instead,
and those then win over the machine's own config:

```bash
zro nodes tag db-1 tag:db env:prod
```

Peers learn tag changes live, and the rules use them immediately.
