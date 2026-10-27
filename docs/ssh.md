# SSH over the mesh

Every zro machine can run a small SSH server that is reachable **only on the mesh**. It is off
until the machine turns it on.

```bash
# on the machine to log in to
sudo zro join --plane https://zro.example.com --token zro_tok_... --ssh-user ubuntu

# from any other machine on the network
sudo zro ssh ubuntu@db-1               # interactive shell
sudo zro ssh db-1 -- df -h             # one command; its exit status is passed through
sudo zro ssh -t db-1 -- htop           # a command that needs a terminal
```

`zro ssh` talks to the local node, so run it as the same user as the node (usually with `sudo`).
Without `user@`, it logs in as the user you ran `sudo` from.

## Who can log in

All three of these must hold:

1. **The network policy lets the client reach the SSH port.** Turning SSH on opens the port
   locally, and a network DENY rule still closes it, for example
   `zro acl add --from tag:contractor --to db-1 --ports ssh --action deny`.
2. **The client is who it says it is.** It must sign with the SSH key that the control plane holds
   for the machine at that mesh address. Each machine creates its own key (`<state_dir>/ssh.key`)
   and the plane hands it out. A relay, or someone who takes over an address, cannot log in.
3. **A grant names the local user.** Root is allowed only when it is listed.

```yaml
# zro.yaml (node section)
ssh:
  enabled: true
  port: 22                # on the mesh address only; use 2222 if the host's sshd holds 22
  allow:
    - from: "tag:admin"   # "*", a tag, a hostname or a mesh IP
      users: [ubuntu, root]
    - from: "ci-runner"
      users: [deploy]
  idle_timeout: 30m
  max_sessions: 10
```

The server's host key comes from the plane as well, so there is no "unknown host" prompt and no
`known_hosts` file to manage. Port forwarding, agent forwarding and sftp are refused. `scp` works
because it runs as a command.

## Audit

Each login and logout is recorded on the plane:

```console
$ zro audit -n 3
TIME                 ACTOR       ACTION      TARGET  DETAIL                      FROM
2026-10-27 10:39:16  node:db-1   ssh.logout  ubuntu  from web-1 after 12m4s      203.0.113.4
2026-10-27 10:27:12  node:db-1   ssh.login   ubuntu  from web-1 (100.64.0.2)     203.0.113.4
```

## Limits

- Interactive shells need Linux. macOS runs commands without a terminal. Windows has no server.
- In kernel mode the server binds the machine's mesh address. If the host's own sshd listens on
  `0.0.0.0:22`, that bind fails and the log says so. Set `ssh.port`; peers learn the new port by themselves.
