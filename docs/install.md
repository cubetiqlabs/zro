# Installing the zro CLI

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are published on the
[Releases page](https://github.com/sombochea/zro/releases). Each release carries a
`checksums.txt` that the installers and `zro update` verify before installing anything.

## Linux and macOS

```bash
curl -fsSL https://raw.githubusercontent.com/sombochea/zro/main/scripts/install.sh | sh
```

Installs to `/usr/local/bin` if writable, otherwise `~/.local/bin`. Options (environment):

| Variable | Meaning |
|---|---|
| `ZRO_VERSION` | Release tag to install, e.g. `v0.1.0` (default: latest) |
| `ZRO_INSTALL_DIR` | Target directory |

## Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/sombochea/zro/main/scripts/install.ps1 | iex
```

Installs `zro.exe` to `%LOCALAPPDATA%\zro` and adds it to your user `PATH`. Same
`ZRO_VERSION` / `ZRO_INSTALL_DIR` variables.

## Docker

```bash
docker pull ghcr.io/sombochea/zro:latest        # or :0.1.0 / :0.1
docker run --rm ghcr.io/sombochea/zro version
```

The image is multi-arch (amd64, arm64). See [deployment.md](deployment.md) for running the plane, edges and gateways.

## Platform notes

The client works everywhere, but the kernel TUN interface and route programming are
Linux-only. On macOS and Windows run the node in userspace mode (`interface_mode: netstack`):
the overlay is then reachable through the node's built-in SOCKS5 proxy and tunnels instead of
a system network interface. Userspace mode is exercised on macOS by the test suite; Windows builds are compiled in CI but not yet run there.

## Updating

```bash
zro update            # install the latest release
zro update --check    # only report
zro update --version v0.1.0   # pin or roll back
```

`zro update` downloads the archive for your platform, verifies its SHA-256 against
`checksums.txt`, and replaces the running executable; restart long-running services
afterwards. If the binary lives in a root-owned directory, run it with `sudo`.

**Update notices.** Client commands (`node`, `token`, `network`, `p2p`, `version`) print a
one-line notice on stderr when a newer release exists. The check runs at most once a day
(cached in the state directory), times out after 3 seconds, never installs anything, and is
skipped for development builds and for the servers (`plane`, `edge`, `gw`). Turn it off with
`ZRO_NO_UPDATE_CHECK=1`. Docker users update by pulling a newer tag.

## Running the node as a service

Examples to adapt: [`examples/zro-node.service`](examples/zro-node.service) (systemd) and
[`examples/tech.cubis.zro-node.plist`](examples/tech.cubis.zro-node.plist) (launchd). On Windows,
wrap `zro.exe node` with a service manager such as [NSSM](https://nssm.cc/) or
`New-Service`.

Config lives in `zro.yaml` (see [`zro.example.yaml`](../zro.example.yaml)); every key is
also an environment variable, `ZRO_NODE_PLANE_ENDPOINT` and so on.
