#!/bin/sh
# Install the zro CLI on Linux or macOS.
#   curl -fsSL https://raw.githubusercontent.com/sombochea/zro/main/scripts/install.sh | sh
# Environment: ZRO_VERSION (e.g. v0.1.0, default: latest), ZRO_INSTALL_DIR
# (default: /usr/local/bin if writable, else ~/.local/bin).
set -eu

REPO="sombochea/zro"
BASE="${ZRO_DOWNLOAD_BASE:-https://github.com/$REPO/releases}"

die() { echo "install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
need curl; need tar

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); on Windows use scripts/install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

tag="${ZRO_VERSION:-}"
if [ -z "$tag" ]; then
  # /releases/latest redirects to /releases/tag/<tag>; this avoids the API rate limit.
  tag=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$BASE/latest") || die "cannot look up the latest release"
  tag=${tag##*/}
fi
version=${tag#v}
name="zro_${version}_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading zro $tag ($os/$arch)..."
curl -fsSL -o "$tmp/$name" "$BASE/download/$tag/$name" || die "no release asset $name for $tag"
curl -fsSL -o "$tmp/checksums.txt" "$BASE/download/$tag/checksums.txt" || die "cannot download checksums.txt"

want=$(awk -v n="$name" '$2 == n { print $1 }' "$tmp/checksums.txt")
[ -n "$want" ] || die "checksums.txt has no entry for $name"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$name" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then got=$(shasum -a 256 "$tmp/$name" | awk '{print $1}')
else die "sha256sum or shasum is required to verify the download"; fi
[ "$got" = "$want" ] || die "checksum mismatch for $name; refusing to install"

tar -xzf "$tmp/$name" -C "$tmp" zro

dir="${ZRO_INSTALL_DIR:-}"
if [ -z "$dir" ]; then
  if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
fi
mkdir -p "$dir"
install -m 0755 "$tmp/zro" "$dir/zro"
echo "Installed $dir/zro"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH to run 'zro'." ;; esac
"$dir/zro" version
