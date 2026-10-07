#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <version|latest>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

repo=https://github.com/FujiHaruka/credshim
bin=/Library/CredShim/bin/credshim

[[ -x $bin ]] || { echo "$bin is not installed; install it first with: sudo ./credshim service install" >&2; exit 1; }
case $(uname -m) in
  arm64) target=aarch64-apple-darwin ;;
  *) echo "no release binary for $(uname -m) Macs; build from source and run: sudo ./credshim service install --upgrade" >&2; exit 1 ;;
esac

version=${1#v}
if [[ $version == latest ]]; then
  latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$repo/releases/latest")
  version=${latest##*/tag/v}
fi
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $version" >&2; exit 1; }

installed=$("$bin" --version)
installed=${installed##* }
if [[ $installed == "$version" ]]; then
  echo "credshim $version is already installed"
  exit 0
fi

archive=credshim-$version-$target.tar.gz
curl -fsSL -o "$tmp/$archive" "$repo/releases/download/v$version/$archive" || { echo "could not download $archive from release v$version" >&2; exit 1; }
curl -fsSL -o "$tmp/SHA256SUMS" "$repo/releases/download/v$version/SHA256SUMS"
(cd "$tmp" && grep " $archive\$" SHA256SUMS | shasum -a 256 -c)
tar -xzf "$tmp/$archive" -C "$tmp" credshim
downloaded=$("$tmp/credshim" --version)
[[ ${downloaded##* } == "$version" ]] || { echo "the $archive binary reports '$downloaded', not $version" >&2; exit 1; }

echo "upgrading credshim $installed to $version"
"$tmp/credshim" service install --upgrade
