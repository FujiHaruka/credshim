#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 [--user <development-user>] [<version>|latest]" >&2
  exit 2
}

main() {
  exec </dev/null
  dev=
  version=latest
  while [[ $# -gt 0 ]]; do
    case $1 in
      --user) [[ $# -ge 2 ]] || usage; dev=$2; shift 2 ;;
      -*) usage ;;
      *) version=$1; shift ;;
    esac
  done

  [[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
  export PATH=/usr/bin:/bin:/usr/sbin:/sbin
  unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy CURL_CA_BUNDLE SSL_CERT_FILE
  cd /
  umask 077
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  releases=${CREDSHIM_RELEASES:-https://github.com/FujiHaruka/credshim/releases}

  case $(uname -s)/$(uname -m) in
    Linux/x86_64) target=x86_64-unknown-linux-gnu bin=/usr/local/libexec/credshim/credshim ;;
    Linux/aarch64) target=aarch64-unknown-linux-gnu bin=/usr/local/libexec/credshim/credshim ;;
    Darwin/arm64) target=aarch64-apple-darwin bin=/Library/CredShim/bin/credshim ;;
    *) echo "no release binary for $(uname -s) $(uname -m); build from source (cargo install --locked --path crates/cli) and run: sudo ./credshim service install --user <development-user>" >&2; exit 1 ;;
  esac

  if [[ -x $bin ]]; then
    installed=$("$bin" --version)
    installed=${installed##* }
  else
    installed=
    [[ -n $dev ]] || { echo "pass the development user (the account the agents run as): --user <name>" >&2; exit 1; }
  fi
  if [[ -n $dev ]]; then
    id -u "$dev" >/dev/null 2>&1 || { echo "no such user: $dev" >&2; exit 1; }
  fi

  version=${version#v}
  if [[ $version == latest ]]; then
    latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$releases/latest")
    version=${latest##*/tag/v}
  fi
  [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release version: $version" >&2; exit 1; }

  if [[ $installed == "$version" ]]; then
    echo "credshim $version is already installed"
    exit 0
  fi

  archive=credshim-$version-$target.tar.gz
  curl -fsSL -o "$tmp/$archive" "$releases/download/v$version/$archive" || { echo "could not download $archive from release v$version" >&2; exit 1; }
  curl -fsSL -o "$tmp/SHA256SUMS" "$releases/download/v$version/SHA256SUMS"
  if command -v sha256sum >/dev/null; then
    (cd "$tmp" && grep " $archive\$" SHA256SUMS | sha256sum -c -)
  else
    (cd "$tmp" && grep " $archive\$" SHA256SUMS | shasum -a 256 -c)
  fi
  tar -xzf "$tmp/$archive" -C "$tmp" credshim
  downloaded=$("$tmp/credshim" --version)
  [[ ${downloaded##* } == "$version" ]] || { echo "the $archive binary reports '$downloaded', not $version" >&2; exit 1; }

  if [[ -n $installed ]]; then
    echo "upgrading credshim $installed to $version"
  else
    echo "installing credshim $version"
  fi
  "$tmp/credshim" service install --upgrade ${dev:+--user "$dev"}
}

main "$@"
