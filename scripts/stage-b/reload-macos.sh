#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

user=_credshim
state=/var/lib/credshim
public=/etc/credshim
bin=/Library/CredShim/bin/credshim
label=dev.credshim.proxy

launchctl print "system/$label" >/dev/null 2>&1 || {
  echo "the credshim service is not loaded; start it with: sudo $bin service install" >&2
  exit 1
}
sudo -u "$user" HOME="$state" "$bin" run --check --config "$state/config.toml"
sudo -u "$user" HOME="$state" "$bin" env --config "$state/config.toml" \
  --ca-cert "$public/ca.pem" --bundle "$public/bundle.pem" > "$tmp/env"
echo "# dummy keys, for a project's .env or direnv: $public/keys.env" >> "$tmp/env"
sudo -u "$user" HOME="$state" "$bin" env --keys --config "$state/config.toml" > "$tmp/keys.env"
install -m 0644 -o root -g wheel "$tmp/env" "$public/env"
install -m 0644 -o root -g wheel "$tmp/keys.env" "$public/keys.env"
launchctl kill SIGHUP "system/$label"
echo "credshim is reloading its config; $state/credshim.log records the result"
