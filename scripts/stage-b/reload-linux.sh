#!/usr/bin/env bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

user=credshim
state=/var/lib/credshim
public=/etc/credshim
bin=/usr/local/libexec/credshim/credshim

systemctl is-active --quiet credshim.service || {
  echo "the credshim service is not running; start it with: sudo $bin service install" >&2
  exit 1
}
sudo -u "$user" HOME="$state" "$bin" run --check --config "$state/config.toml"
sudo -u "$user" HOME="$state" "$bin" env --config "$state/config.toml" \
  --ca-cert "$public/ca.pem" --bundle "$public/bundle.pem" > "$tmp/env"
echo "# dummy keys, for a project's .env or direnv: $public/keys.env" >> "$tmp/env"
sudo -u "$user" HOME="$state" "$bin" env --keys --config "$state/config.toml" > "$tmp/keys.env"
install -m 0644 -o root -g root "$tmp/env" "$public/env"
install -m 0644 -o root -g root "$tmp/keys.env" "$public/keys.env"
systemctl kill --signal=HUP --kill-whom=main credshim.service
echo "credshim is reloading its config; journalctl -u credshim records the result"
