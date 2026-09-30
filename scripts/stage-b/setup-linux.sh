#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <path-to-credshim-binary>" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
binary=$(realpath "$1")
[[ -x $binary ]] || { echo "$binary is not an executable" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

user=credshim
state=/var/lib/credshim
public=/etc/credshim
bin=/usr/local/bin/credshim

if ! id -u "$user" >/dev/null 2>&1; then
  useradd --system --home-dir "$state" --no-create-home --shell /usr/sbin/nologin "$user"
fi

install -d -m 0700 -o "$user" -g "$user" "$state"
install -d -m 0755 -o root -g root "$public"
install -m 0755 -o root -g root "$binary" "$bin"

if [[ ! -e $state/config.toml ]]; then
  cat > "$tmp/config.toml" <<TOML
[listen]
addr = "127.0.0.1:8787"

[ca]
dir = "$state/ca"

[secrets]
backend = "age-file"
path = "$state/secrets.age"

[vault]
path = "$state/oauth-vault.age"

[audit]
path = "$state/audit.jsonl"

[status]
socket = "$state/status.sock"

# Add rules with: credshim preset openai | sudo -u $user tee -a $state/config.toml
# then register the secret: sudo -u $user $bin secret set openai --config $state/config.toml
TOML
  install -m 0600 -o "$user" -g "$user" "$tmp/config.toml" "$state/config.toml"
fi

if [[ ! -e $state/ca/ca-key.pem ]]; then
  sudo -u "$user" HOME="$state" "$bin" ca init --dir "$state/ca" >/dev/null
fi
install -m 0644 -o root -g root "$state/ca/ca.pem" "$public/ca.pem"
sudo -u "$user" HOME="$state" "$bin" ca bundle --dir "$state/ca" > "$tmp/bundle.pem"
install -m 0644 -o root -g root "$tmp/bundle.pem" "$public/bundle.pem"

cat > /etc/systemd/system/credshim.service <<UNIT
[Unit]
Description=CredShim credential-injecting proxy
After=network-online.target

[Service]
User=$user
Group=$user
Environment=HOME=$state
ExecStart=$bin run --config $state/config.toml
Restart=on-failure
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$state
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now credshim.service
systemctl restart credshim.service

cat <<DONE
credshim runs as '$user' and listens on 127.0.0.1:8787.
For the development user:
  export HTTPS_PROXY=http://127.0.0.1:8787 SSL_CERT_FILE=$public/bundle.pem NODE_EXTRA_CA_CERTS=$public/ca.pem
Check isolation as that user (not root): scripts/stage-b/verify.sh
DONE
