#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <path-to-credshim-binary> [<development-user>]" >&2
  exit 2
}

[[ $# -eq 1 || $# -eq 2 ]] || usage
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
binary=$(realpath "$1")
[[ -x $binary ]] || { echo "$binary is not an executable" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

refuse_writable_ancestors() {
  local dir=$1
  while :; do
    if [[ $(stat -c %u "$dir") != 0 ]] || (( 8#$(stat -c %a "$dir") & 8#022 )); then
      echo "$dir must be owned by root and not writable by group or others; the proxy binary below it could be replaced" >&2
      exit 1
    fi
    [[ $dir == / ]] && break
    dir=$(dirname "$dir")
  done
}

user=credshim
dev_uid=
if [[ $# -eq 2 ]]; then
  dev_uid=$(id -u "$2") || { echo "no such user: $2" >&2; exit 1; }
  [[ $dev_uid != 0 ]] || { echo "the development user must not be root" >&2; exit 1; }
fi
state=/var/lib/credshim
agent=/var/lib/credshim-ssh
public=/etc/credshim
bin=/usr/local/libexec/credshim/credshim

if ! id -u "$user" >/dev/null 2>&1; then
  useradd --system --home-dir "$state" --no-create-home --shell /usr/sbin/nologin "$user"
fi

install -d -m 0700 -o "$user" -g "$user" "$state"
install -d -m 0755 -o "$user" -g "$user" "$agent"
install -d -m 0755 -o root -g root "$public"
install -d -m 0755 -o root -g root /usr/local/libexec /usr/local/libexec/credshim
refuse_writable_ancestors /usr/local/libexec/credshim
[[ $binary -ef $bin ]] || install -m 0755 -o root -g root "$binary" "$bin"

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

[ssh]
socket = "$agent/agent.sock"
${dev_uid:+client_uids = [$dev_uid]}

# Run every step below from a session the development user does not own (another console,
# or an SSH login as the administrator): its processes can read what is typed into its terminals.
# Add rules with: $bin preset openai | sudo -u $user tee -a $state/config.toml
# then register the secret: sudo -u $user $bin secret set openai
# then rerun "sudo $bin service install" so $public/keys.env carries the new dummies
# SSH keys and AWS SSO logins are made as $user too:
#   sudo -u $user $bin ssh keygen ssh-github
#   sudo -u $user $bin aws sso login <session>
# Run as $user, credshim reads $state/config.toml without --config.
TOML
  install -m 0600 -o "$user" -g "$user" "$tmp/config.toml" "$state/config.toml"
fi

if [[ -n $dev_uid ]] && ! grep -Eq "^client_uids *=.*[^0-9]$dev_uid([^0-9]|$)" "$state/config.toml"; then
  echo "note: add 'client_uids = [$dev_uid]' under [ssh] in $state/config.toml (socket = \"$agent/agent.sock\") so $2 can use the ssh agent" >&2
fi

if [[ ! -e $state/ca/ca-key.pem ]]; then
  sudo -u "$user" HOME="$state" "$bin" ca init --dir "$state/ca" >/dev/null
fi
if [[ -e $state/ca/bundle.pem ]]; then
  chmod go-w "$state/ca/bundle.pem"
fi
sudo -u "$user" cat "$state/ca/ca.pem" > "$tmp/ca.pem"
install -m 0644 -o root -g root "$tmp/ca.pem" "$public/ca.pem"
sudo -u "$user" HOME="$state" "$bin" ca bundle --dir "$state/ca" > "$tmp/bundle.pem"
install -m 0644 -o root -g root "$tmp/bundle.pem" "$public/bundle.pem"
sudo -u "$user" HOME="$state" "$bin" env --config "$state/config.toml" \
  --ca-cert "$public/ca.pem" --bundle "$public/bundle.pem" > "$tmp/env"
echo "# dummy keys, for a project's .env or direnv: $public/keys.env" >> "$tmp/env"
install -m 0644 -o root -g root "$tmp/env" "$public/env"
sudo -u "$user" HOME="$state" "$bin" env --keys --config "$state/config.toml" > "$tmp/keys.env"
install -m 0644 -o root -g root "$tmp/keys.env" "$public/keys.env"

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
ReadWritePaths=$state $agent
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
  . $public/env && $bin doctor
  copy the dummy keys a project needs from $public/keys.env into its .env
Make sure the development user is not an administrator (no sudo), then check isolation as that user:
  scripts/stage-b/verify.sh
DONE
