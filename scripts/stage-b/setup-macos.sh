#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: sudo $0 <path-to-credshim-binary> [<development-user>]" >&2
  exit 2
}

[[ $# -eq 1 || $# -eq 2 ]] || usage
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
binary=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
[[ -x $binary ]] || { echo "$binary is not an executable" >&2; exit 1; }
cd /
umask 077
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

refuse_writable_ancestors() {
  local dir=$1
  while :; do
    if [[ $(stat -f %u "$dir") != 0 ]] || (( 8#$(stat -f %Lp "$dir") & 8#022 )); then
      echo "$dir must be owned by root and not writable by group or others; the proxy binary below it could be replaced" >&2
      exit 1
    fi
    [[ $dir == / ]] && break
    dir=$(dirname "$dir")
  done
}

user=_credshim
dev_uid=
if [[ $# -eq 2 ]]; then
  dev_uid=$(id -u "$2") || { echo "no such user: $2" >&2; exit 1; }
  [[ $dev_uid != 0 ]] || { echo "the development user must not be root" >&2; exit 1; }
fi
state=/var/lib/credshim
agent=/var/lib/credshim-ssh
public=/etc/credshim
bin=/Library/CredShim/bin/credshim
label=dev.credshim.proxy
plist=/Library/LaunchDaemons/$label.plist

if ! dscl . -read "/Users/$user" >/dev/null 2>&1; then
  uid=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -n | awk 'BEGIN{u=400} $1==u{u++} END{print u}')
  while dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$uid" \
    || dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$uid"; do
    uid=$((uid + 1))
  done
  dscl . -create "/Groups/$user"
  dscl . -create "/Groups/$user" PrimaryGroupID "$uid"
  dscl . -create "/Users/$user"
  dscl . -create "/Users/$user" UniqueID "$uid"
  dscl . -create "/Users/$user" PrimaryGroupID "$uid"
  dscl . -create "/Users/$user" UserShell /usr/bin/false
  dscl . -create "/Users/$user" NFSHomeDirectory "$state"
  dscl . -create "/Users/$user" IsHidden 1
  dscl . -create "/Users/$user" Password '*'
fi

[[ -d /var/lib ]] || install -d -m 0755 -o root -g wheel /var/lib
install -d -m 0700 -o "$user" -g "$user" "$state"
install -d -m 0755 -o "$user" -g "$user" "$agent"
install -d -m 0755 -o root -g wheel "$public" /Library/CredShim /Library/CredShim/bin
refuse_writable_ancestors /Library/CredShim/bin
[[ $binary -ef $bin ]] || install -m 0755 -o root -g wheel "$binary" "$bin"

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
install -m 0644 -o root -g wheel "$tmp/ca.pem" "$public/ca.pem"
sudo -u "$user" HOME="$state" "$bin" ca bundle --dir "$state/ca" > "$tmp/bundle.pem"
install -m 0644 -o root -g wheel "$tmp/bundle.pem" "$public/bundle.pem"
sudo -u "$user" HOME="$state" "$bin" env --config "$state/config.toml" \
  --ca-cert "$public/ca.pem" --bundle "$public/bundle.pem" > "$tmp/env"
echo "# dummy keys, for a project's .env or direnv: $public/keys.env" >> "$tmp/env"
install -m 0644 -o root -g wheel "$tmp/env" "$public/env"
sudo -u "$user" HOME="$state" "$bin" env --keys --config "$state/config.toml" > "$tmp/keys.env"
install -m 0644 -o root -g wheel "$tmp/keys.env" "$public/keys.env"

cat > "$tmp/$label.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>UserName</key><string>$user</string>
  <key>GroupName</key><string>$user</string>
  <key>ProgramArguments</key>
  <array>
    <string>$bin</string>
    <string>run</string>
    <string>--config</string>
    <string>$state/config.toml</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>HOME</key><string>$state</string></dict>
  <key>Umask</key><integer>63</integer>
  <key>HardResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
  <key>SoftResourceLimits</key><dict><key>Core</key><integer>0</integer></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$state/credshim.log</string>
</dict>
</plist>
PLIST
install -m 0644 -o root -g wheel "$tmp/$label.plist" "$plist"
launchctl bootout "system/$label" 2>/dev/null || true
launchctl bootstrap system "$plist"

cat <<DONE
credshim runs as '$user' and listens on 127.0.0.1:8787.
For the development user:
  . $public/env && $bin doctor
  copy the dummy keys a project needs from $public/keys.env into its .env
Make sure the development user is not an administrator (no sudo), then check isolation as that user:
  scripts/stage-b/verify.sh
DONE
