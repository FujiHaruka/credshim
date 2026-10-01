#!/usr/bin/env bash
set -uo pipefail

state=${CREDSHIM_STATE:-/var/lib/credshim}
agent=${CREDSHIM_AGENT_DIR:-/var/lib/credshim-ssh}
public=${CREDSHIM_PUBLIC:-/etc/credshim}
addr=${CREDSHIM_ADDR:-127.0.0.1:8787}
failures=0

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }
check() {
  local what=$1
  shift
  if "$@"; then pass "$what"; else fail "$what"; fi
}

if [[ $EUID -eq 0 ]]; then
  echo "run this as the development user, not root" >&2
  exit 2
fi

case $(uname -s) in
  Darwin)
    service_user=_credshim
    service_file=/Library/LaunchDaemons/dev.credshim.proxy.plist
    owner_of() { stat -f %Su "$1"; }
    ;;
  *)
    service_user=credshim
    service_file=/etc/systemd/system/credshim.service
    owner_of() { stat -c %U "$1"; }
    ;;
esac

cannot_read() { [[ ! -r $1 ]] && ! cat "$1" >/dev/null 2>&1; }
cannot_write() { [[ ! -w $1 ]] && ! { : >>"$1"; } 2>/dev/null; }
cannot_list() { ! ls "$1" >/dev/null 2>&1; }
cannot_create_in() {
  if touch "$1/.credshim-verify" 2>/dev/null; then
    rm -f "$1/.credshim-verify"
    return 1
  fi
}
no_sudo() { ! sudo -n true 2>/dev/null; }
not_admin() { ! id -Gn | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }
immutable_path() {
  local path=$1
  if [[ -d $path ]]; then
    cannot_create_in "$path" || { echo "      writable: $path"; return 1; }
  else
    cannot_write "$path" || { echo "      writable: $path"; return 1; }
  fi
  while [[ $path != / ]]; do
    path=$(dirname "$path")
    cannot_create_in "$path" || { echo "      writable: $path"; return 1; }
  done
}

check "development user cannot sudo without a password" no_sudo
check "development user is not in an administrator group (sudo, wheel, admin)" not_admin
check "service user '$service_user' exists" id -u "$service_user"
check "state directory $state exists" test -d "$state"
check "state directory $state is owned by $service_user" test "$(owner_of "$state" 2>/dev/null)" = "$service_user"
check "service definition $service_file exists" test -f "$service_file"
check "service definition and its directories are not writable" immutable_path "$service_file"
check "state directory $state is not listable" cannot_list "$state"
check "state directory $state is not writable" cannot_create_in "$state"
for file in config.toml secrets.age secrets.age.lock secrets.key ca/ca-key.pem oauth-vault.age audit.jsonl; do
  check "cannot read $state/$file" cannot_read "$state/$file"
  check "cannot write $state/$file" cannot_write "$state/$file"
done
check "ssh agent directory $agent exists" test -d "$agent"
check "ssh agent directory $agent is owned by $service_user" test "$(owner_of "$agent" 2>/dev/null)" = "$service_user"
check "ssh agent directory $agent is not writable" immutable_path "$agent"
if [[ -S $agent/agent.sock ]]; then
  check "ssh agent socket is owned by $service_user" test "$(owner_of "$agent/agent.sock")" = "$service_user"
  agent_reachable() {
    SSH_AUTH_SOCK="$agent/agent.sock" ssh-add -l >/dev/null 2>&1
    [[ $? -ne 2 ]]
  }
  check "development user can list the ssh agent's keys" agent_reachable
else
  echo "SKIP  no ssh agent socket in $agent (no [[ssh_key]] rules)"
fi
check "public CA certificate is readable" test -r "$public/ca.pem"
check "trust bundle is readable" test -r "$public/bundle.pem"
check "shell environment file is readable" test -r "$public/env"
env_value() { sed -n "s/^export $1='\(.*\)'\$/\1/p" "$public/env"; }
check "shell environment points AWS_CA_BUNDLE at the readable trust bundle" \
  bash -c "[[ -r '$(env_value AWS_CA_BUNDLE)' && '$(env_value AWS_CA_BUNDLE)' == '$public/bundle.pem' ]]"
if grep -q '^export SSH_AUTH_SOCK=' "$public/env"; then
  check "shell environment points SSH_AUTH_SOCK at the agent socket" test "$(env_value SSH_AUTH_SOCK)" = "$agent/agent.sock"
fi
check "public CA directory holds no private key" bash -c "! grep -q 'PRIVATE KEY' '$public'/*.pem"

pid=$(pgrep -u "$service_user" -f 'credshim run' | head -n 1)
if [[ -z $pid ]]; then
  fail "proxy is running as $service_user"
else
  pass "proxy is running as $service_user (pid $pid)"
  binary=$(ps -o args= -p "$pid" | awk '{print $1}')
  check "proxy binary $binary and its directories are not writable" immutable_path "$binary"
  check "cannot signal the proxy" bash -c "! kill -0 $pid 2>/dev/null"
  if [[ -d /proc/$pid ]]; then
    check "cannot read the proxy's environment" cannot_read "/proc/$pid/environ"
    check "cannot read the proxy's memory" cannot_read "/proc/$pid/mem"
  fi
fi

host=${addr%:*}
port=${addr##*:}
check "proxy accepts connections on $addr" bash -c "exec 3<>/dev/tcp/$host/$port"

if [[ $failures -gt 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
