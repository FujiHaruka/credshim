#!/usr/bin/env bash
set -uo pipefail

state=${CREDSHIM_STATE:-/var/lib/credshim}
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
cannot_create_in() { ! touch "$1/.credshim-verify" 2>/dev/null; }
no_sudo() { ! sudo -n true 2>/dev/null; }
not_admin() { ! id -Gn | tr ' ' '\n' | grep -qxE 'sudo|wheel|admin'; }
immutable_path() {
  local path=$1
  if [[ -d $path ]]; then cannot_create_in "$path" || return 1; else cannot_write "$path" || return 1; fi
  while [[ $path != / ]]; do
    path=$(dirname "$path")
    cannot_create_in "$path" || return 1
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
for file in config.toml secrets.age secrets.key ca/ca-key.pem oauth-vault.age audit.jsonl; do
  check "cannot read $state/$file" cannot_read "$state/$file"
  check "cannot write $state/$file" cannot_write "$state/$file"
done
check "public CA certificate is readable" test -r "$public/ca.pem"
check "trust bundle is readable" test -r "$public/bundle.pem"
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
