#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

allowed='^crates/(core/src/inject\.rs|secrets/src/|oauth/src/vault\.rs|oauth/src/token_exchange\.rs)'

matches=$(grep -rnE --include='*.rs' 'expose_secret[[:space:]]*\(' crates | grep -v '/tests/' || [[ $? == 1 ]])
violations=$(printf '%s\n' "$matches" | grep -Ev "$allowed" | grep -v '^$' || [[ $? == 1 ]])

if [[ -n "$violations" ]]; then
  echo "expose_secret() is only allowed in the injection and secret-store modules:" >&2
  echo "$violations" >&2
  exit 1
fi
echo "OK: expose_secret confined to allowed modules"
