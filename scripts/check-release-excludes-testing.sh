#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

log=$(mktemp)
trap 'rm -f "$log"' EXIT

if cargo build --locked --release -p credshim --features testing 2>"$log"; then
  echo "FAIL: release build with --features testing succeeded; the compile guard is missing" >&2
  exit 1
fi
grep -q "must never be enabled in a release build" "$log" || {
  echo "FAIL: release build with testing failed for an unexpected reason:" >&2
  cat "$log" >&2
  exit 1
}
cargo build --locked --release -p credshim
bin=${CARGO_TARGET_DIR:-target}/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release/credshim
[[ -f $bin ]] || {
  echo "FAIL: the release binary is not at $bin" >&2
  exit 1
}
if grep -q "credshim-testing-hooks-enabled" "$bin"; then
  echo "FAIL: the release binary contains the testing hooks marker" >&2
  exit 1
fi
echo "OK: release build refuses the testing feature and the release binary has no testing hooks"
