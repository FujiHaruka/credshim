#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

log=$(mktemp)
trap 'rm -f "$log"' EXIT

if cargo build --release -p credshim --features testing 2>"$log"; then
  echo "FAIL: release build with --features testing succeeded; the compile guard is missing" >&2
  exit 1
fi
grep -q "must never be enabled in a release build" "$log" || {
  echo "FAIL: release build with testing failed for an unexpected reason:" >&2
  cat "$log" >&2
  exit 1
}
echo "OK: release build refuses the testing feature"
