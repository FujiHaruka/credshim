#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

marker="credshim-testing-hooks-enabled"

if cargo build --release -p credshim --features testing 2>/tmp/credshim-release-testing.log; then
  echo "FAIL: release build with --features testing succeeded; the compile guard is missing" >&2
  exit 1
fi
grep -q "must never be enabled in a release build" /tmp/credshim-release-testing.log || {
  echo "FAIL: release build with testing failed for an unexpected reason:" >&2
  cat /tmp/credshim-release-testing.log >&2
  exit 1
}

cargo build --release -p credshim
if grep -q "$marker" target/release/credshim; then
  echo "FAIL: release binary contains the testing hooks marker" >&2
  exit 1
fi
echo "OK: release build excludes testing hooks"
