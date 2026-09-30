#!/usr/bin/env bash
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/check-secret-exposure.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

tree() {
  local root="$work/$1" file="$2"
  mkdir -p "$root/crates/m/src" "$root/$(dirname "$file")"
  echo 'fn f() {}' > "$root/crates/m/src/lib.rs"
  [[ -z "$file" ]] || echo 'fn g(s: &S) { s.expose_secret(); }' > "$root/$file"
  echo "$root"
}

expect() {
  local want="$1" name="$2" root="$3"
  if "$check" "$root" > /dev/null 2>&1; then got=pass; else got=fail; fi
  if [[ "$got" != "$want" ]]; then
    echo "self-test $name: expected $want, got $got" >&2
    exit 1
  fi
}

expect fail nested-tests-dir "$(tree nested crates/m/src/tests/mod.rs)"
expect pass crate-tests-dir "$(tree crate_tests crates/m/tests/it.rs)"
expect pass clean "$(tree clean '')"
echo "OK: check-secret-exposure self-test"
