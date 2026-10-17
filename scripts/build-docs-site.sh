#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/docs-site}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
blob=https://github.com/FujiHaruka/credshim/blob/main
pages=(install configuration aws ssh container troubleshooting threat-model development)

stage_page() {
  sed -E \
    -e '/^(Documentation site:|ドキュメントサイト：)/d' \
    -e 's#\]\(docs/#](#g' \
    -e 's#\]\((\.\./)*README\.md#](index.md#g' \
    -e "s#\]\((\.\./)*LICENSE-#]($blob/LICENSE-#g" \
    "$1" >"$2"
}

build_book() {
  local lang=$1 readme=$2 docs=$3
  local book=$stage/$lang
  mkdir -p "$book/src"
  cp "$root/site/$lang/book.toml" "$root/site/lang-switch.js" "$root/site/lang-switch.css" "$book/"
  cp "$root/site/$lang/SUMMARY.md" "$book/src/"
  stage_page "$readme" "$book/src/index.md"
  for page in "${pages[@]}"; do
    stage_page "$docs/$page.md" "$book/src/$page.md"
  done
  mdbook build "$book" --dest-dir "$out/$lang"
}

rm -rf "$out"
build_book en "$root/README.md" "$root/docs"
build_book ja "$root/docs/ja/README.md" "$root/docs/ja"
cp "$root/site/index.html" "$out/"
