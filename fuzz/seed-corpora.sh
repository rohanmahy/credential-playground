#!/usr/bin/env bash
# Seeds fuzz/corpus/<target>/ from testdata/ (gitignored; rerun at will).
# Usage: fuzz/seed-corpora.sh [target...]   (default: every target)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
td=$root/testdata
out=$root/fuzz/corpus
all=(cbor_decode edn_parse edn_print json_parse detect jose cose keys engine_open engine_validate)
targets=("${@:-${all[@]}}")

# add TARGET [PREFIX_HEX] < file-list: copies each file, optionally with a
# prefix byte (for targets whose first byte selects an option).
add() {
  local dir=$out/$1 prefix=${2:-} f n=0
  mkdir -p "$dir"
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    if [ -n "$prefix" ]; then
      { printf '%b' "\\x$prefix"; cat "$f"; } >"$dir/$prefix-$n-${f##*/}"
    else
      cp "$f" "$dir/$n-${f##*/}"
    fi
  done
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# hildjj/cbor-test-vectors: every `"encoded": h'…'` as binary, and every
# one-line `"decoded": …` value as EDN text.
mkdir -p "$tmp/cbor" "$tmp/edn"
i=0
grep -ho "\"encoded\": h'[0-9a-fA-F ]*'" "$td"/cbor-test-vectors/tests/*/*.edn |
  sed -e "s/.*h'//" -e "s/'//" -e 's/ //g' |
  while IFS= read -r hex; do
    i=$((i + 1))
    printf '%s' "$hex" | xxd -r -p >"$tmp/cbor/$i"
  done
i=0
grep -h '"decoded": .*,$' "$td"/cbor-test-vectors/tests/*/*.edn |
  sed -e 's/^ *"decoded": //' -e 's/,$//' |
  while IFS= read -r edn; do
    i=$((i + 1))
    printf '%s' "$edn" >"$tmp/edn/$i"
  done
for f in "$td"/tokens/*.hex; do xxd -r -p "$f" >"$tmp/cbor/$(basename "$f").bin"; done

cbor_files() {
  find "$tmp/cbor" -type f
  find "$td/tokens" "$td/keys" -name '*.cbor'
}
edn_files() {
  find "$tmp/edn" -type f
  find "$td/tokens" "$td/cbor-test-vectors" -name '*.edn'
}
json_files() {
  find "$td/JSONTestSuite/test_parsing" -type f
  find "$td/tokens" "$td/keys" -name '*.json'
}
token_files() { find "$td/tokens" -type f ! -name README.md; }
key_files() { find "$td/keys" -type f ! -name README.md; }
jose_files() { find "$td/tokens" \( -name '*.txt' -o -name 'rfc7515-*.json' -o -name 'rfc9901-s8*.json' \); }
cose_files() { find "$td/tokens" -name '*.cbor' ! -name '*claims*'; }

for t in "${targets[@]}"; do
  case $t in
    cbor_decode) cbor_files | add "$t" ;;
    edn_parse) edn_files | add "$t" ;;
    edn_print)
      for p in 00 05 1a; do cbor_files | add "$t" "$p"; done ;;
    json_parse) json_files | add "$t" ;;
    detect | engine_open) { token_files; key_files; } | add "$t" ;;
    jose) jose_files | add "$t" ;;
    cose) cose_files | add "$t" ;;
    keys) key_files | add "$t" 00 ;;
    engine_validate)
      # Indices into KINDS in fuzz_targets/engine_validate.rs.
      for p in 00 02 03 04 05 06 07; do jose_files | add "$t" "$p"; done
      for p in 08 09 0a 0b; do cose_files | add "$t" "$p"; done ;;
    *) echo "unknown target: $t" >&2; exit 1 ;;
  esac
  echo "$t: $(find "$out/$t" -type f | wc -l | tr -d ' ') seeds"
done
