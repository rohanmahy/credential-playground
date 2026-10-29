#!/usr/bin/env bash
# Minimizes every crash, timeout, and OOM input of the given targets (default:
# all) with `cargo fuzz tmin`. A smaller input is written next to the
# original as fuzz/artifacts/<target>/minimized-from-<hash> (none if the
# original is already minimal); tmin logs go to fuzz/logs/. Prints one line
# per input; exits 0 even if minimization fails (the originals stay).
# Usage: fuzz/minimize.sh [target...]   (toolchain: $FUZZ_TOOLCHAIN)
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-02-01}
if [ $# -gt 0 ]; then
  targets=("$@")
else
  read -r -a targets <<<"$(cargo "+$toolchain" fuzz list | tr '\n' ' ')"
fi

mkdir -p fuzz/logs
for t in "${targets[@]}"; do
  for f in fuzz/artifacts/"$t"/crash-* fuzz/artifacts/"$t"/timeout-* fuzz/artifacts/"$t"/oom-*; do
    [ -f "$f" ] || continue
    if cargo "+$toolchain" fuzz tmin -r 10000 "$t" "$f" -- -timeout=10 -rss_limit_mb=4096 \
      >"fuzz/logs/tmin-$t-${f##*/}.log" 2>&1; then
      echo "minimized $f"
    else
      echo "could not minimize $f (see fuzz/logs/tmin-$t-${f##*/}.log)"
    fi
  done
done
