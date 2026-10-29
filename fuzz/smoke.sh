#!/usr/bin/env bash
# Runs every fuzz target for SECONDS (default 60) on its corpus, as many at
# once as there are CPUs. Logs go to fuzz/logs/<target>.log; crashes and
# timeouts to fuzz/artifacts/<target>/. Fails if any target fails.
# Usage: fuzz/smoke.sh [SECONDS] [target...]
# Needs cargo-fuzz and the nightly in $FUZZ_TOOLCHAIN (default below);
# run fuzz/seed-corpora.sh first.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
seconds=${1:-60}
shift || true
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-02-01}
jobs=${FUZZ_JOBS:-$(getconf _NPROCESSORS_ONLN)}
if [ $# -gt 0 ]; then
  targets=("$@")
else
  read -r -a targets <<<"$(cargo "+$toolchain" fuzz list | tr '\n' ' ')"
fi
mkdir -p fuzz/logs

run() {
  local t=$1
  mkdir -p "fuzz/corpus/$t"
  if cargo "+$FUZZ_TOOLCHAIN" fuzz run "$t" "fuzz/corpus/$t" -- \
    -max_total_time="$FUZZ_SECONDS" -timeout=10 -rss_limit_mb=4096 \
    >"fuzz/logs/$t.log" 2>&1; then
    echo "ok    $t: $(grep -o 'Done [0-9]* runs.*' "fuzz/logs/$t.log" | tail -1)"
  else
    echo "FAIL  $t (fuzz/logs/$t.log)"
    tail -n 30 "fuzz/logs/$t.log"
    return 1
  fi
}
export -f run
export FUZZ_TOOLCHAIN=$toolchain FUZZ_SECONDS=$seconds

cargo "+$toolchain" fuzz build
printf '%s\n' "${targets[@]}" | xargs -P "$jobs" -I{} bash -c 'run {}'
