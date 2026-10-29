#!/usr/bin/env bash
# Runs the Linux desktop build and e2e suite (scripts/desktop-e2e.sh) in a
# Docker container, e.g. on macOS, where WebDriver can't drive WKWebView.
# The image (scripts/desktop-e2e.Dockerfile) matches the host architecture.
# The checkout is mounted read-only and copied into the container, so the
# host's target/, node_modules/, and build outputs are never touched. Cargo,
# target/, pnpm, and node_modules live in named volumes, so re-runs are
# incremental. Failure screenshots and the page source land in
# app/test-results/desktop-e2e/.
#
# Usage: scripts/desktop-e2e-docker.sh [--no-build] [wdio args...]
#        scripts/desktop-e2e-docker.sh --clean   # remove the volumes and image
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
image=tokenator-desktop-e2e
volumes=(tokenator-e2e-cargo tokenator-e2e-target tokenator-e2e-pnpm tokenator-e2e-node-modules)

if [ "${1:-}" = --clean ]; then
  docker volume rm -f "${volumes[@]}" >/dev/null
  docker image rm -f "$image" >/dev/null 2>&1 || true
  echo "removed the $image image and its volumes"
  exit 0
fi

docker build --quiet -t "$image" -f "$root/scripts/desktop-e2e.Dockerfile" "$root/scripts" >/dev/null

out=$root/app/test-results/desktop-e2e
mkdir -p "$out"
# Emptied rather than recreated: a bind mount of a just-recreated directory
# can go stale.
find "$out" -mindepth 1 -delete

tty=()
if [ -t 1 ]; then tty=(-t); fi

docker run --rm "${tty[@]}" --init \
  --mount "type=bind,src=$root,dst=/src,readonly" \
  --mount "type=bind,src=$out,dst=/out" \
  -v tokenator-e2e-cargo:/usr/local/cargo/registry \
  -v tokenator-e2e-target:/work/target \
  -v tokenator-e2e-pnpm:/pnpm-store \
  -v tokenator-e2e-node-modules:/work/app/node_modules \
  -e npm_config_store_dir=/pnpm-store \
  -e TOKENATOR_E2E_OUT=/out \
  "$image" bash -c '
    set -euo pipefail
    rsync -a --delete \
      --exclude=/.git --exclude=/.worktrees --exclude=/target --exclude=/fuzz/target \
      --exclude=/app/node_modules --exclude=/app/dist --exclude=/app/test-results \
      --exclude=/crates/tokenator-wasm/pkg \
      /src/ /work/
    exec scripts/desktop-e2e.sh "$@"
  ' desktop-e2e "$@"
