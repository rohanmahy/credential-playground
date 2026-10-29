#!/usr/bin/env bash
# Builds the desktop app on Linux and runs the desktop e2e suite
# (app/e2e-desktop) against the binary under Xvfb. Needs the packages from
# `scripts/linux-deps.sh --e2e`, Rust with wasm32-unknown-unknown, wasm-pack,
# tauri-cli, tauri-driver, Node 22, and pnpm. scripts/desktop-e2e-docker.sh
# runs this in a container; the desktop-e2e CI job runs the same steps.
# Usage: scripts/desktop-e2e.sh [--no-build] [wdio args...]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
build=1
if [ "${1:-}" = --no-build ]; then
  build=0
  shift
fi

cd "$root/app"
pnpm install --frozen-lockfile
if [ $build = 1 ]; then
  # target/release/tokenator, without incognito (e2e-desktop/build.mjs).
  pnpm build:desktop-e2e
fi
xvfb-run --auto-servernum --server-args='-screen 0 1600x1000x24' pnpm test:e2e:desktop "$@"
