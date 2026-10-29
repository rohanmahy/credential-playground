#!/usr/bin/env bash
# Builds the Linux .deb with the Tauri CLI and copies it to a versioned name.
# Usage: app/scripts/package-linux-deb.sh [VERSION]   (default: dev)
# Needs: the packages from scripts/linux-deps.sh, cargo-tauri 2, wasm-pack,
# pnpm (with `pnpm install` done in app/), and the wasm32-unknown-unknown
# target. Prints the .deb path, and writes deb=<path> to $GITHUB_OUTPUT when
# set.
set -euo pipefail

version=${1:-dev}
root=$(cd "$(dirname "$0")/../.." && pwd)
target=${CARGO_TARGET_DIR:-$root/target}

cd "$root/app"
# beforeBuildCommand (tauri.conf.json) runs `pnpm build`, which builds the wasm.
cargo tauri build --bundles deb --ci

built=$(find "$target/release/bundle/deb" -maxdepth 1 -name '*.deb' -print -quit)
[ -n "$built" ] || { echo "no .deb in $target/release/bundle/deb" >&2; exit 1; }
arch=$(dpkg --print-architecture)
deb=$target/release/bundle/The-Tokenator-$version-linux-$arch.deb
cp "$built" "$deb"
echo "$deb"
if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "deb=$deb" >>"$GITHUB_OUTPUT"; fi
