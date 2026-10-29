#!/usr/bin/env bash
# Builds the unsigned macOS .app with the Tauri CLI and zips it with ditto
# (which keeps the bundle's symlinks and extended attributes).
# Usage: app/scripts/package-macos-app.sh [VERSION]   (default: dev)
# A universal (arm64 + x86_64) binary; ARCH=aarch64 or ARCH=x86_64 builds
# one architecture. Needs: cargo-tauri 2, wasm-pack, pnpm (with
# `pnpm install` done in app/), and the wasm32-unknown-unknown target plus
# the Rust target(s) for ARCH. Prints the zip path, and writes
# zip=<path> to $GITHUB_OUTPUT when set.
set -euo pipefail

version=${1:-dev}
root=$(cd "$(dirname "$0")/../.." && pwd)
arch=${ARCH:-universal}
case $arch in
  universal) target=universal-apple-darwin ;;
  aarch64 | x86_64) target=$arch-apple-darwin ;;
  *) echo "unknown ARCH: $arch" >&2; exit 1 ;;
esac

cd "$root/app"
# beforeBuildCommand (tauri.conf.json) runs `pnpm build`, which builds the wasm.
cargo tauri build --target "$target" --bundles app --ci

bundle_dir=$root/target/$target/release/bundle/macos
app=$(find "$bundle_dir" -maxdepth 1 -name '*.app' -print -quit)
[ -n "$app" ] || { echo "no .app in $bundle_dir" >&2; exit 1; }
zip=$root/target/$target/release/bundle/The-Tokenator-$version-macos-$arch.zip
rm -f "$zip"
ditto -c -k --keepParent "$app" "$zip"
echo "$zip"
if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "zip=$zip" >>"$GITHUB_OUTPUT"; fi
