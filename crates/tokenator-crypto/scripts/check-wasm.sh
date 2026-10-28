#!/bin/sh
# tokenator-crypto must build for wasm32-unknown-unknown without a getrandom
# backend: randomness is always injected, so getrandom must not be in the
# normal dependency graph at all.
set -eu
cd "$(dirname "$0")/../../.."
cargo build -p tokenator-crypto --target wasm32-unknown-unknown
if cargo tree -p tokenator-crypto -e normal --target wasm32-unknown-unknown -i getrandom >/dev/null 2>&1; then
    echo "error: getrandom is a normal dependency of tokenator-crypto" >&2
    cargo tree -p tokenator-crypto -e normal --target wasm32-unknown-unknown -i getrandom >&2
    exit 1
fi
echo "tokenator-crypto: wasm32-unknown-unknown build OK, no getrandom"
