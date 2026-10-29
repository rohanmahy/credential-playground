# The Linux desktop build and e2e environment for scripts/desktop-e2e-docker.sh:
# the Tauri 2 / WebKitGTK build deps, WebKitWebDriver and Xvfb, Rust (with
# wasm32 for the web assets), wasm-pack, tauri-cli, tauri-driver, Node 22, and
# pnpm. Same steps as the desktop-e2e job in .github/workflows/ci.yml.
FROM ubuntu:24.04

ARG NODE_VERSION=22.23.4
ARG RUST_TOOLCHAIN=stable
ARG WASM_PACK_VERSION=0.15.0
ARG TAURI_CLI_VERSION=2.12.4
ARG TAURI_DRIVER_VERSION=2.1.0
# app/package.json "packageManager"
ARG PNPM_VERSION=12.14.0

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/node/bin:$PATH \
    CARGO_TERM_COLOR=always \
    CARGO_INCREMENTAL=0 \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0

COPY linux-deps.sh /tmp/linux-deps.sh
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates rsync xz-utils \
    && /tmp/linux-deps.sh --e2e \
    && rm -rf /var/lib/apt/lists/* /tmp/linux-deps.sh

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --profile minimal \
        --default-toolchain "$RUST_TOOLCHAIN" --target wasm32-unknown-unknown \
    && cargo install --locked "wasm-pack@$WASM_PACK_VERSION" "tauri-cli@$TAURI_CLI_VERSION" \
        "tauri-driver@$TAURI_DRIVER_VERSION" \
    && rm -rf "$CARGO_HOME/registry" "$CARGO_HOME/git"

RUN arch=$(dpkg --print-architecture | sed 's/amd64/x64/') \
    && mkdir -p /usr/local/node \
    && curl -sSfL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-$arch.tar.xz" \
        | tar -xJ -C /usr/local/node --strip-components=1 \
    && corepack enable && corepack prepare "pnpm@$PNPM_VERSION" --activate

WORKDIR /work
