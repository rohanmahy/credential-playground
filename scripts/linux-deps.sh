#!/usr/bin/env bash
# Installs the Debian/Ubuntu packages for building the desktop app on Linux
# (Tauri 2 prerequisites: WebKitGTK 4.1, libsoup 3, GTK 3) and, with
# --e2e, for running the desktop e2e suite (WebKitWebDriver, Xvfb).
# Used by scripts/desktop-e2e.Dockerfile and the desktop-e2e CI job.
# Tested on Ubuntu 24.04. Run as root, or with sudo available.
# Usage: scripts/linux-deps.sh [--e2e]
set -euo pipefail

packages=(
  build-essential
  pkg-config
  curl
  file
  libwebkit2gtk-4.1-dev # WebKitGTK 4.1, pulls in libsoup-3.0 and javascriptcoregtk-4.1
  libgtk-3-dev
  libsoup-3.0-dev
  librsvg2-dev
  libxdo-dev # muda (the menu crate behind tauri) links libxdo
)
if [ "${1:-}" = --e2e ]; then
  packages+=(
    webkit2gtk-driver # WebKitWebDriver, which tauri-driver runs
    xvfb
    xauth # xvfb-run needs it
    fonts-dejavu-core
  )
fi

sudo=
if [ "$(id -u)" -ne 0 ]; then sudo=sudo; fi
export DEBIAN_FRONTEND=noninteractive
$sudo apt-get update
$sudo apt-get install -y --no-install-recommends "${packages[@]}"
