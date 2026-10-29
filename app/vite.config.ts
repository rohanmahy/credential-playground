/// <reference types="vitest/config" />
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { svelteTesting } from '@testing-library/svelte/vite';
import { cspString } from './csp.config.ts';

// Adds the CSP <meta> to the production index.html (not in dev, where Vite's
// HMR client needs inline scripts and a websocket).
function cspMeta(): Plugin {
  return {
    name: 'tokenator-csp-meta',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler: () => [
        {
          tag: 'meta',
          attrs: { 'http-equiv': 'Content-Security-Policy', content: cspString() },
          injectTo: 'head-prepend',
        },
      ],
    },
  };
}

// `pnpm build:wasm` writes the wasm-bindgen module here (gitignored).
export const WASM_PKG = fileURLToPath(new URL('../crates/tokenator-wasm/pkg', import.meta.url));
const wasmGlue = `${WASM_PKG}/tokenator_wasm.js`;
// Unit tests (and the CSP test's build) run without the Rust toolchain:
// they get a module whose init() fails. A real build refuses to fall back.
const wasmMissing = fileURLToPath(new URL('./src/lib/engine/wasm-missing.ts', import.meta.url));

function tokenatorWasm(): string {
  if (existsSync(wasmGlue)) return wasmGlue;
  if (process.env['VITEST']) return wasmMissing;
  throw new Error('crates/tokenator-wasm/pkg is missing: run `pnpm build:wasm` first');
}

export default defineConfig(() => ({
  plugins: [svelte(), svelteTesting(), cspMeta()],
  // Relative asset paths, for GitHub Pages and the Tauri bundle.
  base: './',
  resolve: {
    alias: { 'tokenator-wasm': tokenatorWasm() },
  },
  server: {
    // The dev server may read the wasm package outside app/.
    fs: { allow: ['.', WASM_PKG] },
  },
  build: {
    target: 'es2022',
    // Inline nothing as data: URLs; everything is loaded from 'self'
    // (including the .wasm, which the glue fetches by URL).
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.ts'],
    // Need the built wasm module: `pnpm test:wasm` (vitest.wasm.config.ts).
    exclude: ['src/test/wasm/**', 'node_modules/**'],
    setupFiles: ['src/test/setup.ts'],
    restoreMocks: true,
  },
}));
