// `pnpm test:wasm`: tests that need the built wasm module
// (crates/tokenator-wasm/pkg, from `pnpm build:wasm`), run in Node: the
// parity check against testdata/parity, WasmEngine over the real module,
// checks on the binary, and the Workspace store over the real engine. See crates/tokenator-wasm/TEST-PLAN.md.
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';
import { WASM_PKG } from './vite.config.ts';

export default defineConfig({
  // The stores use Svelte runes (keyPaste.test.ts drives the Workspace).
  plugins: [svelte()],
  resolve: {
    alias: { 'tokenator-wasm': `${WASM_PKG}/tokenator_wasm.js` },
  },
  test: {
    environment: 'node',
    include: ['src/test/wasm/**/*.test.ts'],
    globalSetup: ['src/test/wasm/globalSetup.ts'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    restoreMocks: true,
  },
});
