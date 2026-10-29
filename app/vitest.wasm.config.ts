// `pnpm test:wasm`: tests that need the built wasm module
// (crates/tokenator-wasm/pkg, from `pnpm build:wasm`), run in Node: the
// parity check against testdata/parity, WasmEngine over the real module,
// and checks on the binary. See crates/tokenator-wasm/TEST-PLAN.md.
import { defineConfig } from 'vitest/config';
import { WASM_PKG } from './vite.config.ts';

export default defineConfig({
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
