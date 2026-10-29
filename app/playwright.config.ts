import { defineConfig, devices } from '@playwright/test';

// The e2e specs run against `vite preview` of the production build, with
// the real WasmEngine (`pnpm build` runs `pnpm build:wasm` first, so the
// Rust toolchain, the wasm32 target, and wasm-pack are needed).
// tauri-driver specs come later (app/TEST-PLAN.md).
export const ORIGIN = 'http://127.0.0.1:4173';

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  reporter: 'list',
  // ML-DSA and RSA run in wasm; the first page load compiles the module.
  timeout: 60_000,
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm build && pnpm preview --host 127.0.0.1 --port 4173 --strictPort',
    url: ORIGIN,
    reuseExistingServer: !process.env['CI'],
    timeout: 300_000,
  },
});
