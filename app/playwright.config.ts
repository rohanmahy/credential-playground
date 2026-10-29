import { defineConfig, devices } from '@playwright/test';

// The e2e specs need the real WASM engine (crates/tokenator-wasm/pkg). They
// run only with TOKENATOR_E2E=1; otherwise every spec is skipped and no
// server is started. tauri-driver specs come later (app/TEST-PLAN.md).
const enabled = process.env['TOKENATOR_E2E'] === '1';

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env['CI'],
  retries: process.env['CI'] ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  ...(enabled
    ? {
        webServer: {
          command: 'pnpm build && pnpm preview --port 4173 --strictPort',
          url: 'http://127.0.0.1:4173',
          reuseExistingServer: !process.env['CI'],
          timeout: 120_000,
        },
      }
    : {}),
});
