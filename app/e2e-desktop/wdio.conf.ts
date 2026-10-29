// WebdriverIO against the real desktop binary (TauriEngine, WebKitGTK) via
// tauri-driver + WebKitWebDriver. Linux only: macOS has no WebDriver for
// WKWebView (Mac-smoketest-checklist.md covers it by hand).
//
// Build the binaries first (`pnpm build:desktop-e2e`), then run
// `xvfb-run pnpm test:e2e:desktop`. Environment:
//   TOKENATOR_BIN   the binary to drive (default: target/desktop-e2e/tokenator)
//   TOKENATOR_SHIPPED_BIN  the shipped-config binary that never-persist.e2e.ts
//                   launches (default: target/release/tokenator)
//   TAURI_DRIVER    tauri-driver (default: on PATH)
//   TOKENATOR_E2E_OUT   a dir for failure screenshots (optional)
//   TOKENATOR_E2E_HOME  a fresh HOME for the app (default: a new temp dir);
//                   never-persist.e2e.ts inspects it after the other specs
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { browser } from '@wdio/globals';
import { appEnv, application, shippedApplication } from './env.ts';

const PORT = 4444;

// The launcher sets this before forking the workers, which inherit it, so
// every session (one per spec file) shares one HOME.
process.env['TOKENATOR_E2E_HOME'] ??= mkdtempSync(join(tmpdir(), 'tokenator-e2e-home-'));
const home = process.env['TOKENATOR_E2E_HOME'];

function waitForPort(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((ok, fail) => {
    const attempt = () => {
      const socket = connect(port, '127.0.0.1');
      socket.once('connect', () => {
        socket.end();
        ok();
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) fail(new Error(`tauri-driver not listening on ${port}`));
        else setTimeout(attempt, 100);
      });
    };
    attempt();
  });
}

let driver: ChildProcess | undefined;
let stopping = false;

function stopDriver() {
  stopping = true;
  driver?.kill();
  driver = undefined;
}

export const config: WebdriverIO.Config = {
  runner: 'local',
  hostname: '127.0.0.1',
  port: PORT,
  // One app session per file, in this order: never-persist.e2e.ts checks
  // the HOME the others used.
  specs: [
    './specs/launch.e2e.ts',
    './specs/paste-validate.e2e.ts',
    './specs/keys.e2e.ts',
    './specs/issue-present.e2e.ts',
    './specs/live-edit.e2e.ts',
    './specs/tree-sync.e2e.ts',
    './specs/never-persist.e2e.ts',
  ],
  // One app at a time: they share HOME, and tauri-driver binds one port.
  maxInstances: 1,
  capabilities: [
    {
      // tauri-driver turns this into webkitgtk:browserOptions.
      'tauri:options': { application },
    } as WebdriverIO.Capabilities,
  ],
  logLevel: 'warn',
  waitforTimeout: 15_000,
  connectionRetryTimeout: 60_000,
  connectionRetryCount: 1,
  framework: 'mocha',
  reporters: ['spec'],
  mochaOpts: { ui: 'bdd', timeout: 120_000 },

  onPrepare() {
    if (process.platform !== 'linux') {
      throw new Error('Desktop e2e runs on Linux only (scripts/desktop-e2e-docker.sh on macOS).');
    }
    for (const bin of [application, shippedApplication]) {
      if (!existsSync(bin)) throw new Error(`No ${bin}: run \`pnpm build:desktop-e2e\`.`);
    }
    console.log(`desktop e2e: ${application}, HOME=${home}`);
  },

  async beforeSession() {
    stopping = false;
    driver = spawn(process.env['TAURI_DRIVER'] ?? 'tauri-driver', ['--port', String(PORT)], {
      env: appEnv(home),
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    driver.once('exit', (code) => {
      if (!stopping) {
        console.error(`tauri-driver exited early (${code})`);
        process.exit(1);
      }
    });
    await waitForPort(PORT, 10_000);
  },

  // A screenshot and the page source of each failed test, for debugging
  // (scripts/desktop-e2e-docker.sh copies them to app/test-results/).
  async afterTest(test, _context, { passed }) {
    const out = process.env['TOKENATOR_E2E_OUT'];
    if (passed || !out) return;
    mkdirSync(out, { recursive: true });
    const base = join(out, `${test.parent} - ${test.title}`.replace(/[^\w.-]+/g, '_'));
    await browser.saveScreenshot(`${base}.png`);
    writeFileSync(`${base}.html`, await browser.getPageSource());
  },

  afterSession() {
    stopDriver();
  },
};

for (const signal of ['exit', 'SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
  process.once(signal, stopDriver);
}
