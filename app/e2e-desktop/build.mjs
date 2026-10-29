// Builds the two binaries the desktop e2e suite uses, with `cargo tauri
// build --no-bundle`:
// - target/desktop-e2e/tokenator, the one WebDriver drives: tauri.conf.json
//   except `incognito: false` on the windows. wry gives an incognito webview
//   an ephemeral WebKitGTK context with automation disabled, so
//   WebKitWebDriver can't attach to it ("failed to create a new browsing
//   context"). The override is derived from tauri.conf.json here, so the
//   two can't drift apart.
// - target/release/tokenator, with the shipped config, which
//   never-persist.e2e.ts launches without WebDriver.
// Usage (in app/): pnpm build:desktop-e2e [extra cargo tauri build args]
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const app = join(import.meta.dirname, '..');
const target = resolve(process.env['CARGO_TARGET_DIR'] ?? join(app, '../target'));

/** @param {string[]} extra */
function tauriBuild(extra) {
  // beforeBuildCommand runs `pnpm build`; the binary is target/release/tokenator.
  const args = ['tauri', 'build', '--no-bundle', '--ci', ...extra, ...process.argv.slice(2)];
  const { status } = spawnSync('cargo', args, { cwd: app, stdio: 'inherit' });
  if (status !== 0) process.exit(status ?? 1);
}

const conf = JSON.parse(readFileSync(join(app, 'src-tauri/tauri.conf.json'), 'utf8'));
const override = {
  app: {
    windows: conf.app.windows.map((/** @type {object} */ w) => ({ ...w, incognito: false })),
  },
};
const file = join(mkdtempSync(join(tmpdir(), 'tokenator-e2e-conf-')), 'tauri.e2e.conf.json');
writeFileSync(file, JSON.stringify(override));

tauriBuild(['--config', file]);
mkdirSync(join(target, 'desktop-e2e'), { recursive: true });
copyFileSync(join(target, 'release/tokenator'), join(target, 'desktop-e2e/tokenator'));
tauriBuild([]);
