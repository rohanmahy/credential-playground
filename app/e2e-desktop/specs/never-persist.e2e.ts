// Checklist §10: nothing comes back after a restart, and the app writes no
// user data. Runs last, so the HOME shared by every session of the run
// (wdio.conf.ts) holds what all the specs did.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { browser } from '@wdio/globals';
import {
  appEnv,
  filesUnder,
  isSystemCache,
  isWebKitBookkeeping,
  REGISTRY_CACHE,
  shippedApplication,
} from '../env.ts';
import {
  appReady,
  createKey,
  detectedType,
  expectThat,
  fixtureText,
  keyCards,
  page,
  paste,
} from '../helpers';

describe('never persist', () => {
  before(appReady);

  it('a restart brings back no keys or tabs', async () => {
    await createKey('Ed25519', 'holder');
    await paste(fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
    await expectThat(detectedType()).toHaveText('JWT');

    // Quits the app and launches it again.
    await browser.reloadSession();
    await appReady();
    await expectThat(keyCards()).toHaveCount(0);
    await expectThat(page.getByRole('tab')).toHaveCount(0);
  });

  it('after the run, the app data dir holds no web storage and no other files', () => {
    const home = process.env['TOKENATOR_E2E_HOME'];
    if (!home) throw new Error('TOKENATOR_E2E_HOME is not set (wdio.conf.ts)');
    // The registry cache is written only after Update registries, which no
    // spec does; it is allowed all the same.
    const unexpected = filesUnder(home).filter(
      (f) => !isSystemCache(f) && !isWebKitBookkeeping(f) && f !== REGISTRY_CACHE,
    );
    expect(unexpected).toEqual([]);
  });

  it('the shipped (incognito) binary writes nothing but WebKit bookkeeping', async () => {
    const home = mkdtempSync(join(tmpdir(), 'tokenator-shipped-home-'));
    const app = spawn(shippedApplication, [], { env: appEnv(home), stdio: 'ignore' });
    let exited: number | null = null;
    app.once('exit', (code) => (exited = code ?? -1));
    // Long enough to load the UI and initialise the engine.
    await browser.pause(5_000);
    expect(exited).toBeNull();
    app.kill('SIGTERM');
    await new Promise((done) => (exited === null ? app.once('exit', done) : done(null)));
    const written = filesUnder(home).filter((f) => !isSystemCache(f) && !isWebKitBookkeeping(f));
    expect(written).toEqual([]);
  });
});
