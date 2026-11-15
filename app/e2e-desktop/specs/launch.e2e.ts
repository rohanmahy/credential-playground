// Checklist §1: the real binary launches with the native TauriEngine, and
// About shows the SD-CWT revision from engine.info().
import { browser } from '@wdio/globals';
import { activePanel, appReady, closeDialog, expectThat, keyArea, page, tabs } from '../helpers';

describe('launch', () => {
  before(appReady);

  it('opens the shell: no global input, Issuer and Holder key areas, one empty tab', async () => {
    await expectThat(page.getByRole('textbox', 'Paste a credential or key')).toHaveCount(0);
    await expectThat(page.getByRole('button', 'Open')).toHaveCount(0);
    await expectThat(keyArea('issuer')).toBeVisible();
    await expectThat(keyArea('holder')).toBeVisible();
    await expectThat(tabs()).toHaveCount(1);
    await expectThat(activePanel().getByRole('button', 'From clipboard')).toBeVisible();
    await expectThat(activePanel().getByRole('button', 'Open file…')).toBeVisible();
    await expectThat(activePanel().getByRole('combobox', 'Type')).toBeVisible();
    await expectThat(page.getByRole('alert')).toHaveCount(0);
  });

  it('runs inside Tauri with the native engine, not WASM', async () => {
    const env = await browser.execute(() => ({
      tauri: '__TAURI_INTERNALS__' in window,
      wasm: performance.getEntriesByType('resource').filter((e) => e.name.endsWith('.wasm')).length,
    }));
    expect(env).toEqual({ tauri: true, wasm: 0 });
  });

  it('About shows the SD-CWT revision and registry dates', async () => {
    await page.getByRole('button', 'About').click();
    const about = page.getByRole('dialog', 'About');
    await expectThat(about).toContainText('draft-ietf-spice-sd-cwt-08');
    await expectThat(about).toContainText(/registry\s*\d{4}-\d{2}-\d{2}/);
    await closeDialog('About');
  });
});
