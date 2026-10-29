// #43 on the native engine: New EDN draft → write a COSE_Key → set the type
// to COSE_Key → Add to key panel. Mirrors app/e2e/drafts.spec.ts.
import { browser } from '@wdio/globals';
import { appReady, detectedType, expectThat, keyCards, page } from '../helpers';

const COSE_KEY =
  "{1: 2, -1: 1, -2: h'58a9fe64819ebdcc06232cabcc5a1934175aabdfd3b2acc697dea8734096ba2b', -3: h'cbbeedf91bc01d1293b1219d21851fc1eb8ebf0aef0c3f90dc7bf92747d229b1'}";

describe('drafts', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
  });

  it('New EDN draft → COSE_Key → Add to key panel', async () => {
    await page.getByRole('button', 'New EDN draft').click();
    await expectThat(detectedType()).toHaveText('EDN claim set');
    await expectThat(page.getByRole('navigation', 'Provenance')).toContainText('New');

    const editor = page.getByTestId('live-editor').locator('.cm-content');
    await editor.selectText('{}');
    await editor.keys(COSE_KEY);
    await expectThat(editor).toContainText('cbbeedf91bc0');

    await page.getByRole('button', /detected as/i).click();
    await page.getByRole('menuitemradio', /^COSE_Key( \(detected\))?$/).click();
    await expectThat(detectedType()).toHaveText('COSE_Key');

    await page.getByRole('button', 'Add to key panel').click();
    await expectThat(keyCards()).toHaveCount(1);
    await expectThat(keyCards().first()).toContainText('EC P-256');
    await expectThat(keyCards().first()).toContainText('New');
  });
});
