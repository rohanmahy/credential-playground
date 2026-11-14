// #43 on the native engine, in the empty startup tab (SPEC §4.1): pick EDN
// claims, type a COSE_Sign1 (typing never autodetects), set the type to
// CWT with "Detected as…", and it stays a CWT. Mirrors
// app/e2e/drafts.spec.ts.
import { browser } from '@wdio/globals';
import { activePanel, appReady, detectedType, expectThat, page, tabBox } from '../helpers';

const SIGN1 = `18([<< {1: -7} >>, {}, << {1: "issuer", 4: 4102444800} >>, h'00'])`;

describe('typed tabs', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
  });

  it('EDN claims → type a COSE_Sign1 → set to CWT', async () => {
    await activePanel().getByRole('combobox', 'Type').selectOption('EDN claims');
    await tabBox().keys(SIGN1);
    await expectThat(detectedType()).toHaveText('EDN claim set');

    await page.getByRole('button', /detected as/i).click();
    await page.getByRole('menuitemradio', /^CWT( \(detected\))?$/).click();
    await expectThat(detectedType()).toHaveText('CWT');
    // a typed tab has no original signature: never "signature stale"
    await expectThat(page.getByRole('status').withText('signature stale')).toHaveCount(0);

    await tabBox().selectText('"issuer"');
    await tabBox().keys('"other"');
    await expectThat(tabBox()).toContainText('"other"');
    await expectThat(detectedType()).toHaveText('CWT');
  });
});
