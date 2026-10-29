// Checklist §3: main ↔ raw pane sync on a CWT (folding and selection keyed
// by NodeId), and the raw pane toggle keeping the fold state. Mirrors
// app/e2e/tree-sync.spec.ts.
import { browser } from '@wdio/globals';
import {
  appReady,
  detectedType,
  expectThat,
  fixtureText,
  mainPane,
  page,
  paste,
  rawPane,
} from '../helpers';

describe('synced panes (CBOR)', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
    await paste(fixtureText('tokens/rfc8392-a3-signed-cwt.hex'));
    await expectThat(detectedType()).toHaveText('CWT');
  });

  it('collapsing in the main pane collapses the raw pane, and back', async () => {
    const payload = mainPane().locator('[data-node-id="payload"]');
    const rawPayload = rawPane().locator('[data-node-id="payload"][aria-expanded]');
    await expectThat(payload).toHaveAttribute('aria-expanded', 'true');
    await payload.getByRole('button', 'Collapse').click();
    await expectThat(payload).toHaveAttribute('aria-expanded', 'false');
    await expectThat(rawPayload).toHaveAttribute('aria-expanded', 'false');
    await expectThat(mainPane()).notToContainText('coap://as.example.com');
    await expectThat(rawPane().locator('[data-node-id="payload/~e/1"]')).toHaveCount(0);

    await rawPayload.getByRole('button', 'Expand').click();
    await expectThat(payload).toHaveAttribute('aria-expanded', 'true');
    await expectThat(mainPane()).toContainText('coap://as.example.com');
  });

  it('selecting a claim in the main pane selects its hex rows, and back', async () => {
    const claim = mainPane().locator('[data-node-id="payload/~e/1"]');
    await claim.click();
    await expectThat(claim).toHaveAttribute('aria-selected', 'true');
    await expectThat(rawPane().locator('[data-node-id="payload/~e/1"]').first()).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await rawPane().locator('[data-node-id="signature"]').first().click();
    await expectThat(mainPane().locator('[data-node-id="signature"]')).toHaveAttribute(
      'aria-selected',
      'true',
    );
  });

  it('turning the raw pane off and on keeps the fold state', async () => {
    await mainPane().locator('[data-node-id="payload"]').getByRole('button', 'Collapse').click();
    const toggle = page.getByRole('checkbox', 'Show raw pane');
    await toggle.click();
    await expectThat(rawPane()).toBeHidden();
    await toggle.click();
    await expectThat(rawPane()).toBeVisible();
    await expectThat(rawPane().locator('[data-node-id="payload"][aria-expanded]')).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    await expectThat(mainPane().locator('[data-node-id="payload"]')).toHaveAttribute(
      'aria-expanded',
      'false',
    );
  });
});
