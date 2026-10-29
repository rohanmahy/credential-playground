// Tree sync between the main and raw panes (SPEC §4.1) on real engine
// output: folding and selection are keyed by path-based NodeIds, so they
// mirror across panes and survive a re-render.
import { expect, test, type Page } from '@playwright/test';
import { fixtureText, paste } from './helpers';

function panes(page: Page) {
  return {
    main: page.getByRole('tree', { name: 'Main pane' }),
    raw: page.getByRole('tree', { name: 'Raw pane' }),
  };
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
});

test.describe('COSE (hex rows ↔ EDN lines)', () => {
  test.beforeEach(async ({ page }) => {
    await paste(page, fixtureText('tokens/rfc8392-a3-signed-cwt.hex'));
    await expect(page.getByTestId('detected-type')).toHaveText('CWT');
  });

  test('collapsing in the main pane collapses the raw pane', async ({ page }) => {
    const { main, raw } = panes(page);
    const payload = main.locator('[data-node-id="payload"]');
    await expect(payload).toHaveAttribute('aria-expanded', 'true');
    await payload.getByRole('button', { name: 'Collapse' }).click();
    await expect(payload).toHaveAttribute('aria-expanded', 'false');
    await expect(raw.locator('[data-node-id="payload"][aria-expanded]')).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    await expect(main).not.toContainText('coap://as.example.com');
    await expect(raw.locator('[data-node-id="payload/~e/1"]')).toHaveCount(0);
  });

  test('expanding in the raw pane expands the main pane', async ({ page }) => {
    const { main, raw } = panes(page);
    await main
      .locator('[data-node-id="payload"]')
      .getByRole('button', { name: 'Collapse' })
      .click();
    const rawPayload = raw.locator('[data-node-id="payload"][aria-expanded]');
    await rawPayload.getByRole('button', { name: 'Expand' }).click();
    await expect(main.locator('[data-node-id="payload"]')).toHaveAttribute('aria-expanded', 'true');
    await expect(main).toContainText('coap://as.example.com');
    await expect(raw.locator('[data-node-id="payload/~e/1"]').first()).toBeVisible();
  });

  test('keyboard folding in the raw pane mirrors to the main pane', async ({ page }) => {
    const { main, raw } = panes(page);
    const rawPayload = raw.locator('[data-node-id="payload"][aria-expanded]');
    await rawPayload.click();
    await rawPayload.press('ArrowLeft');
    await expect(main.locator('[data-node-id="payload"]')).toHaveAttribute(
      'aria-expanded',
      'false',
    );
    await raw.locator('[data-node-id="payload"][aria-expanded]').press('ArrowRight');
    await expect(main.locator('[data-node-id="payload"]')).toHaveAttribute('aria-expanded', 'true');
  });

  test('selecting a claim in the main pane selects its hex rows', async ({ page }) => {
    const { main, raw } = panes(page);
    await main.locator('[data-node-id="payload/~e/1"]').click();
    await expect(main.locator('[data-node-id="payload/~e/1"]')).toHaveAttribute(
      'aria-selected',
      'true',
    );
    const rows = raw.locator('[data-node-id="payload/~e/1"]');
    await expect(rows.first()).toHaveAttribute('aria-selected', 'true');
    await expect(raw.locator('[data-node-id="signature"]').first()).toHaveAttribute(
      'aria-selected',
      'false',
    );
  });

  test('selecting a hex row selects its main-pane line', async ({ page }) => {
    const { main, raw } = panes(page);
    await raw.locator('[data-node-id="signature"]').first().click();
    await expect(main.locator('[data-node-id="signature"]')).toHaveAttribute(
      'aria-selected',
      'true',
    );
  });

  test('fold state survives a re-render (view option change)', async ({ page }) => {
    const { main } = panes(page);
    await main
      .locator('[data-node-id="payload"]')
      .getByRole('button', { name: 'Collapse' })
      .click();
    // Re-render through the engine with another view option.
    await page.getByRole('button', { name: 'Settings' }).click();
    const settings = page.getByRole('dialog', { name: 'Settings' });
    await settings.getByRole('checkbox', { name: 'Registry annotations' }).click();
    await page.keyboard.press('Escape');
    await expect(settings).toBeHidden();
    await expect(main).not.toContainText('/ iss /');
    await expect(main.locator('[data-node-id="payload"]')).toHaveAttribute(
      'aria-expanded',
      'false',
    );
  });
});

test.describe('JOSE (segments ↔ JSON view)', () => {
  test.beforeEach(async ({ page }) => {
    await paste(page, fixtureText('tokens/rfc7515-a3-jws-es256.txt'));
    await expect(page.getByTestId('detected-type')).toHaveText('JWT');
  });

  test('collapsing a part collapses its segment', async ({ page }) => {
    const { main, raw } = panes(page);
    await main
      .locator('[data-node-id="payload"]')
      .getByRole('button', { name: 'Collapse' })
      .click();
    await expect(raw.locator('[data-node-id="payload"]')).toHaveAttribute('aria-expanded', 'false');
    await expect(main).not.toContainText('"iss":"joe"');
  });

  test('selecting a claim highlights its characters in the payload segment', async ({ page }) => {
    const { main, raw } = panes(page);
    await main.locator('[data-node-id="payload/~e/iss"]').click();
    const segment = raw.locator('[data-node-id="payload"]');
    await expect(segment).toHaveAttribute('aria-selected', 'true');
    // The marked base64url characters decode to text containing the claim.
    const marked = (await segment.locator('mark').textContent()) ?? '';
    expect(marked.length).toBeGreaterThan(0);
    const decoded = Buffer.from(marked, 'base64url').toString('latin1');
    expect(decoded).toContain('joe');
  });
});
