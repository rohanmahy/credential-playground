// Checklist §5 and §6: Issue/Redact → Present (holder key, audience,
// nonce) → Validate with key binding, JOSE and COSE, with seeded keys on
// the native engine. Mirrors app/e2e/issue-present.spec.ts.
import { browser } from '@wdio/globals';
import {
  actions,
  appReady,
  createKey,
  detectedType,
  expectSignature,
  expectThat,
  fixtureText,
  mainPane,
  page,
  paste,
  rawPane,
  validate,
} from '../helpers';

// Key binding validates against `cnf` (SPEC §6), so credentials that are
// presented later are issued with the holder key as `cnf`.
async function issueWithHolder(action: 'Issue' | 'Redact'): Promise<void> {
  const dialog = page.getByRole('dialog', action);
  await dialog.getByRole('combobox', 'Holder key (cnf)').selectOption('Holder Ed25519');
  await dialog.getByRole('button', action).click();
  await expectThat(dialog).toBeHidden();
}

async function presentTo(): Promise<void> {
  await actions().getByRole('button', 'Present').click();
  const present = page.getByRole('dialog', 'Present');
  await present.getByRole('textbox', 'Audience').type('https://verifier.example');
  await present.getByRole('textbox', 'Nonce').type('n-0S6');
  await present.getByRole('button', 'Present').click();
  await expectThat(present).toBeHidden();
}

// Redact needs EDN with to-be-redacted (58) tags (SPEC §5); the claims of
// SD-CWT Figure 4 are the issuer's input before tagging.
const TAGGED_EDN =
  '{1: "https://issuer.example", 2: "https://holder.example", 6: 1725244200, ' +
  '58(500): true, 501: "ABCD-123456", 502: [58(1549560720), 1612498440]}';

describe('issue, present, validate', () => {
  beforeEach(async () => {
    await browser.refresh();
    await appReady();
    await createKey('EC P-256', 'issuer');
    await createKey('Ed25519', 'holder');
  });

  it('SD-JWT: mark claims, issue, present with audience and nonce, key binding passes', async () => {
    await paste(fixtureText('tokens/rfc9901-a1-input-claims.json'));
    await expectThat(detectedType()).toHaveText('JSON claim set');
    await mainPane().locator('[data-node-id="given_name"]').rightClick();
    await page.getByRole('menuitemcheckbox', /selectively disclosable/i).click();
    await expectThat(mainPane().locator('[data-sd-mark="true"]')).toHaveCount(1);
    await actions().getByRole('button', 'Issue').click();
    await issueWithHolder('Issue');
    await expectThat(detectedType()).toHaveText('SD-JWT');
    await expectThat(page.getByRole('table', 'Disclosures')).toContainText('given_name');

    await presentTo();
    await expectThat(detectedType()).toHaveText('SD-JWT+KB');
    await expectThat(page.getByRole('navigation', 'Provenance')).toContainText('Present');

    const report = await validate();
    await expectThat(page.getByTestId('report-overall')).toHaveText(/pass/i);
    await expectSignature('pass');
    await expectThat(report).toContainText(/key binding/i);
  });

  it('SD-CWT: redact tagged EDN, present as SD-KBT, validate', async () => {
    await paste(TAGGED_EDN);
    await expectThat(detectedType()).toHaveText('EDN claim set');
    await actions().getByRole('button', 'Redact').click();
    await issueWithHolder('Redact');
    await expectThat(detectedType()).toHaveText('SD-CWT');
    await expectThat(page.getByRole('table', 'Disclosures')).toBeVisible();

    await presentTo();
    await expectThat(detectedType()).toHaveText('SD-KBT');
    await expectThat(mainPane()).toContainText('/ kcwt /');

    const report = await validate();
    await expectThat(page.getByTestId('report-overall')).toHaveText(/pass|warn/i);
    await expectSignature('pass');
    await expectThat(report).toContainText(/key binding/i);
  });

  it('CWT: issue from EDN, present in an SD-KBT, validate', async () => {
    await paste('{1: "https://issuer.example", 2: "alice", 4: 1900000000}');
    await expectThat(detectedType()).toHaveText('EDN claim set');
    await actions().getByRole('button', 'Issue').click();
    await issueWithHolder('Issue');
    await expectThat(detectedType()).toHaveText('CWT');
    await expectThat(rawPane()).toBeVisible();

    await presentTo();
    await expectThat(detectedType()).toHaveText('SD-KBT');
    await validate();
    await expectSignature('pass');
    await expectThat(page.getByTestId('report-overall')).toHaveText(/pass|warn/i);
  });
});
