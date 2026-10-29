// Checklist §7: live edit a signed JWT → "modified – signature stale" →
// Keep original signature → Validate FAIL (tampered); Re-sign → PASS.
// The edit is real keystrokes into CodeMirror.
import {
  actions,
  appReady,
  createKey,
  detectedType,
  expectSignature,
  expectThat,
  page,
  paste,
  validate,
} from '../helpers';

describe('live edit and tamper', () => {
  before(appReady);

  it('edit → stale → keep signature → FAIL; re-sign → PASS', async () => {
    await createKey('EC P-256', 'issuer');
    await paste('{"iss": "https://issuer.example", "sub": "alice"}');
    await expectThat(detectedType()).toHaveText('JSON claim set');
    await actions().getByRole('button', 'Issue').click();
    const issue = page.getByRole('dialog', 'Issue');
    await issue.getByRole('button', 'Issue').click();
    await expectThat(issue).toBeHidden();
    await expectThat(detectedType()).toHaveText('JWT');
    await validate();
    await expectSignature('pass');

    const live = page.getByRole('switch', 'Live edit');
    await live.click();
    await expectThat(live).toHaveAttribute('aria-checked', 'true');
    const editor = page.getByTestId('live-editor').locator('.cm-content');
    await expectThat(editor).toContainText('alice');
    await editor.selectText('alice');
    await editor.keys('mallory');
    await expectThat(editor).toContainText('mallory');

    const stale = page.getByRole('status').withText('modified – signature stale');
    await expectThat(stale).toBeVisible();
    await stale.getByRole('button', 'Keep original signature').click();
    await expectThat(page.getByTestId('validation-badge')).toHaveText(/tampered/i);
    await validate();
    await expectSignature('fail');

    await actions().getByRole('button', 'Re-sign').click();
    await expectThat(page.getByRole('navigation', 'Provenance')).toContainText('Re-sign');
    await expectThat(page.getByRole('switch', 'Live edit')).toHaveAttribute(
      'aria-checked',
      'false',
    );
    await validate();
    await expectSignature('pass');
    await expectThat(page.getByRole('tree', 'Main pane')).toContainText('mallory');
  });
});
