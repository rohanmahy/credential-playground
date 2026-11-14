// Writing a credential from scratch in an empty tab (#43 under SPEC §4.1):
// the Type picker sets what typed text parses as; the type then changes
// only through "Detected as…" and sticks across edits; typed tabs have no
// original signature, so they never go stale; claim sets can be issued
// with the Issuer area's key. Names: ../ui.ts.
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import * as fx from '../fixtures';
import { parseAsKind } from '../MockEngine';
import { renderWithApp, seedKeys, setupApp, type TestApp } from '../render';
import { NAMES, activePanel, tabBox, typeInto } from '../ui';

function shell(setup: (app: TestApp) => void = () => undefined): TestApp {
  const app = setupApp();
  app.engine.parseEdit.mockImplementation(parseAsKind);
  setup(app);
  renderWithApp(AppShell, {}, app);
  return app;
}

const detectedType = () => within(activePanel()).getByTestId('detected-type');

async function writeEdn(text: string) {
  await userEvent.selectOptions(
    within(activePanel()).getByRole('combobox', { name: NAMES.type }),
    NAMES.ednClaims,
  );
  await typeInto(tabBox(), text);
  await waitFor(() => expect(detectedType()).toHaveTextContent(/./));
}

describe('type of a typed tab', () => {
  it('"Detected as…" sets the type explicitly, and the choice survives edits', async () => {
    const app = shell();
    await writeEdn(fx.CWT_EDN);
    expect(detectedType()).toHaveTextContent('EDN claim set');
    await userEvent.click(within(activePanel()).getByRole('button', { name: /detected as/i }));
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await userEvent.click(
      within(screen.getByRole('menu')).getByRole('menuitemradio', { name: /^CWT/ }),
    );
    await waitFor(() => expect(detectedType()).toHaveTextContent('CWT'));
    expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: { type: 'cwt' } }),
    );

    await typeInto(tabBox(), ' ');
    await waitFor(() =>
      expect(app.engine.parseEdit).toHaveBeenLastCalledWith(
        expect.objectContaining({ kind: { type: 'cwt' }, text: `${fx.CWT_EDN} ` }),
      ),
    );
    expect(detectedType()).toHaveTextContent('CWT');
    expect(app.engine.detect).not.toHaveBeenCalled();
    await userEvent.click(within(activePanel()).getByRole('button', { name: /detected as/i }));
    expect(
      within(screen.getByRole('menu')).getByRole('menuitemradio', { name: /^CWT/ }),
    ).toHaveAttribute('aria-checked', 'true');
  });

  it('a typed COSE_Key stays in the tab: nothing is added to the key areas', async () => {
    const app = shell();
    await writeEdn(fx.ISSUER_CWK_EDN);
    expect(screen.queryByRole('button', { name: 'Add to key panel' })).toBeNull();
    expect(app.keys.forRole('issuer')).toBeNull();
    expect(app.keys.forRole('holder')).toBeNull();
    expect(app.engine.keyImport).not.toHaveBeenCalled();
  });

  it('a typed COSE_Sign1 set to CWT is never marked stale (no original signature)', async () => {
    const app = shell();
    await writeEdn(fx.CWT_EDN);
    app.engine.parseEdit.mockResolvedValue(fx.cwtDraftEdit);
    await userEvent.click(within(activePanel()).getByRole('button', { name: /detected as/i }));
    await userEvent.click(screen.getByRole('menuitemradio', { name: /^CWT/ }));
    await waitFor(() => expect(detectedType()).toHaveTextContent('CWT'));
    expect(screen.queryByText('modified – signature stale')).toBeNull();
    expect(
      within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
        name: 'Validate',
      }),
    ).toHaveAttribute('aria-disabled', 'false');
  });
});

describe('actions', () => {
  it('a typed JSON claim set is issued with the Issuer area key', async () => {
    const app = shell((a) => seedKeys(a, fx.issuerCard));
    await typeInto(tabBox(), fx.DRAFT_JSON_TEXT);
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
    const issue = within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
      name: 'Issue',
    });
    await waitFor(() => expect(issue).toHaveAttribute('aria-disabled', 'false'));
    await userEvent.click(issue);
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Issue' })).getByRole('button', { name: 'Issue' }),
    );
    await waitFor(() => expect(app.engine.issue).toHaveBeenCalled());
    expect(app.engine.issue.mock.calls[0]?.[0].issuer.bytes).toBe(fx.issuerInfo.key.bytes);
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(2));
  });

  it('without an Issuer key, Issue is disabled and says so', async () => {
    shell((a) => seedKeys(a, fx.holderCard));
    await typeInto(tabBox(), fx.DRAFT_JSON_TEXT);
    await waitFor(() => expect(detectedType()).toHaveTextContent('JSON claim set'));
    const issue = within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
      name: 'Issue',
    });
    expect(issue).toHaveAttribute('aria-disabled', 'true');
    expect(issue.getAttribute('title')).toMatch(/issuer key/i);
  });
});
