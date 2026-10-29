// Input, detection, "Detected as…", and the unwrapping breadcrumb (SPEC §3).
import { screen, within, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import TabHeader from '../../lib/components/TabHeader.svelte';
import { utf8 } from '../../lib/engine/bytes';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

describe('tab header detection info', () => {
  it('shows the detected type and the unwrapping-layer breadcrumb', () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt, { candidates: fx.bearerCandidates });
    renderWithApp(TabHeader, { tabId: tab.id }, app);
    expect(screen.getByTestId('detected-type')).toHaveTextContent('JWT');
    const crumbs = within(screen.getByRole('navigation', { name: 'Unwrapping layers' }))
      .getAllByRole('listitem')
      .map((li) => li.textContent?.trim());
    expect(crumbs).toEqual(['Authorization header', 'Bearer', 'JWT']);
  });

  it('"Detected as…" lists the candidates and re-opens the input as another', async () => {
    const app = setupApp();
    app.engine.open.mockResolvedValueOnce(fx.sdJwt);
    const tab = seedTab(app.workspace, fx.jwt, {
      candidates: fx.containerCandidates,
      input: utf8('{"credential":"…","id_token":"…"}'),
    });
    renderWithApp(TabHeader, { tabId: tab.id }, app);
    await userEvent.click(screen.getByRole('button', { name: /detected as/i }));
    const menu = screen.getByRole('menu');
    const items = within(menu).getAllByRole('menuitemradio');
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveAttribute('aria-checked', 'true');
    expect(items[1]).toHaveTextContent('SD-JWT');
    await userEvent.click(items[1] as HTMLElement);
    await waitFor(() => expect(screen.getByTestId('detected-type')).toHaveTextContent('SD-JWT'));
    expect(app.engine.open).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      fx.containerCandidates[1],
      expect.anything(),
    );
    const crumbs = within(
      screen.getByRole('navigation', { name: 'Unwrapping layers' }),
    ).getAllByRole('listitem');
    expect(crumbs.map((c) => c.textContent?.trim())).toEqual(['JSON field id_token', 'SD-JWT']);
  });
});

describe('opening input', () => {
  it('pasting a token opens a tab', async () => {
    const app = setupApp();
    renderWithApp(AppShell, {}, app);
    await userEvent.click(screen.getByRole('textbox', { name: /paste a credential or key/i }));
    await userEvent.paste(fx.jwtToken);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(1));
    expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken));
    expect(screen.getByRole('tab', { selected: true })).toHaveTextContent('JWT');
  });

  it('pasting a key adds it to the key panel instead', async () => {
    const app = setupApp();
    app.engine.detect.mockResolvedValueOnce(fx.jwkCandidates);
    renderWithApp(AppShell, {}, app);
    await userEvent.click(screen.getByRole('textbox', { name: /paste a credential or key/i }));
    await userEvent.paste(fx.VERIFIER_JWK);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    const keys = screen.getByRole('complementary', { name: 'Keys' });
    await waitFor(() => expect(within(keys).getAllByRole('article')).toHaveLength(1));
    expect(screen.queryAllByRole('tab')).toHaveLength(0);
  });

  it('opens from the clipboard with clipboard provenance', async () => {
    const app = setupApp();
    app.platform.clipboard = fx.jwtToken;
    renderWithApp(AppShell, {}, app);
    await userEvent.click(screen.getByRole('button', { name: /from clipboard/i }));
    await waitFor(() => expect(screen.getAllByRole('tab')).toHaveLength(1));
    expect(screen.getByRole('navigation', { name: 'Provenance' })).toHaveTextContent('Clipboard');
  });
});
