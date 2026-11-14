// Desktop menus (SPEC §4): the native menu bar sends item ids to the
// frontend through `Platform.onMenu`, and the frontend performs the action.
// Ids: new_tab (⌘T / Ctrl+T), open_file (⌘O / Ctrl+O), from_clipboard,
// close_tab (⌘W / Ctrl+W), split_view, raw_pane, datetime, settings, about.
import { screen, waitFor, within } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import { utf8 } from '../../lib/engine/bytes';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp, type TestApp } from '../render';
import { NAMES, activePanel, tabBox, textOf } from '../ui';

function desktop(setup: (app: TestApp) => void = () => undefined): TestApp {
  const app = setupApp();
  app.platform.kind = 'tauri';
  setup(app);
  renderWithApp(AppShell, {}, app);
  return app;
}

const tabs = () => within(screen.getByRole('tablist', { name: 'Credentials' })).getAllByRole('tab');

async function menu(app: TestApp, id: string) {
  await waitFor(() => expect(app.platform.onMenu).toHaveBeenCalled());
  app.platform.emitMenu(id);
}

describe('desktop menu', () => {
  it('the shell subscribes to menu events', async () => {
    const app = desktop();
    await waitFor(() => expect(app.platform.onMenu).toHaveBeenCalledTimes(1));
    expect(app.platform.menuHandlers).toHaveLength(1);
  });

  it('File → New Tab opens an empty tab', async () => {
    const app = desktop();
    await menu(app, 'new_tab');
    await waitFor(() => expect(tabs()).toHaveLength(2));
    expect(tabs()[1]).toHaveAttribute('aria-selected', 'true');
    expect(textOf(tabBox())).toBe('');
  });

  it('File → Close Tab closes the active tab', async () => {
    const app = desktop((a) => {
      seedTab(a.workspace, fx.jwt);
      seedTab(a.workspace, fx.cwt);
    });
    expect(tabs()).toHaveLength(2);
    await menu(app, 'close_tab');
    await waitFor(() => expect(tabs()).toHaveLength(1));
    expect(app.workspace.tabs.map((t) => t.doc.kind.type)).toEqual(['jwt']);
  });

  it('File → From Clipboard fills the empty active tab and runs token detection', async () => {
    const app = desktop((a) => (a.platform.clipboard = fx.jwtToken));
    await menu(app, 'from_clipboard');
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    await waitFor(() =>
      expect(within(activePanel()).getByTestId('detected-type')).toHaveTextContent('JWT'),
    );
    expect(tabs()).toHaveLength(1);
  });

  it('File → From Clipboard with a non-empty active tab opens a new tab for it', async () => {
    const app = desktop((a) => {
      seedTab(a.workspace, fx.cwt);
      a.platform.clipboard = fx.jwtToken;
    });
    await menu(app, 'from_clipboard');
    await waitFor(() => expect(tabs()).toHaveLength(2));
    await waitFor(() =>
      expect(within(activePanel()).getByTestId('detected-type')).toHaveTextContent('JWT'),
    );
    expect(app.workspace.tabs[0]?.doc.kind.type).toBe('cwt');
  });

  it('File → Open File… reads a file into the empty tab', async () => {
    const app = desktop((a) => {
      a.platform.files = [{ name: 'token.jwt', bytes: utf8(fx.jwtToken) }];
    });
    await menu(app, 'open_file');
    await waitFor(() => expect(app.platform.openFile).toHaveBeenCalled());
    await waitFor(() => expect(app.engine.detect).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    await waitFor(() =>
      expect(
        within(activePanel()).getByRole('navigation', { name: 'Provenance' }),
      ).toHaveTextContent('File: token.jwt'),
    );
  });

  it('Tools → Date/time opens the chit; Help → About opens About', async () => {
    const app = desktop();
    await menu(app, 'datetime');
    expect(await screen.findByRole('dialog', { name: 'Date/time' })).toBeInTheDocument();
    await menu(app, 'about');
    expect(await screen.findByRole('dialog', { name: 'About' })).toBeInTheDocument();
  });

  it('unsubscribes when the shell goes away', async () => {
    const app = setupApp();
    app.platform.kind = 'tauri';
    const { unmount } = renderWithApp(AppShell, {}, app);
    await waitFor(() => expect(app.platform.menuHandlers).toHaveLength(1));
    unmount();
    expect(app.platform.menuHandlers).toHaveLength(0);
  });

  it('the on-screen buttons stay (the menu is a shortcut)', () => {
    desktop();
    expect(screen.getByRole('button', { name: NAMES.newTab })).toBeInTheDocument();
    expect(within(activePanel()).getByRole('button', { name: NAMES.openFile })).toBeInTheDocument();
  });
});
