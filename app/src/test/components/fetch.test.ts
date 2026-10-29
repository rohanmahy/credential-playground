// URL fetches are always user-confirmed; CORS failures on the web explain
// themselves and offer pasting instead (SPEC §1, §4.2, §6, §9).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import CredentialTab from '../../lib/components/CredentialTab.svelte';
import KeyPanel from '../../lib/components/KeyPanel.svelte';
import { FetchError } from '../../lib/platform/Platform';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

const URL = 'https://issuer.example/.well-known/jwks.json';

async function askFetch() {
  await userEvent.click(screen.getByRole('button', { name: 'Fetch from URL' }));
  await userEvent.type(screen.getByRole('textbox', { name: 'URL' }), URL);
  await userEvent.click(screen.getByRole('button', { name: 'Fetch' }));
  return screen.getByRole('alertdialog');
}

describe('key fetch', () => {
  it('asks before fetching, showing the URL and the privacy note; Cancel fetches nothing', async () => {
    const app = setupApp();
    renderWithApp(KeyPanel, {}, app);
    const confirm = await askFetch();
    expect(confirm).toHaveTextContent(URL);
    expect(confirm).toHaveTextContent(/IP address/);
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
    await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
  });

  it('fetches and imports after confirmation', async () => {
    const app = setupApp();
    renderWithApp(KeyPanel, {}, app);
    const confirm = await askFetch();
    await userEvent.click(within(confirm).getByRole('button', { name: /^fetch/i }));
    await waitFor(() => expect(app.platform.fetchUrl).toHaveBeenCalledWith(URL));
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(1));
    expect(screen.getByRole('article')).toHaveTextContent(`URL: ${URL}`);
  });

  it('on a CORS failure explains why and offers pasting instead', async () => {
    const app = setupApp();
    app.platform.fetchUrl.mockRejectedValueOnce(new FetchError('cors', URL, 'Failed to fetch'));
    renderWithApp(KeyPanel, {}, app);
    const confirm = await askFetch();
    await userEvent.click(within(confirm).getByRole('button', { name: /^fetch/i }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/CORS|cross-origin/i);
    expect(alert).toHaveTextContent(/desktop app/i);
    await userEvent.click(within(alert).getByRole('button', { name: 'Paste instead' }));
    const box = screen.getByRole('textbox', { name: /paste the content/i });
    await userEvent.click(box);
    await userEvent.paste(fx.VERIFIER_JWK);
    await userEvent.click(screen.getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(app.engine.keyImport).toHaveBeenCalled());
  });
});

describe('fetch hints in a validation report', () => {
  it('are confirmed first, then imported and re-validated', async () => {
    const app = setupApp();
    app.engine.validate.mockResolvedValueOnce(fx.kidUrlReport);
    const tab = seedTab(app.workspace, fx.jwt);
    renderWithApp(CredentialTab, { tabId: tab.id }, app);
    await userEvent.click(screen.getByRole('button', { name: 'Validate' }));
    await userEvent.click(await screen.findByRole('button', { name: /fetch key from/i }));
    const confirm = screen.getByRole('alertdialog');
    expect(confirm).toHaveTextContent('https://issuer.example/keys/1.jwk');
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
    await userEvent.click(within(confirm).getByRole('button', { name: /^fetch/i }));
    await waitFor(() => expect(app.engine.keyImport).toHaveBeenCalled());
    await waitFor(() => expect(app.engine.validate).toHaveBeenCalledTimes(2));
  });
});
