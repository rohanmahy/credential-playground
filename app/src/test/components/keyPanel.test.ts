// Key panel (SPEC §4.2).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import KeyPanel from '../../lib/components/KeyPanel.svelte';
import { textToB64u } from '../../lib/engine/bytes';
import { KEY_SPECS } from '../../lib/logic/keys';
import * as fx from '../fixtures';
import { renderWithApp, seedKeys, setupApp } from '../render';

function panel(...cards: (typeof fx.issuerCard)[]) {
  const app = setupApp();
  seedKeys(app, ...cards);
  renderWithApp(KeyPanel, {}, app);
  return { app, aside: screen.getByRole('complementary', { name: 'Keys' }) };
}

const card = (label: string) => screen.getByRole('article', { name: label });

describe('key cards', () => {
  it('show type, role, kid, private/public, provenance, and both thumbprints', () => {
    panel(fx.issuerCard, fx.verifierCard);
    const c = card('Issuer P-256');
    expect(c).toHaveTextContent('EC P-256');
    expect(within(c).getByRole('combobox', { name: 'Role' })).toHaveValue('issuer');
    expect(within(c).getByTestId('kid')).toHaveTextContent('issuer-1');
    expect(c).toHaveTextContent(/private/i);
    expect(c).toHaveTextContent('Generated');
    expect(c).toHaveTextContent(fx.issuerInfo.jwk_thumbprint);
    expect(c).toHaveTextContent(fx.issuerInfo.cose_thumbprint);
    expect(card('Verifier P-256')).toHaveTextContent(/public/i);
    expect(card('Verifier P-256')).toHaveTextContent('Pasted');
  });

  it('roles can be changed', async () => {
    const { app } = panel(fx.holderCard);
    await userEvent.selectOptions(
      within(card('Holder Ed25519')).getByRole('combobox', { name: 'Role' }),
      'verifier',
    );
    expect(app.keys.get('key-2')?.role).toBe('verifier');
  });

  it('thumbprints use a selectable hash', async () => {
    const { app } = panel(fx.issuerCard);
    await userEvent.selectOptions(
      within(card('Issuer P-256')).getByRole('combobox', { name: 'Thumbprint hash' }),
      'sha384',
    );
    await waitFor(() =>
      expect(app.engine.keyThumbprint).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'jwk', hash: 'sha384' }),
      ),
    );
    expect(app.engine.keyThumbprint).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'cose', hash: 'sha384' }),
    );
  });

  it('auto kid sets the kid to the JWK thumbprint', async () => {
    const { app } = panel(fx.issuerCard);
    const c = card('Issuer P-256');
    await userEvent.click(within(c).getByRole('button', { name: /set kid/i }));
    await userEvent.click(screen.getByRole('menuitem', { name: /JWK thumbprint/i }));
    await waitFor(() =>
      expect(app.engine.keyAssignKid).toHaveBeenCalledWith(
        expect.objectContaining({ source: { type: 'jwk_thumbprint', hash: 'sha256' } }),
      ),
    );
    await waitFor(() =>
      expect(within(card('Issuer P-256')).getByTestId('kid')).toHaveTextContent(
        fx.issuerInfo.jwk_thumbprint,
      ),
    );
  });

  it('derive public key adds a linked card', async () => {
    const { app } = panel(fx.issuerCard);
    await userEvent.click(
      within(card('Issuer P-256')).getByRole('button', { name: /derive public key/i }),
    );
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(2));
    expect(app.keys.cards[1]?.provenance).toEqual({
      type: 'derived_key',
      parent: 'key-1',
      how: 'public',
    });
    expect(screen.getAllByRole('article')[1]).toHaveTextContent(/derived from Issuer P-256/i);
  });
});

describe('create', () => {
  it('offers every algorithm and creates a seeded key', async () => {
    const { app } = panel();
    await userEvent.click(screen.getByRole('button', { name: 'Create key' }));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    const alg = within(dialog).getByRole('combobox', { name: 'Algorithm' });
    expect(
      within(alg)
        .getAllByRole('option')
        .map((o) => o.textContent?.trim()),
    ).toEqual(KEY_SPECS.map((k) => k.label));
    await userEvent.selectOptions(alg, 'ML-DSA-65');
    await userEvent.click(within(dialog).getByRole('radio', { name: /from a seed/i }));
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Seed' }), 'abc');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Role' }), 'holder');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(app.engine.keyGenerate).toHaveBeenCalled());
    expect(app.engine.keyGenerate.mock.calls[0]?.[0]).toMatchObject({
      spec: { type: 'ml_dsa65' },
      seed: { type: 'seed', bytes: textToB64u('abc') },
      role: 'holder',
    });
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(1));
  });

  it('can use the well-known test seed', async () => {
    const { app } = panel();
    await userEvent.click(screen.getByRole('button', { name: 'Create key' }));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    await userEvent.click(within(dialog).getByRole('radio', { name: /well-known test seed/i }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(app.engine.keyGenerate).toHaveBeenCalled());
    expect(app.engine.keyGenerate.mock.calls[0]?.[0].seed).toEqual({ type: 'well_known' });
  });
});

describe('import', () => {
  it('from a paste', async () => {
    const { app } = panel();
    await userEvent.click(screen.getByRole('button', { name: 'Import key' }));
    const dialog = screen.getByRole('dialog', { name: 'Import key' });
    await userEvent.click(within(dialog).getByRole('textbox', { name: 'Key' }));
    await userEvent.paste(fx.VERIFIER_JWK);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Import' }));
    await waitFor(() =>
      expect(app.engine.keyImport).toHaveBeenCalledWith(
        expect.objectContaining({ bytes: textToB64u(fx.VERIFIER_JWK) }),
      ),
    );
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(1));
    expect(screen.getByRole('article')).toHaveTextContent('Pasted');
  });

  it('from the clipboard and from a file', async () => {
    const { app } = panel();
    app.platform.clipboard = fx.VERIFIER_JWK;
    app.platform.files = [{ name: 'holder.pem', bytes: new Uint8Array([45, 45]) }];
    await userEvent.click(screen.getByRole('button', { name: 'Import key' }));
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Import key' })).getByRole('button', {
        name: /from clipboard/i,
      }),
    );
    await waitFor(() => expect(app.platform.readClipboard).toHaveBeenCalled());
    await userEvent.click(screen.getByRole('button', { name: 'Import key' }));
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Import key' })).getByRole('button', {
        name: /from file/i,
      }),
    );
    await waitFor(() => expect(app.platform.openFile).toHaveBeenCalled());
    await waitFor(() => expect(screen.getAllByRole('article')).toHaveLength(2));
    expect(screen.getAllByRole('article')[1]).toHaveTextContent('File: holder.pem');
  });
});

describe('export', () => {
  it('defaults to public and needs an explicit choice for private', async () => {
    const { app } = panel(fx.issuerCard);
    await userEvent.click(within(card('Issuer P-256')).getByRole('button', { name: 'Export' }));
    const dialog = screen.getByRole('dialog', { name: 'Export key' });
    expect(within(dialog).getByRole('radio', { name: 'Public' })).toBeChecked();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Copy public key' }));
    await waitFor(() =>
      expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.VERIFIER_JWK, {
        sensitive: false,
      }),
    );

    await userEvent.click(within(dialog).getByRole('radio', { name: 'Private' }));
    const copyPrivate = within(dialog).getByRole('button', { name: 'Copy private key' });
    expect(copyPrivate).toBeDisabled();
    expect(within(dialog).getByRole('button', { name: /save/i })).toBeDisabled();
    await userEvent.click(
      within(dialog).getByRole('checkbox', { name: /I understand this exports the private key/i }),
    );
    expect(copyPrivate).toBeEnabled();
    await userEvent.click(copyPrivate);
    await waitFor(() =>
      expect(app.platform.writeClipboard).toHaveBeenLastCalledWith(fx.ISSUER_JWK, {
        sensitive: true,
      }),
    );
    expect(await within(dialog).findByRole('status')).toHaveTextContent(
      /private key copied to clipboard/i,
    );
  });

  it('offers JWK, COSE_Key, and PEM formats', async () => {
    panel(fx.issuerCard);
    await userEvent.click(within(card('Issuer P-256')).getByRole('button', { name: 'Export' }));
    const fmt = within(screen.getByRole('dialog', { name: 'Export key' })).getByRole('combobox', {
      name: 'Format',
    });
    const options = within(fmt)
      .getAllByRole('option')
      .map((o) => o.textContent ?? '');
    for (const f of [/^JWK$/, /JWK Set/, /COSE_Key/, /COSE_KeySet/, /PEM/]) {
      expect(
        options.some((o) => f.test(o)),
        String(f),
      ).toBe(true);
    }
  });
});

describe('convert', () => {
  it('shows JWK and CWK side by side, public or private', async () => {
    const { app } = panel(fx.issuerCard);
    await userEvent.click(within(card('Issuer P-256')).getByRole('button', { name: 'Convert' }));
    const jwk = await screen.findByRole('region', { name: 'JWK' });
    const cwk = screen.getByRole('region', { name: 'COSE_Key' });
    await waitFor(() => expect(jwk).toHaveTextContent('"kty":"EC"'));
    await waitFor(() => expect(cwk).toHaveTextContent('/ kty / 1: 2'));
    expect(app.engine.keyToJwk).toHaveBeenLastCalledWith(
      expect.objectContaining({ visibility: 'public' }),
    );
    await userEvent.click(screen.getByRole('switch', { name: /private/i }));
    await waitFor(() =>
      expect(app.engine.keyToCwk).toHaveBeenLastCalledWith(
        expect.objectContaining({ visibility: 'private' }),
      ),
    );
    expect(app.engine.keyToJwk).toHaveBeenLastCalledWith(
      expect.objectContaining({ visibility: 'private' }),
    );
  });
});
