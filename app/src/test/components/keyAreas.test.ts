// The key panel as two key areas, Issuer key and Holder key (SPEC §3,
// §4, §4.2). Each area holds one key, has its own input with key
// detection (`engine.detectKey`), a JWK / COSE_Key format toggle, Clear,
// the key details, and Export / Make public / Auto kid. Names: ../ui.ts.
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AppShell from '../../lib/components/AppShell.svelte';
import { EngineFailure } from '../../lib/engine/Engine';
import { textToB64u, toB64u, utf8 } from '../../lib/engine/bytes';
import { KEY_SPECS } from '../../lib/logic/keys';
import type { KeyCard } from '../../lib/model';
import * as fx from '../fixtures';
import { notAKey } from '../MockEngine';
import { renderWithApp, seedKeys, seedTab, setupApp, type TestApp } from '../render';
import {
  NAMES,
  dropOnto,
  keyArea,
  keyBox,
  keyButton,
  pasteInto,
  textOf,
  typeInto,
  type AreaRole,
} from '../ui';

function shell(...cards: KeyCard[]): TestApp {
  const app = setupApp();
  seedKeys(app, ...cards);
  renderWithApp(AppShell, {}, app);
  return app;
}

function formatRadio(role: AreaRole, name: 'JWK' | 'COSE_Key'): HTMLElement {
  const group = within(keyArea(role)).getByRole('radiogroup', { name: NAMES.keyFormat });
  return within(group).getByRole('radio', { name });
}

/** A key operation that needs a key: absent, disabled, or aria-disabled. */
function expectUnavailable(role: AreaRole, name: string) {
  const button = within(keyArea(role)).queryByRole('button', { name });
  if (button === null) return;
  const off = button.hasAttribute('disabled') || button.getAttribute('aria-disabled') === 'true';
  expect(off, `${name} in the ${role} area should be unavailable`).toBe(true);
}

const keyOf = (app: TestApp, role: AreaRole) => app.keys.forRole(role);

describe('layout', () => {
  it('the key panel is split into an Issuer key and a Holder key area with their own buttons', () => {
    shell();
    for (const role of ['issuer', 'holder'] as const) {
      const area = keyArea(role);
      for (const name of [NAMES.create, NAMES.import, NAMES.fetch, NAMES.clear]) {
        expect(within(area).getByRole('button', { name }), `${role}: ${name}`).toBeInTheDocument();
      }
      expect(textOf(keyBox(role))).toBe('');
      expect(formatRadio(role, 'JWK')).toBeChecked();
      expect(formatRadio(role, 'COSE_Key')).not.toBeChecked();
    }
  });

  it('the area is the role: no role picker and no Verifier anywhere', () => {
    shell(fx.issuerCard, fx.holderCard);
    expect(screen.queryByRole('combobox', { name: 'Role' })).toBeNull();
    expect(screen.queryByText(/verifier/i)).toBeNull();
    expect(screen.queryByRole('option', { name: /verifier/i })).toBeNull();
  });

  it('with no key, the operations that need one are unavailable', () => {
    shell();
    for (const role of ['issuer', 'holder'] as const) {
      for (const name of [NAMES.export, NAMES.makePublic, NAMES.autoKid]) {
        expectUnavailable(role, name);
      }
    }
  });
});

describe('a key in an area', () => {
  it('shows the key as JWK text and its details', async () => {
    shell(fx.issuerCard, fx.holderCard);
    await waitFor(() => expect(textOf(keyBox('issuer'))).toMatch(/"kty":\s*"EC"/));
    expect(textOf(keyBox('issuer'))).toContain('issuer-1');
    const issuer = keyArea('issuer');
    expect(issuer).toHaveTextContent('EC P-256');
    expect(within(issuer).getByTestId('kid')).toHaveTextContent('issuer-1');
    expect(issuer).toHaveTextContent(/private/i);
    expect(issuer).toHaveTextContent('Generated');
    expect(issuer).toHaveTextContent(fx.issuerInfo.jwk_thumbprint);
    expect(issuer).toHaveTextContent(fx.issuerInfo.cose_thumbprint);

    await waitFor(() => expect(textOf(keyBox('holder'))).toMatch(/"kty":\s*"OKP"/));
    const holder = keyArea('holder');
    expect(holder).toHaveTextContent('Ed25519');
    expect(holder).toHaveTextContent('File: holder.jwk.json');
    expect(holder).not.toHaveTextContent(fx.issuerInfo.jwk_thumbprint);
  });

  it('the format toggle re-renders the key as COSE_Key (EDN) and back', async () => {
    const app = shell(fx.issuerCard);
    await waitFor(() => expect(textOf(keyBox('issuer'))).toMatch(/"kty":\s*"EC"/));
    await userEvent.click(formatRadio('issuer', 'COSE_Key'));
    await waitFor(() => expect(textOf(keyBox('issuer'))).toContain('/ kty / 1: 2'));
    expect(app.engine.keyToCwk).toHaveBeenCalledWith(
      expect.objectContaining({ key: expect.objectContaining({ bytes: fx.issuerInfo.key.bytes }) }),
    );
    expect(formatRadio('issuer', 'COSE_Key')).toBeChecked();
    // the key itself is unchanged
    expect(keyOf(app, 'issuer')?.info.jwk_thumbprint).toBe(fx.issuerInfo.jwk_thumbprint);
    await userEvent.click(formatRadio('issuer', 'JWK'));
    await waitFor(() => expect(textOf(keyBox('issuer'))).toMatch(/"kty":\s*"EC"/));
  });

  it('thumbprints use a selectable hash', async () => {
    const app = shell(fx.issuerCard);
    await userEvent.selectOptions(
      within(keyArea('issuer')).getByRole('combobox', { name: 'Thumbprint hash' }),
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

  it('Auto kid sets the kid to the JWK thumbprint', async () => {
    const app = shell(fx.issuerCard);
    await userEvent.click(keyButton('issuer', NAMES.autoKid));
    await userEvent.click(screen.getByRole('menuitem', { name: /JWK thumbprint/i }));
    await waitFor(() =>
      expect(app.engine.keyAssignKid).toHaveBeenCalledWith(
        expect.objectContaining({ source: { type: 'jwk_thumbprint', hash: 'sha256' } }),
      ),
    );
    await waitFor(() =>
      expect(within(keyArea('issuer')).getByTestId('kid')).toHaveTextContent(
        fx.issuerInfo.jwk_thumbprint,
      ),
    );
    expect(keyOf(app, 'issuer')?.info.kid).toEqual({
      type: 'text',
      value: fx.issuerInfo.jwk_thumbprint,
    });
  });

  it('Make public replaces the area key with its public part (no second key)', async () => {
    const app = shell(fx.issuerCard);
    await userEvent.click(keyButton('issuer', NAMES.makePublic));
    await waitFor(() => expect(app.engine.keyPublic).toHaveBeenCalled());
    expect(app.engine.keyPublic.mock.calls[0]?.[0].bytes).toBe(fx.issuerInfo.key.bytes);
    await waitFor(() => expect(keyOf(app, 'issuer')?.info.private).toBe(false));
    expect(keyOf(app, 'holder')).toBeNull();
    expect(app.keys.cards).toHaveLength(1);
    await waitFor(() => expect(keyArea('issuer')).toHaveTextContent(/public/i));
    await waitFor(() => expect(textOf(keyBox('issuer'))).not.toContain('"d"'));
  });
});

describe('export', () => {
  it('defaults to public and needs an explicit choice for private', async () => {
    const app = shell(fx.issuerCard);
    await userEvent.click(keyButton('issuer', NAMES.export));
    const dialog = screen.getByRole('dialog', { name: 'Export key' });
    expect(within(dialog).getByRole('radio', { name: 'Public' })).toBeChecked();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Copy public key' }));
    await waitFor(() =>
      expect(app.platform.writeClipboard).toHaveBeenCalledWith(fx.ISSUER_PUBLIC_JWK, {
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
    shell(fx.holderCard);
    await userEvent.click(keyButton('holder', NAMES.export));
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

describe('paste into an empty area runs key detection', () => {
  it('a JWK: detectKey, then keyImport with that candidate; the key fills that area only', async () => {
    const app = shell();
    await pasteInto(keyBox('issuer'), fx.ISSUER_JWK);
    await waitFor(() => expect(app.engine.detectKey).toHaveBeenCalledWith(utf8(fx.ISSUER_JWK)));
    await waitFor(() =>
      expect(app.engine.keyImport).toHaveBeenCalledWith(
        expect.objectContaining({
          bytes: textToB64u(fx.ISSUER_JWK),
          candidate: fx.jwkCandidates[0],
        }),
      ),
    );
    await waitFor(() => expect(keyOf(app, 'issuer')).not.toBeNull());
    expect(keyOf(app, 'issuer')?.provenance).toEqual({ type: 'pasted' });
    expect(keyOf(app, 'holder')).toBeNull();
    expect(app.engine.detect).not.toHaveBeenCalled();
    await waitFor(() => expect(keyArea('issuer')).toHaveTextContent('Pasted'));
    // nothing opened in the tabs
    expect(screen.getAllByRole('tab')).toHaveLength(1);
  });

  it('a PEM key is shown as JWK', async () => {
    const app = shell();
    app.engine.detectKey.mockResolvedValueOnce(fx.pemCandidates);
    app.engine.keyImport.mockResolvedValueOnce([fx.issuerPublicInfo]);
    await pasteInto(keyBox('holder'), fx.ISSUER_PEM);
    await waitFor(() =>
      expect(app.engine.keyImport).toHaveBeenCalledWith(
        expect.objectContaining({ candidate: fx.pemCandidates[0] }),
      ),
    );
    await waitFor(() => expect(textOf(keyBox('holder'))).toMatch(/"kty":\s*"EC"/));
    expect(textOf(keyBox('holder'))).not.toContain('BEGIN PUBLIC KEY');
    expect(formatRadio('holder', 'JWK')).toBeChecked();
  });

  it('a COSE_Key: the format toggle follows the detected format', async () => {
    const app = shell();
    app.engine.detectKey.mockResolvedValueOnce(fx.coseKeyCandidates);
    app.engine.keyImport.mockResolvedValueOnce([fx.issuerInfo]);
    await pasteInto(keyBox('issuer'), 'a4010220012158');
    await waitFor(() => expect(keyOf(app, 'issuer')).not.toBeNull());
    await waitFor(() => expect(formatRadio('issuer', 'COSE_Key')).toBeChecked());
    await waitFor(() => expect(textOf(keyBox('issuer'))).toContain('/ kty / 1: 2'));
  });

  it('a token is not a key: "Not a recognized key", and the area stays empty', async () => {
    const app = shell();
    app.engine.detectKey.mockResolvedValueOnce([]);
    await pasteInto(keyBox('issuer'), fx.jwtToken);
    await waitFor(() => expect(app.engine.detectKey).toHaveBeenCalledWith(utf8(fx.jwtToken)));
    expect(await within(keyArea('issuer')).findByRole('alert')).toHaveTextContent(NAMES.notAKey);
    expect(keyOf(app, 'issuer')).toBeNull();
    expect(app.engine.detect).not.toHaveBeenCalled();
    expect(screen.getAllByRole('tab')).toHaveLength(1);
    expectUnavailable('issuer', NAMES.export);
  });

  it('keyImport rejecting with not_a_key shows its message', async () => {
    const app = shell();
    app.engine.keyImport.mockRejectedValueOnce(notAKey());
    await pasteInto(keyBox('holder'), '{"iss":"x"}');
    expect(await within(keyArea('holder')).findByRole('alert')).toHaveTextContent(NAMES.notAKey);
    expect(keyOf(app, 'holder')).toBeNull();
  });

  it('a JWK Set opens a chooser (kid, alg, kty); the key picked fills the area', async () => {
    const app = shell();
    app.engine.detectKey.mockResolvedValueOnce(fx.jwkSetCandidates);
    app.engine.keyImport.mockResolvedValueOnce([fx.setKeyA, fx.setKeyB]);
    await pasteInto(keyBox('issuer'), fx.JWK_SET);
    const chooser = await screen.findByRole('dialog', { name: NAMES.chooser });
    const choices = within(chooser)
      .getAllByRole('button')
      .filter((b) => /set-key-/.test(b.textContent ?? ''));
    expect(choices).toHaveLength(2);
    expect(choices[0]).toHaveTextContent('set-key-a');
    expect(choices[0]).toHaveTextContent('ES256');
    expect(choices[0]).toHaveTextContent('EC');
    expect(choices[1]).toHaveTextContent('set-key-b');
    expect(choices[1]).toHaveTextContent('EdDSA');
    expect(choices[1]).toHaveTextContent('OKP');
    expect(keyOf(app, 'issuer')).toBeNull();
    await userEvent.click(choices[1] as HTMLElement);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: NAMES.chooser })).toBeNull());
    expect(keyOf(app, 'issuer')?.info.kid).toEqual({ type: 'text', value: 'set-key-b' });
    expect(keyOf(app, 'holder')).toBeNull();
    expect(app.keys.cards).toHaveLength(1);
  });
});

describe('typing and later edits', () => {
  it('typing into an empty area does not autodetect; it parses in the toggle format (JWK)', async () => {
    const app = shell();
    await typeInto(keyBox('issuer'), fx.ISSUER_JWK);
    await waitFor(() =>
      expect(app.engine.keyImport).toHaveBeenLastCalledWith(
        expect.objectContaining({ bytes: textToB64u(fx.ISSUER_JWK), format: { type: 'jwk' } }),
      ),
    );
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    await waitFor(() => expect(keyOf(app, 'issuer')).not.toBeNull());
  });

  it('with COSE_Key selected, typed text parses as COSE_Key', async () => {
    const app = shell();
    await userEvent.click(formatRadio('holder', 'COSE_Key'));
    await typeInto(keyBox('holder'), fx.ISSUER_CWK_EDN);
    await waitFor(() =>
      expect(app.engine.keyImport).toHaveBeenLastCalledWith(
        expect.objectContaining({ format: { type: 'cose_key' } }),
      ),
    );
    expect(app.engine.detectKey).not.toHaveBeenCalled();
  });

  it('text that does not parse shows an error, and the area has no key', async () => {
    const app = shell();
    app.engine.keyImport.mockRejectedValue(
      new EngineFailure({ code: 'parse', message: 'expected a JSON object', node_id: null }),
    );
    await typeInto(keyBox('issuer'), '{"kty": ');
    expect(await within(keyArea('issuer')).findByRole('alert')).toHaveTextContent(
      'expected a JSON object',
    );
    expect(keyOf(app, 'issuer')).toBeNull();
    expectUnavailable('issuer', NAMES.export);
  });

  it('paste into a non-empty area never autodetects', async () => {
    const app = shell(fx.issuerCard);
    await waitFor(() => expect(textOf(keyBox('issuer'))).toMatch(/"kty":\s*"EC"/));
    await pasteInto(keyBox('issuer'), ' ');
    await pasteInto(keyBox('issuer'), fx.JWK_SET);
    // give a (wrong) detection a chance to run
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog', { name: NAMES.chooser })).toBeNull();
  });
});

describe('Create, Import, Fetch from URL fill their own area', () => {
  it('Create offers every algorithm, has no Role, and fills the area it was opened from', async () => {
    const app = shell();
    await userEvent.click(keyButton('holder', NAMES.create));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    const alg = within(dialog).getByRole('combobox', { name: 'Algorithm' });
    expect(
      within(alg)
        .getAllByRole('option')
        .map((o) => o.textContent?.trim()),
    ).toEqual(KEY_SPECS.map((k) => k.label));
    expect(within(dialog).queryByRole('combobox', { name: 'Role' })).toBeNull();
    await userEvent.selectOptions(alg, 'ML-DSA-65');
    await userEvent.click(within(dialog).getByRole('radio', { name: /from a seed/i }));
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Seed' }), 'abc');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(app.engine.keyGenerate).toHaveBeenCalled());
    expect(app.engine.keyGenerate.mock.calls[0]?.[0]).toMatchObject({
      spec: { type: 'ml_dsa65' },
      seed: { type: 'seed', bytes: textToB64u('abc') },
    });
    await waitFor(() => expect(keyOf(app, 'holder')).not.toBeNull());
    expect(keyOf(app, 'issuer')).toBeNull();
    expect(keyOf(app, 'holder')?.provenance).toEqual({ type: 'generated' });
  });

  it('Create can use the well-known test seed', async () => {
    const app = shell();
    await userEvent.click(keyButton('issuer', NAMES.create));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    await userEvent.click(within(dialog).getByRole('radio', { name: /well-known test seed/i }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(app.engine.keyGenerate).toHaveBeenCalled());
    expect(app.engine.keyGenerate.mock.calls[0]?.[0].seed).toEqual({ type: 'well_known' });
    await waitFor(() => expect(keyOf(app, 'issuer')).not.toBeNull());
  });

  it('a random key uses 32 bytes of platform entropy', async () => {
    const app = shell();
    await userEvent.click(keyButton('issuer', NAMES.create));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    await userEvent.click(within(dialog).getByRole('radio', { name: /random/i }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(app.engine.keyGenerate).toHaveBeenCalled());
    expect(app.platform.randomBytes).toHaveBeenCalledWith(32);
    expect(app.engine.keyGenerate.mock.calls[0]?.[0].seed).toEqual({
      type: 'entropy',
      bytes: toB64u(Uint8Array.from({ length: 32 }, (_, i) => i)),
    });
  });

  it('Create replaces the key already in the area', async () => {
    const app = shell(fx.holderCard);
    app.engine.keyGenerate.mockResolvedValueOnce(fx.mlDsaInfo);
    await userEvent.click(keyButton('holder', NAMES.create));
    const dialog = screen.getByRole('dialog', { name: 'Create key' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(keyOf(app, 'holder')?.info.description).toBe('ML-DSA-44'));
    expect(app.keys.cards).toHaveLength(1);
  });

  it('Import from a paste fills the area; a set goes through the chooser', async () => {
    const app = shell();
    app.engine.keyImport.mockResolvedValueOnce([fx.setKeyA, fx.setKeyB]);
    await userEvent.click(keyButton('holder', NAMES.import));
    const dialog = screen.getByRole('dialog', { name: 'Import key' });
    await userEvent.click(within(dialog).getByRole('textbox', { name: 'Key' }));
    await userEvent.paste(fx.JWK_SET);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Import' }));
    const chooser = await screen.findByRole('dialog', { name: NAMES.chooser });
    await userEvent.click(within(chooser).getByRole('button', { name: /set-key-a/ }));
    await waitFor(() =>
      expect(keyOf(app, 'holder')?.info.kid).toEqual({ type: 'text', value: 'set-key-a' }),
    );
    expect(keyOf(app, 'issuer')).toBeNull();
  });

  it('Import from the clipboard and from a file', async () => {
    const app = shell();
    app.platform.clipboard = fx.ISSUER_PUBLIC_JWK;
    app.platform.files = [{ name: 'holder.pem', bytes: new Uint8Array([45, 45]) }];
    await userEvent.click(keyButton('issuer', NAMES.import));
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Import key' })).getByRole('button', {
        name: /from clipboard/i,
      }),
    );
    await waitFor(() => expect(keyOf(app, 'issuer')?.provenance).toEqual({ type: 'clipboard' }));
    await userEvent.click(keyButton('holder', NAMES.import));
    await userEvent.click(
      within(screen.getByRole('dialog', { name: 'Import key' })).getByRole('button', {
        name: /from file/i,
      }),
    );
    await waitFor(() =>
      expect(keyOf(app, 'holder')?.provenance).toEqual({ type: 'file', name: 'holder.pem' }),
    );
    await waitFor(() => expect(keyArea('holder')).toHaveTextContent('File: holder.pem'));
  });

  it('Fetch from URL is confirmed first; a fetched set goes through the chooser', async () => {
    const app = shell();
    const url = 'https://issuer.example/.well-known/jwks.json';
    app.engine.keyImport.mockResolvedValueOnce([fx.setKeyA, fx.setKeyB]);
    await userEvent.click(keyButton('issuer', NAMES.fetch));
    await userEvent.type(screen.getByRole('textbox', { name: 'URL' }), url);
    await userEvent.click(screen.getByRole('button', { name: 'Fetch' }));
    const confirm = screen.getByRole('alertdialog');
    expect(app.platform.fetchUrl).not.toHaveBeenCalled();
    await userEvent.click(within(confirm).getByRole('button', { name: /^fetch/i }));
    await waitFor(() => expect(app.platform.fetchUrl).toHaveBeenCalledWith(url));
    const chooser = await screen.findByRole('dialog', { name: NAMES.chooser });
    await userEvent.click(within(chooser).getByRole('button', { name: /set-key-a/ }));
    await waitFor(() => expect(keyOf(app, 'issuer')?.provenance).toEqual({ type: 'url', url }));
  });
});

describe('Clear', () => {
  it('removes that area key only', async () => {
    const app = shell(fx.issuerCard, fx.holderCard);
    await waitFor(() => expect(textOf(keyBox('issuer'))).not.toBe(''));
    await userEvent.click(keyButton('issuer', NAMES.clear));
    await waitFor(() => expect(keyOf(app, 'issuer')).toBeNull());
    expect(textOf(keyBox('issuer'))).toBe('');
    expect(keyArea('issuer')).not.toHaveTextContent(fx.issuerInfo.jwk_thumbprint);
    expectUnavailable('issuer', NAMES.export);
    expectUnavailable('issuer', NAMES.makePublic);
    expect(keyOf(app, 'holder')?.info.jwk_thumbprint).toBe(fx.holderInfo.jwk_thumbprint);
  });

  it('actions that need the cleared key disable', async () => {
    const app = setupApp();
    seedKeys(app, fx.issuerCard, fx.holderCard);
    seedTab(app.workspace, fx.jsonClaims);
    renderWithApp(AppShell, {}, app);
    const issue = within(screen.getByRole('toolbar', { name: 'Actions' })).getByRole('button', {
      name: 'Issue',
    });
    expect(issue).toHaveAttribute('aria-disabled', 'false');
    await userEvent.click(keyButton('issuer', NAMES.clear));
    await waitFor(() => expect(issue).toHaveAttribute('aria-disabled', 'true'));
    expect(issue.getAttribute('title')).toMatch(/issuer key/i);
  });

  it('after Clear, the next paste autodetects again', async () => {
    const app = shell(fx.issuerCard);
    await userEvent.click(keyButton('issuer', NAMES.clear));
    await waitFor(() => expect(textOf(keyBox('issuer'))).toBe(''));
    await pasteInto(keyBox('issuer'), fx.HOLDER_JWK);
    await waitFor(() => expect(app.engine.detectKey).toHaveBeenCalledWith(utf8(fx.HOLDER_JWK)));
  });
});

describe('drag and drop', () => {
  it('an empty area accepts a drop and runs key detection', async () => {
    const app = shell();
    const outcome = await dropOnto(keyBox('holder'), { text: fx.HOLDER_JWK });
    expect(outcome.accepted).toBe(true);
    await waitFor(() => expect(app.engine.detectKey).toHaveBeenCalledWith(utf8(fx.HOLDER_JWK)));
    await waitFor(() => expect(keyOf(app, 'holder')).not.toBeNull());
    expect(keyOf(app, 'issuer')).toBeNull();
  });

  it('a dropped file is detected from its bytes', async () => {
    const app = shell();
    const file = new File([fx.ISSUER_JWK], 'issuer.jwk', { type: 'application/json' });
    const outcome = await dropOnto(keyBox('issuer'), { file });
    expect(outcome.accepted).toBe(true);
    await waitFor(() => expect(app.engine.detectKey).toHaveBeenCalledWith(utf8(fx.ISSUER_JWK)));
    await waitFor(() => expect(keyOf(app, 'issuer')).not.toBeNull());
    expect(keyOf(app, 'issuer')?.provenance).toEqual({ type: 'dropped', name: 'issuer.jwk' });
  });

  it('a non-empty area refuses the drop (dropEffect none) and ignores it', async () => {
    const app = shell(fx.issuerCard);
    await waitFor(() => expect(textOf(keyBox('issuer'))).toMatch(/"kty":\s*"EC"/));
    const before = textOf(keyBox('issuer'));
    const outcome = await dropOnto(keyBox('issuer'), { text: fx.HOLDER_JWK });
    expect(outcome.accepted).toBe(false);
    expect(outcome.dropEffect).toBe('none');
    await new Promise((r) => setTimeout(r, 300));
    expect(app.engine.detectKey).not.toHaveBeenCalled();
    expect(app.engine.keyImport).not.toHaveBeenCalled();
    expect(textOf(keyBox('issuer'))).toBe(before);
    expect(keyOf(app, 'issuer')?.info.jwk_thumbprint).toBe(fx.issuerInfo.jwk_thumbprint);
  });
});
