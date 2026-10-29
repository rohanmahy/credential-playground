// The About box with the security notes (SPEC §9).
import { screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import AboutBox from '../../lib/components/AboutBox.svelte';
import AppShell from '../../lib/components/AppShell.svelte';
import { renderWithApp } from '../render';

describe('About', () => {
  it('shows the security and privacy notes', () => {
    renderWithApp(AboutBox, {});
    const about = screen.getByRole('dialog', { name: 'About' });
    expect(about).toHaveTextContent(/memory, unprotected/);
    expect(about).toHaveTextContent('RUSTSEC-2023-0071');
    expect(about).toHaveTextContent(/reveals your IP address/);
    expect(about).toHaveTextContent(/strict CSP/);
  });

  it('opens from the toolbar and shows the targeted SD-CWT revision and registry dates', async () => {
    const { app } = renderWithApp(AppShell, {});
    await userEvent.click(screen.getByRole('button', { name: 'About' }));
    const about = screen.getByRole('dialog', { name: 'About' });
    await waitFor(() => expect(about).toHaveTextContent('draft-ietf-spice-sd-cwt-08'));
    expect(about).toHaveTextContent('2026-09-01');
    expect(app.engine.info).toHaveBeenCalled();
  });
});
