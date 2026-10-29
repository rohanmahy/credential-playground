// Date/time chit (SPEC §4.3).
import { screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import DateTimeChit from '../../lib/components/DateTimeChit.svelte';
import * as fx from '../fixtures';
import { renderWithApp, seedTab, setupApp } from '../render';

const field = (name: string) =>
  within(screen.getByRole('dialog', { name: 'Date/time' })).getByRole('textbox', { name });

describe('DateTimeChit', () => {
  it('pre-fills from a time-valued node and shows every form', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    renderWithApp(DateTimeChit, { tabId: tab.id, nodeId: 'payload/~e/exp' }, app);
    await waitFor(() =>
      expect(app.engine.datetime).toHaveBeenCalledWith({
        input: { type: 'epoch', text: '1893456000' },
        now: fx.NOW,
        local_offset_minutes: 60,
      }),
    );
    await waitFor(() => expect(field('Epoch seconds')).toHaveValue('1893456000'));
    expect(field('Milliseconds')).toHaveValue('1893456000000');
    expect(field('RFC 3339 (UTC)')).toHaveValue('2030-01-01T00:00:00Z');
    expect(field('RFC 3339 (local)')).toHaveValue('2030-01-01T01:00:00+01:00');
    expect(screen.getByTestId('relative')).toHaveTextContent('in 1081 d 16 h');
    const dialog = screen.getByRole('dialog', { name: 'Date/time' });
    expect(dialog).toHaveTextContent('1(1893456000)');
    expect(dialog).toHaveTextContent('c11a70dbd880');
    expect(dialog).toHaveTextContent("dt'2030-01-01T00:00:00Z'");
    expect(dialog).toHaveTextContent('100(21915)');
  });

  it('keeps every field in sync when one is edited', async () => {
    const app = setupApp();
    renderWithApp(DateTimeChit, {}, app);
    await waitFor(() => expect(app.engine.datetime).toHaveBeenCalled());
    app.engine.datetime.mockResolvedValue(fx.forms2031);
    const rfc = field('RFC 3339 (UTC)');
    await userEvent.clear(rfc);
    await userEvent.type(rfc, '2031-01-01T00:00:00Z{Enter}');
    await waitFor(() =>
      expect(app.engine.datetime).toHaveBeenLastCalledWith(
        expect.objectContaining({ input: { type: 'rfc3339', text: '2031-01-01T00:00:00Z' } }),
      ),
    );
    await waitFor(() => expect(field('Epoch seconds')).toHaveValue('1924992000'));
    const ms = field('Milliseconds');
    await userEvent.clear(ms);
    await userEvent.type(ms, '1924992000000{Enter}');
    await waitFor(() =>
      expect(app.engine.datetime).toHaveBeenLastCalledWith(
        expect.objectContaining({ input: { type: 'millis', millis: 1924992000000 } }),
      ),
    );
  });

  it('opened without a node starts at the clock and cannot insert', async () => {
    const app = setupApp();
    app.settings.clockOverride = 1893456000;
    renderWithApp(DateTimeChit, {}, app);
    await waitFor(() =>
      expect(app.engine.datetime).toHaveBeenCalledWith(
        expect.objectContaining({ input: { type: 'epoch', text: '1893456000' } }),
      ),
    );
    expect(screen.getByRole('button', { name: 'Insert' })).toBeDisabled();
  });

  it('Insert writes the chosen form into the node in live edit', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.cwt, { liveEdit: true });
    renderWithApp(DateTimeChit, { tabId: tab.id, nodeId: 'payload/~e/4' }, app);
    await waitFor(() => expect(field('Epoch seconds')).toHaveValue('1893456000'));
    await userEvent.click(screen.getByRole('radio', { name: /1\(1893456000\)/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Insert' }));
    await waitFor(() => expect(app.engine.parseEdit).toHaveBeenCalled());
    expect(app.engine.parseEdit.mock.calls[0]?.[0].text).toBe(
      fx.CWT_EDN.replace('1444064944', '1(1893456000)'),
    );
  });

  it('"Use as clock" sets the validation clock override', async () => {
    const app = setupApp();
    const tab = seedTab(app.workspace, fx.jwt);
    renderWithApp(DateTimeChit, { tabId: tab.id, nodeId: 'payload/~e/exp' }, app);
    await waitFor(() => expect(field('Epoch seconds')).toHaveValue('1893456000'));
    await userEvent.click(screen.getByRole('button', { name: 'Use as clock' }));
    expect(app.settings.clockOverride).toBe(1893456000);
  });
});
