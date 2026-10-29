import { describe, expect, it } from 'vitest';
import { Settings } from '../../lib/stores/settings.svelte';
import { MockPlatform } from '../MockPlatform';
import { NOW } from '../fixtures';

describe('Settings', () => {
  it('uses the platform clock unless overridden', () => {
    const s = new Settings(new MockPlatform());
    expect(s.now()).toBe(NOW);
    s.clockOverride = 1893456000;
    expect(s.now()).toBe(1893456000);
    s.clockOverride = null;
    expect(s.now()).toBe(NOW);
  });

  it('defaults to 60 s skew (SPEC §6)', () => {
    expect(new Settings(new MockPlatform()).skew).toBe(60);
  });

  it('builds view options from the toggles, the clock, and the local offset', () => {
    const p = new MockPlatform();
    const s = new Settings(p);
    s.decodedViews = false;
    s.annotations = false;
    s.jsonPretty = true;
    s.clockOverride = 1893456000;
    expect(s.viewOptions()).toMatchObject({
      decoded_views: false,
      annotations: false,
      json_layout: 'pretty',
      now: 1893456000,
      local_offset_minutes: 60,
    });
  });
});
