import { describe, expect, it } from 'vitest';
import { hoverText, timeHintText } from '../../lib/logic/hover';
import { ANNOTATIONS } from '../fixtures';

describe('hoverText', () => {
  it("uses the registry's name, description, and spec display text", () => {
    const t = hoverText(ANNOTATIONS.iss);
    expect(t).toContain('iss');
    expect(t).toContain('Issuer');
    expect(t).toContain('RFC 7519, Section 4.1.1');
  });

  it('never shows URLs (they carry draft revisions)', () => {
    const t = hoverText({
      name: 'redacted_claim_keys',
      description: 'Redacted claim keys in a map',
      value_name: null,
      spec: [
        {
          text: 'draft-ietf-spice-sd-cwt, Section 4',
          url: 'https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt-08#section-4',
        },
      ],
    });
    expect(t).toContain('draft-ietf-spice-sd-cwt, Section 4');
    expect(t).not.toContain('-08');
    expect(t).not.toContain('https://');
  });

  it('includes a registered value name', () => {
    expect(hoverText(ANNOTATIONS.coseAlg)).toContain('ES256');
  });
});

describe('timeHintText', () => {
  it('shows the UTC date and the relative time', () => {
    const t = timeHintText({
      epoch: 1893456000,
      rfc3339: '2030-01-01T00:00:00Z',
      relative: 'in 1081 d 16 h',
    });
    expect(t).toContain('2030-01-01T00:00:00Z');
    expect(t).toContain('in 1081 d 16 h');
    expect(timeHintText({ epoch: 0, rfc3339: '1970-01-01T00:00:00Z', relative: null })).toBe(
      '1970-01-01T00:00:00Z',
    );
  });
});
