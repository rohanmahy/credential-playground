// Date/time forms and engine info.
import type { DateTimeForms, EngineInfo } from '../../lib/engine/types';

export const info: EngineInfo = {
  version: '0.1.0',
  sd_cwt_revision: 'draft-ietf-spice-sd-cwt-08',
  registry_updated: {
    cwt: '2026-09-01',
    cose: '2026-08-15',
    jwt: '2026-07-30',
    jose: '2026-06-12',
  },
};

/** 2030-01-01T00:00:00Z, now = 1_800_000_000, local offset +60. */
export const forms2030: DateTimeForms = {
  epoch: '1893456000',
  millis: 1893456000000,
  rfc3339_utc: '2030-01-01T00:00:00Z',
  rfc3339_local: '2030-01-01T01:00:00+01:00',
  local_offset_minutes: 60,
  relative: 'in 1081 d 16 h',
  forms: [
    { form: 'epoch', edn: '1893456000', cbor_hex: '1a70dbd880' },
    { form: 'tag1', edn: '1(1893456000)', cbor_hex: 'c11a70dbd880' },
    {
      form: 'rfc3339',
      edn: '"2030-01-01T00:00:00Z"',
      cbor_hex: '74323033302d30312d30315430303a30303a30305a',
    },
    {
      form: 'tag0',
      edn: '0("2030-01-01T00:00:00Z")',
      cbor_hex: 'c074323033302d30312d30315430303a30303a30305a',
    },
    { form: 'tag100', edn: '100(21915)', cbor_hex: 'd86419559b' },
    { form: 'tag1004', edn: '1004("2030-01-01")', cbor_hex: 'd903ec6a323033302d30312d3031' },
    { form: 'dt', edn: "dt'2030-01-01T00:00:00Z'", cbor_hex: '1a70dbd880' },
    { form: 'dt_tagged', edn: "DT'2030-01-01T00:00:00Z'", cbor_hex: 'c11a70dbd880' },
  ],
};

/** 2031-01-01T00:00:00Z. */
export const forms2031: DateTimeForms = {
  epoch: '1924992000',
  millis: 1924992000000,
  rfc3339_utc: '2031-01-01T00:00:00Z',
  rfc3339_local: '2031-01-01T01:00:00+01:00',
  local_offset_minutes: 60,
  relative: 'in 1446 d 16 h',
  forms: forms2030.forms.map((f) => ({
    ...f,
    edn: f.edn
      .replace('2030', '2031')
      .replace('1893456000', '1924992000')
      .replace('21915', '22280'),
  })),
};
