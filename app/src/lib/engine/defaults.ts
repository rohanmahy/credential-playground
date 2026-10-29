// Defaults for DTO fields that are `#[serde(default)]` in Rust but required
// (`T | null`) in the generated TypeScript.
import type { HeaderOptions, SdOptions, ViewOptions } from './types';

export function defaultViewOptions(): ViewOptions {
  return {
    layout: 'indented',
    indent: 2,
    decoded_views: true,
    hide_decoded: [],
    manual_decode: [],
    annotations: true,
    byte_style: 'hex',
    dt_literals: false,
    json_layout: 'original',
    now: null,
    local_offset_minutes: 0,
  };
}

export function defaultHeaderOptions(): HeaderOptions {
  return {
    typ: { type: 'auto' },
    kid: { type: 'from_key' },
    x5c: [],
    extra: null,
    unprotected_extra: null,
  };
}

export function defaultSdOptions(): SdOptions {
  return {
    marks: [],
    decoys: [],
    sd_alg: null,
    fixed_salts: [],
    digest_order: 'sorted',
    force_sd: false,
  };
}
