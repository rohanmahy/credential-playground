// Request DTO fields that are `#[serde(default)]` in Rust are optional in
// the generated TypeScript, so requests omit what they don't set. Only the
// view options are spelled out in full: Settings builds them from its
// toggles, starting from the core defaults below. Never send `null` for a
// non-`Option` field (serde rejects it); omit it instead.
import type { ViewOptions } from './types';

/** `ViewOptions::default()` in tokenator-core. */
export function defaultViewOptions(): Required<ViewOptions> {
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
