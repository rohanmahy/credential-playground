// Hover text for annotated names (SPEC §4.1): registry name, description,
// value name, and the specs' display text (never URLs or draft revisions).
import type { Annotation, TimeHint } from '../engine/types';
import { notImplemented } from '../notImplemented';

export function hoverText(_annotation: Annotation): string {
  notImplemented('hoverText');
}

/** Inline date for a time claim: `2030-01-01T00:00:00Z (in 3 h 12 m)`. */
export function timeHintText(_hint: TimeHint): string {
  notImplemented('timeHintText');
}
