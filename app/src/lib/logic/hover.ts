// Hover text for annotated names (SPEC §4.1): registry name, description,
// value name, and the specs' display text (never URLs or draft revisions).
import type { Annotation, TimeHint } from '../engine/types';

export function hoverText(annotation: Annotation): string {
  const lines = [`${annotation.name}: ${annotation.description}`];
  if (annotation.value_name) lines.push(`Value: ${annotation.value_name}`);
  const specs = annotation.spec.map((s) => s.text).filter(Boolean);
  if (specs.length > 0) lines.push(specs.join('; '));
  return lines.join('\n');
}

/** Inline date for a time claim: `2030-01-01T00:00:00Z (in 3 h 12 m)`. */
export function timeHintText(hint: TimeHint): string {
  return hint.relative ? `${hint.rfc3339} (${hint.relative})` : hint.rfc3339;
}
