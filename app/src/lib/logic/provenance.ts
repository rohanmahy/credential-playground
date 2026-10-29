// Provenance labels and breadcrumbs (SPEC §4).
import type { Provenance } from '../model';
import { notImplemented } from '../notImplemented';

/** `Pasted`, `Clipboard`, `File: token.txt`, `URL: https://…`, `Generated`,
 *  `Derived from Tab 2 via Present`. `title` resolves a tab or key id. */
export function provenanceLabel(_p: Provenance, _title: (id: string) => string): string {
  notImplemented('provenanceLabel');
}
