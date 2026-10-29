// Provenance labels and breadcrumbs (SPEC §4).
import type { Provenance } from '../model';
import { ACTION_LABELS } from './actions';
import { notImplemented } from '../notImplemented';

/** `Pasted`, `Clipboard`, `File: token.txt`, `URL: https://…`, `Generated`, `New`,
 *  `Derived from Tab 2 via Present`. `title` resolves a tab or key id. */
export function provenanceLabel(p: Provenance, title: (id: string) => string): string {
  switch (p.type) {
    case 'pasted':
      return 'Pasted';
    case 'dropped':
      return p.name ? `Dropped: ${p.name}` : 'Dropped';
    case 'clipboard':
      return 'Clipboard';
    case 'file':
      return `File: ${p.name}`;
    case 'url':
      return `URL: ${p.url}`;
    case 'generated':
      return 'Generated';
    case 'new':
      return notImplemented("provenanceLabel 'new'");
    case 'derived':
      return `Derived from ${title(p.parent)} via ${ACTION_LABELS[p.action]}`;
    case 'derived_key':
      return p.how === 'public'
        ? `Public key derived from ${title(p.parent)}`
        : `Derived from ${title(p.parent)} (kid)`;
  }
}
