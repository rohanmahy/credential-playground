import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/svelte';
import { afterEach } from 'vitest';

afterEach(() => cleanup());

// jsdom lacks layout; CodeMirror measures ranges.
if (typeof Range !== 'undefined') {
  const empty = () => ({ length: 0, item: () => null, [Symbol.iterator]: [][Symbol.iterator] });
  Range.prototype.getClientRects ??= empty as unknown as () => DOMRectList;
  Range.prototype.getBoundingClientRect ??= () => new DOMRect();
}
