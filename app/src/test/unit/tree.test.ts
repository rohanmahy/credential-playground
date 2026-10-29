import { describe, expect, it } from 'vitest';
import { ancestorIds, findNode } from '../../lib/logic/tree';
import { cwt, jwt } from '../fixtures';

describe('tree helpers', () => {
  it('finds nodes, including key nodes', () => {
    expect(findNode(jwt.tree, 'payload/~e/exp')?.label).toBe('exp');
    expect(findNode(cwt.tree, 'payload/~e/4/~k')?.kind).toBe('integer');
    expect(findNode(cwt.tree, '')?.id).toBe('');
    expect(findNode(cwt.tree, 'payload/~e/99')).toBeNull();
  });

  it('lists ancestors root first', () => {
    expect(ancestorIds('payload/~e/cnf/jwk')).toEqual([
      '',
      'payload',
      'payload/~e',
      'payload/~e/cnf',
    ]);
    expect(ancestorIds('')).toEqual([]);
    // escaped segments are not split
    expect(ancestorIds('payload/~e/http:~1~1x')).toEqual(['', 'payload', 'payload/~e']);
  });
});
