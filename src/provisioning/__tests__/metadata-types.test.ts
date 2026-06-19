import { describe, it, expect } from 'vitest';
import type { MetadataRelationInfo, MetadataFieldInfo } from '../types';

// Compile-time fixtures: the runtime app sends `null` to clear metadata
// fields, so the SDK types must allow `null` on the clearable fields.
// These assignments fail to type-check if the types are too strict.

describe('loosened metadata types', () => {
  it('MetadataRelationInfo accepts null on clearable fields', () => {
    const rel: MetadataRelationInfo = {
      title: null,
      abstract: null,
      group: null,
      sort_id: null,
      tags: null,
      properties: null,
    };
    expect(rel.title).toBeNull();
  });

  it('MetadataFieldInfo accepts null alias and sort_id', () => {
    const field: MetadataFieldInfo = {
      alias: null,
      queryable: false,
      sort_id: null,
    };
    expect(field.alias).toBeNull();
  });

  it('still accepts the existing non-null shape', () => {
    const rel: MetadataRelationInfo = {
      title: 'Cities',
      tags: ['a', 'b'],
      fields: { name: { alias: 'Name', queryable: true, sort_id: 1 } },
    };
    expect(rel.title).toBe('Cities');
  });
});
