import { describe, it, expect, vi } from 'vitest';
import { createCentiaAdminClient } from '../../admin';
import { CentiaApiError } from '../../http/errors';

function mockFetch(status: number, body: unknown, headers?: Record<string, string>): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => (body !== null && body !== undefined ? JSON.stringify(body) : ''),
    headers: {
      get: (name: string) => headers?.[name.toLowerCase()] ?? null,
    },
  } as unknown as Response);
}

function createClient(fetchFn: typeof globalThis.fetch) {
  return createCentiaAdminClient({
    baseUrl: 'https://api.example.com',
    fetch: fetchFn,
    auth: { getAccessToken: async () => 'test-token' },
  });
}

function lastCall(fetchFn: typeof globalThis.fetch) {
  const calls = (fetchFn as ReturnType<typeof vi.fn>).mock.calls;
  return calls[calls.length - 1] as [string, RequestInit];
}

describe('Schemas', () => {
  it('getSchema sends GET to correct path', async () => {
    const fetchFn = mockFetch(200, { name: 'public', tables: [] });
    const client = createClient(fetchFn);

    const result = await client.provisioning.schemas.getSchema('public');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public');
    expect(init.method).toBe('GET');
    expect(result.name).toBe('public');
  });

  it('getSchema with namesOnly sends query param', async () => {
    const fetchFn = mockFetch(200, { name: 'public' });
    const client = createClient(fetchFn);

    await client.provisioning.schemas.getSchema('public', { namesOnly: true });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public?namesOnly=true');
  });

  it('getSchema without schema name lists all schemas', async () => {
    const fetchFn = mockFetch(200, [{ name: 'public' }, { name: 'test' }]);
    const client = createClient(fetchFn);

    await client.provisioning.schemas.getSchema();

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas');
  });

  it('postSchema sends POST and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/schemas/myschema' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.schemas.postSchema({ name: 'myschema' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ name: 'myschema' });
    expect(result.location).toBe('/api/v4/schemas/myschema');
  });

  it('patchSchema sends PATCH and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/newname' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.schemas.patchSchema('oldname', { name: 'newname' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/oldname');
    expect(init.method).toBe('PATCH');
    expect(result.location).toBe('/api/v4/schemas/newname');
  });

  it('deleteSchema sends DELETE with expectedStatus 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.schemas.deleteSchema('test');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/test');
    expect(init.method).toBe('DELETE');
  });

  it('postSchema throws CentiaApiError on failure', async () => {
    const fetchFn = mockFetch(409, { message: 'Schema already exists' });
    const client = createClient(fetchFn);

    await expect(
      client.provisioning.schemas.postSchema({ name: 'existing' }),
    ).rejects.toThrow(CentiaApiError);
  });
});

describe('Columns', () => {
  it('getColumn sends GET with single column path', async () => {
    const fetchFn = mockFetch(200, { name: 'id', type: 'integer' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.columns.getColumn('public', 'users', 'id');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/columns/id');
    expect(result).toEqual({ name: 'id', type: 'integer' });
  });

  it('getColumn without column name lists all columns', async () => {
    const fetchFn = mockFetch(200, [{ name: 'id' }, { name: 'name' }]);
    const client = createClient(fetchFn);

    await client.provisioning.columns.getColumn('public', 'users');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/columns');
  });

  it('postColumn sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/schemas/public/tables/users/columns/email' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.columns.postColumn('public', 'users', {
      name: 'email',
      type: 'varchar',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/columns');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ name: 'email', type: 'varchar' });
    expect(result.location).toContain('columns/email');
  });

  it('patchColumn sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/public/tables/users/columns/username' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.columns.patchColumn('public', 'users', 'name', {
      name: 'username',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/columns/name');
    expect(init.method).toBe('PATCH');
    expect(result.location).toContain('columns/username');
  });

  it('deleteColumn sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.columns.deleteColumn('public', 'users', 'email');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/columns/email');
    expect(init.method).toBe('DELETE');
  });

  it('encodes path segments with special characters', async () => {
    const fetchFn = mockFetch(200, { name: 'col name' });
    const client = createClient(fetchFn);

    await client.provisioning.columns.getColumn('my schema', 'my table', 'col name');

    const [url] = lastCall(fetchFn);
    expect(url).toContain('my%20schema');
    expect(url).toContain('my%20table');
    expect(url).toContain('col%20name');
  });
});

describe('Constraints', () => {
  it('getConstraint sends GET for specific constraint', async () => {
    const fetchFn = mockFetch(200, { name: 'pk', constraint: 'primary', columns: ['id'] });
    const client = createClient(fetchFn);

    const result = await client.provisioning.constraints.getConstraint('public', 'users', 'pk');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/constraints/pk');
    expect(result).toEqual({ name: 'pk', constraint: 'primary', columns: ['id'] });
  });

  it('postConstraint sends POST 201 with body', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/.../constraints/users-pk' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.constraints.postConstraint('public', 'users', {
      constraint: 'primary',
      columns: ['id'],
      name: 'users-pk',
    });

    const [, init] = lastCall(fetchFn);
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      constraint: 'primary',
      columns: ['id'],
      name: 'users-pk',
    });
    expect(result.location).toContain('users-pk');
  });

  it('deleteConstraint sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.constraints.deleteConstraint('public', 'users', 'users-pk');

    const [url, init] = lastCall(fetchFn);
    expect(url).toContain('constraints/users-pk');
    expect(init.method).toBe('DELETE');
  });
});

describe('Indices', () => {
  it('getIndex sends GET for specific index', async () => {
    const fetchFn = mockFetch(200, { name: 'idx', method: 'btree', columns: ['name'] });
    const client = createClient(fetchFn);

    const result = await client.provisioning.indices.getIndex('public', 'users', 'idx');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/users/indices/idx');
    expect(result).toEqual({ name: 'idx', method: 'btree', columns: ['name'] });
  });

  it('postIndex sends POST 201 with body', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/.../indices/users-btree' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.indices.postIndex('public', 'users', {
      columns: ['name'],
      method: 'btree',
      name: 'users-btree',
    });

    const [, init] = lastCall(fetchFn);
    expect(init.method).toBe('POST');
    expect(result.location).toContain('users-btree');
  });

  it('deleteIndex sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.indices.deleteIndex('public', 'users', 'users-btree');

    const [url, init] = lastCall(fetchFn);
    expect(url).toContain('indices/users-btree');
    expect(init.method).toBe('DELETE');
  });
});

describe('Sequences', () => {
  it('getSequence sends GET for specific sequence', async () => {
    const fetchFn = mockFetch(200, { name: 'id_seq', data_type: 'bigint' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.sequences.getSequence('public', 'id_seq');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/sequences/id_seq');
    expect(result).toEqual({ name: 'id_seq', data_type: 'bigint' });
  });

  it('postSequence sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/schemas/public/sequences/counter_seq' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.sequences.postSequence('public', {
      name: 'counter_seq',
      increment_by: 1,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/sequences');
    expect(init.method).toBe('POST');
    expect(result.location).toContain('counter_seq');
  });

  it('patchSequence sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/public/sequences/new_seq' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.sequences.patchSequence('public', 'old_seq', {
      name: 'new_seq',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/sequences/old_seq');
    expect(init.method).toBe('PATCH');
    expect(result.location).toContain('new_seq');
  });

  it('deleteSequence sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.sequences.deleteSequence('public', 'id_seq');

    const [url, init] = lastCall(fetchFn);
    expect(url).toContain('sequences/id_seq');
    expect(init.method).toBe('DELETE');
  });
});

describe('CentiaAdminClient', () => {
  it('creates client with all provisioning modules', () => {
    const client = createCentiaAdminClient({
      baseUrl: 'https://api.example.com',
      fetch: mockFetch(200, {}),
    });

    expect(client.provisioning).toBeDefined();
    expect(client.provisioning.schemas).toBeDefined();
    expect(client.provisioning.columns).toBeDefined();
    expect(client.provisioning.constraints).toBeDefined();
    expect(client.provisioning.indices).toBeDefined();
    expect(client.provisioning.sequences).toBeDefined();
    expect(client.http).toBeDefined();
  });

  it('passes auth through to HTTP client', async () => {
    const fetchFn = mockFetch(200, { name: 'test' });
    const client = createCentiaAdminClient({
      baseUrl: 'https://api.example.com',
      fetch: fetchFn,
      auth: { getAccessToken: async () => 'admin-token' },
    });

    await client.provisioning.schemas.getSchema('test');

    const [, init] = lastCall(fetchFn);
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer admin-token');
  });
});
