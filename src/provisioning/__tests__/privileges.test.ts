import { describe, it, expect, vi } from 'vitest';
import { createCentiaAdminClient } from '../../admin';

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

describe('Privileges', () => {
  it('getPrivileges sends GET to correct path', async () => {
    const privs = [{ subuser: 'alice', privilege: 'read' }];
    const fetchFn = mockFetch(200, privs);
    const client = createClient(fetchFn);

    const result = await client.provisioning.privileges.getPrivileges('public', 'cities');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/public/tables/cities/privileges');
    expect(init.method).toBe('GET');
    expect(result).toEqual(privs);
  });

  it('patchPrivileges sends PATCH with body', async () => {
    const updated = [{ subuser: 'bob', privilege: 'write' }];
    const fetchFn = mockFetch(200, updated);
    const client = createClient(fetchFn);

    const result = await client.provisioning.privileges.patchPrivileges('myschema', 'mytable', {
      subuser: 'bob',
      privilege: 'write',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/myschema/tables/mytable/privileges');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      subuser: 'bob',
      privilege: 'write',
    });
    expect(result).toEqual(updated);
  });

  it('patchPrivileges sends PATCH with array body', async () => {
    const updated = [
      { subuser: 'bob', privilege: 'write' },
      { subuser: 'alice', privilege: 'read' },
    ];
    const fetchFn = mockFetch(200, updated);
    const client = createClient(fetchFn);

    const body = [
      { subuser: 'bob', privilege: 'write' as const },
      { subuser: 'alice', privilege: 'read' as const },
    ];
    const result = await client.provisioning.privileges.patchPrivileges('myschema', 'mytable', body);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/myschema/tables/mytable/privileges');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual(body);
    expect(result).toEqual(updated);
  });
});
