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

describe('ProvisioningUsers', () => {
  it('getUser sends GET to correct path for specific user', async () => {
    const fetchFn = mockFetch(200, { name: 'alice', email: 'alice@example.com', default_user: false });
    const client = createClient(fetchFn);

    const result = await client.provisioning.users.getUser('alice');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/users/alice');
    expect(init.method).toBe('GET');
    expect(result).toEqual({ name: 'alice', email: 'alice@example.com', default_user: false });
  });

  it('getUser without name lists all users', async () => {
    const fetchFn = mockFetch(200, [{ name: 'alice' }, { name: 'bob' }]);
    const client = createClient(fetchFn);

    await client.provisioning.users.getUser();

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/users');
  });

  it('postUser sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/users/alice' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.users.postUser({
      name: 'alice',
      email: 'alice@example.com',
      password: 'Secret123',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/users');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'alice',
      email: 'alice@example.com',
      password: 'Secret123',
    });
    expect(result.location).toBe('/api/v4/users/alice');
  });

  it('postUser sends optional fields', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/users/bob' });
    const client = createClient(fetchFn);

    await client.provisioning.users.postUser({
      name: 'bob',
      email: 'bob@example.com',
      password: 'Secret123',
      default_user: true,
      properties: { role: 'admin' },
    });

    const [, init] = lastCall(fetchFn);
    const body = JSON.parse(init.body as string);
    expect(body.default_user).toBe(true);
    expect(body.properties).toEqual({ role: 'admin' });
  });

  it('patchUser sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/users/alice' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.users.patchUser('alice', {
      email: 'newalice@example.com',
      password: 'NewSecret123',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/users/alice');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      email: 'newalice@example.com',
      password: 'NewSecret123',
    });
    expect(result.location).toBe('/api/v4/users/alice');
  });

  it('patchUser with null password sends null', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/users/alice' });
    const client = createClient(fetchFn);

    await client.provisioning.users.patchUser('alice', {
      email: 'alice@example.com',
      password: null,
      default_user: true,
    });

    const [, init] = lastCall(fetchFn);
    const body = JSON.parse(init.body as string);
    expect(body.password).toBeNull();
  });

  it('deleteUser sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.users.deleteUser('alice');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/users/alice');
    expect(init.method).toBe('DELETE');
  });

  it('encodes user name with special characters', async () => {
    const fetchFn = mockFetch(200, { name: 'user name' });
    const client = createClient(fetchFn);

    await client.provisioning.users.getUser('user name');

    const [url] = lastCall(fetchFn);
    expect(url).toContain('user%20name');
  });

  it('postUser throws CentiaApiError on failure', async () => {
    const fetchFn = mockFetch(409, { message: 'User already exists' });
    const client = createClient(fetchFn);

    await expect(
      client.provisioning.users.postUser({
        name: 'existing',
        email: 'test@example.com',
        password: 'Secret123',
      }),
    ).rejects.toThrow(CentiaApiError);
  });

  it('passes auth through to HTTP client', async () => {
    const fetchFn = mockFetch(200, { name: 'test' });
    const client = createClient(fetchFn);

    await client.provisioning.users.getUser('test');

    const [, init] = lastCall(fetchFn);
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
  });
});
