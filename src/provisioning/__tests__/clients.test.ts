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

describe('ProvisioningClients', () => {
  it('getClient sends GET for specific client', async () => {
    const fetchFn = mockFetch(200, { id: 'myapp', name: 'My App', public: false });
    const client = createClient(fetchFn);

    const result = await client.provisioning.clients.getClient('myapp');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/clients/myapp');
    expect(init.method).toBe('GET');
    expect(result).toEqual({ id: 'myapp', name: 'My App', public: false });
  });

  it('getClient without id lists all clients', async () => {
    const fetchFn = mockFetch(200, [{ id: 'a' }, { id: 'b' }]);
    const client = createClient(fetchFn);

    await client.provisioning.clients.getClient();

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/clients');
  });

  it('postClient sends POST 201 and returns location + secret', async () => {
    const fetchFn = mockFetch(
      201,
      { secret: 'generated-secret-123' },
      { location: '/api/v4/clients/myapp' },
    );
    const client = createClient(fetchFn);

    const result = await client.provisioning.clients.postClient({
      name: 'My App',
      id: 'myapp',
      public: false,
      confirm: true,
      two_factor: true,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/clients');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe('My App');
    expect(body.id).toBe('myapp');
    expect(body.confirm).toBe(true);
    expect(result.location).toBe('/api/v4/clients/myapp');
    expect(result.secret).toBe('generated-secret-123');
  });

  it('postClient sends optional fields', async () => {
    const fetchFn = mockFetch(
      201,
      { secret: 'sec' },
      { location: '/api/v4/clients/test' },
    );
    const client = createClient(fetchFn);

    await client.provisioning.clients.postClient({
      name: 'Test',
      redirect_uri: ['https://example.com/callback'],
      homepage: 'https://example.com',
      allow_signup: true,
      social_signup: false,
    });

    const [, init] = lastCall(fetchFn);
    const body = JSON.parse(init.body as string);
    expect(body.redirect_uri).toEqual(['https://example.com/callback']);
    expect(body.homepage).toBe('https://example.com');
    expect(body.allow_signup).toBe(true);
  });

  it('patchClient sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/clients/myapp' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.clients.patchClient('myapp', {
      name: 'Updated App',
      public: true,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/clients/myapp');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'Updated App',
      public: true,
    });
    expect(result.location).toBe('/api/v4/clients/myapp');
  });

  it('deleteClient sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.clients.deleteClient('myapp');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/clients/myapp');
    expect(init.method).toBe('DELETE');
  });

  it('encodes client id with special characters', async () => {
    const fetchFn = mockFetch(200, { id: 'my app' });
    const client = createClient(fetchFn);

    await client.provisioning.clients.getClient('my app');

    const [url] = lastCall(fetchFn);
    expect(url).toContain('my%20app');
  });

  it('postClient throws CentiaApiError on failure', async () => {
    const fetchFn = mockFetch(409, { message: 'Client already exists' });
    const client = createClient(fetchFn);

    await expect(
      client.provisioning.clients.postClient({ name: 'existing' }),
    ).rejects.toThrow(CentiaApiError);
  });

  it('passes auth through to HTTP client', async () => {
    const fetchFn = mockFetch(200, { id: 'test' });
    const client = createClient(fetchFn);

    await client.provisioning.clients.getClient('test');

    const [, init] = lastCall(fetchFn);
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
  });
});
