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

describe('RpcMethods', () => {
  it('getRpc sends GET for all methods', async () => {
    const methods = [{ method: 'myMethod', q: 'SELECT 1' }];
    const fetchFn = mockFetch(200, methods);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rpcMethods.getRpc();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/methods');
    expect(init.method).toBe('GET');
    expect(result).toEqual(methods);
  });

  it('getRpc sends GET for specific method', async () => {
    const method = { method: 'myMethod', q: 'SELECT 1' };
    const fetchFn = mockFetch(200, method);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rpcMethods.getRpc('myMethod');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/methods/myMethod');
    expect(init.method).toBe('GET');
    expect(result).toEqual(method);
  });

  it('postRpc sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/methods/newMethod' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.rpcMethods.postRpc({
      method: 'newMethod',
      q: 'SELECT * FROM cities',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/methods');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      method: 'newMethod',
      q: 'SELECT * FROM cities',
    });
    expect(result.location).toBe('/api/v4/methods/newMethod');
  });

  it('patchRpc sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/methods/myMethod' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.rpcMethods.patchRpc('myMethod', {
      q: 'SELECT * FROM updated_table',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/methods/myMethod');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      q: 'SELECT * FROM updated_table',
    });
    expect(result.location).toBe('/api/v4/methods/myMethod');
  });

  it('deleteRpc sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.rpcMethods.deleteRpc('oldMethod');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/methods/oldMethod');
    expect(init.method).toBe('DELETE');
  });

  it('postCallDry sends POST to call/dry', async () => {
    const dryResult = { columns: ['id', 'name'] };
    const fetchFn = mockFetch(200, dryResult);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rpcMethods.postCallDry({
      jsonrpc: '2.0',
      method: 'myMethod',
      params: [{}],
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/call/dry');
    expect(init.method).toBe('POST');
    expect(result).toEqual(dryResult);
  });
});
