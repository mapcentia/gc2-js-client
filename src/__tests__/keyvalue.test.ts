import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Keyvalue } from '../keyvalue/Keyvalue';

function mockFetch(status: number, body: unknown, headers?: Record<string, string>): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => (body !== null && body !== undefined ? JSON.stringify(body) : ''),
    headers: {
      get: (name: string) => headers?.[name.toLowerCase()] ?? null,
    },
  } as unknown as Response);
}

function createHttp(fetchFn: typeof globalThis.fetch) {
  return createCentiaClient({
    baseUrl: 'https://api.example.com',
    fetch: fetchFn,
    auth: { getAccessToken: async () => 'test-token' },
  });
}

function lastCall(fetchFn: typeof globalThis.fetch) {
  const calls = (fetchFn as ReturnType<typeof vi.fn>).mock.calls;
  return calls[calls.length - 1] as [string, RequestInit];
}

describe('Keyvalue', () => {
  it('getKeyvalue sends GET for all keys', async () => {
    const entries = [{ id: 1, key: 'a', value: { x: 1 }, owner: 'alice', public: false }];
    const fetchFn = mockFetch(200, entries);
    const kv = new Keyvalue(createHttp(fetchFn));

    const result = await kv.getKeyvalue();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toEqual(entries);
  });

  it('getKeyvalue sends GET for a specific key', async () => {
    const entry = { id: 2, key: 'my key', value: { a: 1 }, owner: null, public: true };
    const fetchFn = mockFetch(200, entry);
    const kv = new Keyvalue(createHttp(fetchFn));

    const result = await kv.getKeyvalue('my key');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/my%20key');
    expect(init.method).toBe('GET');
    expect(result).toEqual(entry);
  });

  it('getKeyvalue sends paths query for projection', async () => {
    const projection = { value: { 'user.name': 'Alice', active: true } };
    const fetchFn = mockFetch(200, projection);
    const kv = new Keyvalue(createHttp(fetchFn));

    const result = await kv.getKeyvalue('mykey', ['user.name', 'active']);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/mykey?paths=user.name%2Cactive');
    expect(init.method).toBe('GET');
    expect(result).toEqual(projection);
  });

  it('getKeyvalue accepts paths as a single string', async () => {
    const fetchFn = mockFetch(200, { value: { active: true } });
    const kv = new Keyvalue(createHttp(fetchFn));

    await kv.getKeyvalue('mykey', 'active');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/mykey?paths=active');
  });

  it('postKeyvalue sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/keyvalue/mykey' });
    const kv = new Keyvalue(createHttp(fetchFn));

    const result = await kv.postKeyvalue('mykey', { value: { a: 1 }, public: true });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/mykey');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ value: { a: 1 }, public: true });
    expect(result.location).toBe('/api/v4/keyvalue/mykey');
  });

  it('patchKeyvalue sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/keyvalue/mykey' });
    const kv = new Keyvalue(createHttp(fetchFn));

    const result = await kv.patchKeyvalue('mykey', { public: true });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/mykey');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({ public: true });
    expect(result.location).toBe('/api/v4/keyvalue/mykey');
  });

  it('deleteKeyvalue sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const kv = new Keyvalue(createHttp(fetchFn));

    await kv.deleteKeyvalue('mykey');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/keyvalue/mykey');
    expect(init.method).toBe('DELETE');
  });
});
