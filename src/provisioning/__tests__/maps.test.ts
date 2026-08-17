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

describe('Maps', () => {
  it('getMap sends GET to the schema map endpoint', async () => {
    const config = { center: [1386651.0, 7503372.0], zoom: 12, extent: null };
    const fetchFn = mockFetch(200, config);
    const client = createClient(fetchFn);

    const result = await client.provisioning.maps.getMap('my_schema');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/map/schema/my_schema');
    expect(init.method).toBe('GET');
    expect(result).toEqual(config);
  });

  it('patchMap sends PATCH 303 with partial body and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/map/schema/my_schema' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.maps.patchMap('my_schema', {
      center: [1386651.0, 7503372.0],
      zoom: 12,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/map/schema/my_schema');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      center: [1386651.0, 7503372.0],
      zoom: 12,
    });
    expect(result.location).toBe('/api/v4/map/schema/my_schema');
  });

  it('patchMap allows clearing values with null', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/map/schema/my_schema' });
    const client = createClient(fetchFn);

    await client.provisioning.maps.patchMap('my_schema', { extent: null });

    const [, init] = lastCall(fetchFn);
    expect(JSON.parse(init.body as string)).toEqual({ extent: null });
  });
});
