import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Features } from '../features/Features';

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

const point = { type: 'Point', coordinates: [10.0, 55.0] };

describe('Features', () => {
  it('getFeature sends GET for a single key', async () => {
    const feature = { type: 'Feature', geometry: point, properties: { gid: 1, name: 'a' } };
    const fetchFn = mockFetch(200, feature);
    const features = new Features(createHttp(fetchFn));

    const result = await features.getFeature('my_schema', 'my_table', 1);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features/1');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toEqual(feature);
  });

  it('getFeature joins multiple keys with commas', async () => {
    const collection = { type: 'FeatureCollection', features: [] };
    const fetchFn = mockFetch(200, collection);
    const features = new Features(createHttp(fetchFn));

    const result = await features.getFeature('my_schema', 'my_table', [1, 2, 3]);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features/1,2,3');
    expect(result).toEqual(collection);
  });

  it('getFeature sends srs query and URL-encodes string keys', async () => {
    const fetchFn = mockFetch(200, { type: 'Feature', geometry: point, properties: {} });
    const features = new Features(createHttp(fetchFn));

    await features.getFeature('my_schema', 'my_table', 'a key', { srs: 25832 });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features/a%20key?srs=25832');
  });

  it('postFeature sends POST 201 without key in path and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/schemas/my_schema/tables/my_table/features/7' });
    const features = new Features(createHttp(fetchFn));
    const body = { type: 'Feature' as const, geometry: point, properties: { name: 'new' } };

    const result = await features.postFeature('my_schema', 'my_table', body);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(body);
    expect(result.location).toBe('/api/v4/schemas/my_schema/tables/my_table/features/7');
  });

  it('postFeature sends srs query for incoming geometry', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/schemas/my_schema/tables/my_table/features/8' });
    const features = new Features(createHttp(fetchFn));

    await features.postFeature('my_schema', 'my_table', { type: 'FeatureCollection', features: [] }, { srs: 25832 });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features?srs=25832');
  });

  it('patchFeature sends PATCH 303 with key in path and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/my_schema/tables/my_table/features/1' });
    const features = new Features(createHttp(fetchFn));
    const body = { type: 'Feature' as const, geometry: point, properties: { name: 'upd' } };

    const result = await features.patchFeature('my_schema', 'my_table', body, { feature: 1 });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features/1');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual(body);
    expect(result.location).toBe('/api/v4/schemas/my_schema/tables/my_table/features/1');
  });

  it('patchFeature omits path key when features carry keys in properties', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/my_schema/tables/my_table/features/1,2' });
    const features = new Features(createHttp(fetchFn));
    const body = {
      type: 'FeatureCollection' as const,
      features: [
        { type: 'Feature' as const, geometry: point, properties: { gid: 1 } },
        { type: 'Feature' as const, geometry: point, properties: { gid: 2 } },
      ],
    };

    const result = await features.patchFeature('my_schema', 'my_table', body);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features');
    expect(init.method).toBe('PATCH');
    expect(result.location).toBe('/api/v4/schemas/my_schema/tables/my_table/features/1,2');
  });

  it('deleteFeature sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const features = new Features(createHttp(fetchFn));

    await features.deleteFeature('my_schema', 'my_table', 1);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/my_schema/tables/my_table/features/1');
    expect(init.method).toBe('DELETE');
  });
});
