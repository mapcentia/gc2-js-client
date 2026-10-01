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

const settings = {
  schema: 'dagi', schema_exists: true, cache: 'sqlite', format: 'PNG', vector_format: 'MVT',
  ttl: 86400, auto_expire: null, meta_size: 3, meta_buffer: 0, s3_tile_set: null,
  title: 'dagi', abstract: '', _stored: { ttl: 86400 },
  _defaults: {
    cache: 'sqlite', format: 'PNG', ttl: 60, auto_expire: null, meta_size: 3, meta_buffer: 0,
    s3_tile_set: null, title: 'dagi', abstract: '',
  },
};

describe('SchemaTileSettings', () => {
  it('getSchemaTileSettings returns the effective settings and what is stored', async () => {
    const fetchFn = mockFetch(200, settings);
    const client = createClient(fetchFn);

    const result = await client.provisioning.schemaTileSettings.getSchemaTileSettings('dagi');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/dagi/tile');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result.ttl).toBe(86400);
    expect(result._stored.ttl).toBe(86400);
    expect(result._stored.meta_size).toBeUndefined();
    expect(result.vector_format).toBe('MVT');
    expect(result._defaults.ttl).toBe(60);
    expect(result._defaults.auto_expire).toBeNull();
  });

  it('patchSchemaTileSettings sends only the given fields and returns the location (303)', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/schemas/dagi/tile' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.schemaTileSettings.patchSchemaTileSettings('dagi', {
      cache: 'disk', meta_size: 5, title: null,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/dagi/tile');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({ cache: 'disk', meta_size: 5, title: null });
    expect(result.location).toBe('/api/v4/schemas/dagi/tile');
  });

  it('patchSchemaTileSettings throws on a missing schema (404)', async () => {
    const fetchFn = mockFetch(404, { message: 'Schema not found', code: 'SCHEMA_NOT_FOUND' });
    const client = createClient(fetchFn);

    await expect(client.provisioning.schemaTileSettings.patchSchemaTileSettings('dagj', { ttl: 60 }))
      .rejects.toMatchObject({ status: 404, code: 'SCHEMA_NOT_FOUND' });
  });

  it('deleteSchemaTileSettings sends DELETE and expects 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.schemaTileSettings.deleteSchemaTileSettings('dagi');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/dagi/tile');
    expect(init.method).toBe('DELETE');
  });
});
