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

describe('Layers', () => {
  it('getLayer sends GET for all layers', async () => {
    const layers = [{ name: 'my_schema.my_table.the_geom' }];
    const fetchFn = mockFetch(200, layers);
    const client = createClient(fetchFn);

    const result = await client.provisioning.layers.getLayer();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers');
    expect(init.method).toBe('GET');
    expect(result).toEqual(layers);
  });

  it('getLayer sends GET for specific layer', async () => {
    const layer = { name: 'my_schema.my_table.the_geom', properties: { opacity: '80' } };
    const fetchFn = mockFetch(200, layer);
    const client = createClient(fetchFn);

    const result = await client.provisioning.layers.getLayer('my_schema.my_table.the_geom');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom');
    expect(init.method).toBe('GET');
    expect(result).toEqual(layer);
  });

  it('getLayer supports namesOnly', async () => {
    const fetchFn = mockFetch(200, ['my_schema.my_table.the_geom']);
    const client = createClient(fetchFn);

    const result = await client.provisioning.layers.getLayer(undefined, { namesOnly: true });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers?namesOnly=true');
    expect(result).toEqual(['my_schema.my_table.the_geom']);
  });

  it('postLayer sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/layers/my_schema.my_table.the_geom' });
    const client = createClient(fetchFn);

    const body = { name: 'my_schema.my_table.the_geom', classes: [{ name: 'My class' }] };
    const result = await client.provisioning.layers.postLayer(body);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(body);
    expect(result.location).toBe('/api/v4/layers/my_schema.my_table.the_geom');
  });

  it('patchLayer sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/layers/my_schema.my_table.the_geom' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.layers.patchLayer('my_schema.my_table.the_geom', {
      name: 'my_schema.my_table.the_geom',
      properties: { opacity: '50' },
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      name: 'my_schema.my_table.the_geom',
      properties: { opacity: '50' },
    });
    expect(result.location).toBe('/api/v4/layers/my_schema.my_table.the_geom');
  });

  it('getLayerClass sends GET for all classes', async () => {
    const fetchFn = mockFetch(200, [{ id: 'a1b2c3d4' }]);
    const client = createClient(fetchFn);

    await client.provisioning.layers.getLayerClass('my_schema.my_table.the_geom');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes');
    expect(init.method).toBe('GET');
  });

  it('getLayerClass sends GET for specific class', async () => {
    const fetchFn = mockFetch(200, { id: 'a1b2c3d4' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.getLayerClass('my_schema.my_table.the_geom', 'a1b2c3d4');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4');
  });

  it('postLayerClass sends POST 201', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/layers/x/classes/a1b2c3d4' });
    const client = createClient(fetchFn);

    const body = [{ name: 'Class A' }, { name: 'Class B' }];
    const result = await client.provisioning.layers.postLayerClass('my_schema.my_table.the_geom', body);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(body);
    expect(result.location).toBe('/api/v4/layers/x/classes/a1b2c3d4');
  });

  it('patchLayerClass sends PATCH 303', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/layers/x/classes/a1b2c3d4' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.patchLayerClass('my_schema.my_table.the_geom', 'a1b2c3d4', {
      expression: "[type]='road'",
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4');
    expect(init.method).toBe('PATCH');
  });

  it('deleteLayerClass sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.layers.deleteLayerClass('my_schema.my_table.the_geom', 'a1b2c3d4');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4');
    expect(init.method).toBe('DELETE');
  });

  it('getStyle sends GET for all styles of a class', async () => {
    const fetchFn = mockFetch(200, [{ id: 'e5f6a7b8' }]);
    const client = createClient(fetchFn);

    await client.provisioning.layers.getStyle('my_schema.my_table.the_geom', 'a1b2c3d4');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/styles');
    expect(init.method).toBe('GET');
  });

  it('postStyle sends POST 201', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/layers/x/classes/y/styles/e5f6a7b8' });
    const client = createClient(fetchFn);

    const result = await client.provisioning.layers.postStyle('my_schema.my_table.the_geom', 'a1b2c3d4', {
      color: '#008000',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/styles');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ color: '#008000' });
    expect(result.location).toBe('/api/v4/layers/x/classes/y/styles/e5f6a7b8');
  });

  it('patchStyle sends PATCH 303', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/layers/x/classes/y/styles/e5f6a7b8' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.patchStyle('my_schema.my_table.the_geom', 'a1b2c3d4', 'e5f6a7b8', {
      width: '2',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/styles/e5f6a7b8',
    );
    expect(init.method).toBe('PATCH');
  });

  it('deleteStyle sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.layers.deleteStyle('my_schema.my_table.the_geom', 'a1b2c3d4', 'e5f6a7b8');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/styles/e5f6a7b8',
    );
    expect(init.method).toBe('DELETE');
  });

  it('getLabel sends GET for specific label', async () => {
    const fetchFn = mockFetch(200, { id: 'c9d0e1f2' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.getLabel('my_schema.my_table.the_geom', 'a1b2c3d4', 'c9d0e1f2');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/labels/c9d0e1f2',
    );
    expect(init.method).toBe('GET');
  });

  it('postLabel sends POST 201', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/layers/x/classes/y/labels/c9d0e1f2' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.postLabel('my_schema.my_table.the_geom', 'a1b2c3d4', {
      text: '[name]',
      on: true,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/labels');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ text: '[name]', on: true });
  });

  it('patchLabel sends PATCH 303', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/layers/x/classes/y/labels/c9d0e1f2' });
    const client = createClient(fetchFn);

    await client.provisioning.layers.patchLabel('my_schema.my_table.the_geom', 'a1b2c3d4', 'c9d0e1f2', {
      size: '12',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/labels/c9d0e1f2',
    );
    expect(init.method).toBe('PATCH');
  });

  it('deleteLabel sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.layers.deleteLabel('my_schema.my_table.the_geom', 'a1b2c3d4', 'c9d0e1f2');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/layers/my_schema.my_table.the_geom/classes/a1b2c3d4/labels/c9d0e1f2',
    );
    expect(init.method).toBe('DELETE');
  });
});
