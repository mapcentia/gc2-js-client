import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Mapcache } from '../ogc/Mapcache';

const XML = '<?xml version="1.0"?><Capabilities/>';

function mockFetch(status: number, bodyText: string): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => bodyText,
    headers: {
      get: () => null,
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

describe('Mapcache', () => {
  it('getMapcache sends GET to the service path, preserving slashes', async () => {
    const fetchFn = mockFetch(200, XML);
    const mapcache = new Mapcache(createHttp(fetchFn));

    const result = await mapcache.getMapcache('my_database', 'wmts/1.0.0/WMTSCapabilities.xml');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database/wmts/1.0.0/WMTSCapabilities.xml');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toBe(XML);
  });

  it('getMapcache supports WMS query params', async () => {
    const fetchFn = mockFetch(200, XML);
    const mapcache = new Mapcache(createHttp(fetchFn));

    await mapcache.getMapcache('my_database', 'wms', {
      SERVICE: 'WMS',
      REQUEST: 'GetCapabilities',
    });

    const [url] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/mapcache/database/my_database/wms?SERVICE=WMS&REQUEST=GetCapabilities',
    );
  });

  it('getMapcache works without a service path', async () => {
    const fetchFn = mockFetch(200, XML);
    const mapcache = new Mapcache(createHttp(fetchFn));

    await mapcache.getMapcache('my_database');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database');
  });

  it('mapcacheUrl builds a full URL preserving tile template placeholders', () => {
    const mapcache = new Mapcache(createHttp(mockFetch(200, '')));

    const url = mapcache.mapcacheUrl('my_database', 'tms/1.0.0/my_schema.my_table@g20/{z}/{x}/{y}.png');

    expect(url).toBe(
      'https://api.example.com/api/v4/mapcache/database/my_database/tms/1.0.0/my_schema.my_table@g20/{z}/{x}/{y}.png',
    );
  });

  it('deleteMapcacheTileset returns the seed job info on a scoped delete (202)', async () => {
    const job = {
      success: true,
      mode: 'seed',
      message: 'Scoped tile cache deletion started',
      backend: 'sqlite3',
      uuid: 'abc-123',
      pid: 4711,
      tileset: 'my_schema.roads',
      grid: 'g20',
      scope: { bbox: null, zoom: '0,12' },
      _links: { self: '/api/v4/mapcache/database/my_database/tileset/my_schema.roads' },
    };
    const fetchFn = mockFetch(202, JSON.stringify(job));
    const mapcache = new Mapcache(createHttp(fetchFn));

    const result = await mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads', { zoom: '0,12' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database/tileset/my_schema.roads?zoom=0%2C12');
    expect(init.method).toBe('DELETE');
    expect(result).toEqual(job);
  });

  it('deleteMapcacheTileset resolves on a synchronous full wipe (200)', async () => {
    const wiped = {
      success: true,
      mode: 'wipe',
      message: 'Tile cache deleted',
      backend: 'sqlite3',
      tileset: 'my_schema.roads',
      removed: 1234,
    };
    const fetchFn = mockFetch(200, JSON.stringify(wiped));
    const mapcache = new Mapcache(createHttp(fetchFn));

    const result = await mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads');

    expect(result).toEqual(wiped);
    if (result.mode === 'wipe' && 'removed' in result) {
      expect(result.removed).toBe(1234);
    }
  });

  it('deleteMapcacheTileset resolves on a background disk wipe (202)', async () => {
    const started = {
      success: true,
      mode: 'wipe',
      message: 'Tile cache deletion started (disk directory removed in background)',
      backend: 'disk',
      uuid: 'def-456',
      tileset: 'my_schema.roads',
    };
    const fetchFn = mockFetch(202, JSON.stringify(started));
    const mapcache = new Mapcache(createHttp(fetchFn));

    const result = await mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads');

    expect(result).toEqual(started);
  });

  it('deleteMapcacheTileset clears a merged per-schema tileset by its bare schema name', async () => {
    const wiped = { success: true, mode: 'wipe', message: 'Tile cache deleted', backend: 'sqlite', tileset: 'dagi', removed: 42 };
    const fetchFn = mockFetch(200, JSON.stringify(wiped));
    const mapcache = new Mapcache(createHttp(fetchFn));

    const result = await mapcache.deleteMapcacheTileset('my_database', 'dagi');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database/tileset/dagi');
    expect(result).toEqual(wiped);
  });

  it('deleteMapcacheTileset throws UNSUPPORTED_BACKEND on a full delete of an s3 cache', async () => {
    const fetchFn = mockFetch(400, JSON.stringify({ message: 'Full delete not supported', code: 'UNSUPPORTED_BACKEND' }));
    const mapcache = new Mapcache(createHttp(fetchFn));

    await expect(mapcache.deleteMapcacheTileset('my_database', 'dagi'))
      .rejects.toMatchObject({ status: 400, code: 'UNSUPPORTED_BACKEND' });
  });

  it('deleteMapcacheTileset still throws on other statuses', async () => {
    const fetchFn = mockFetch(400, JSON.stringify({ message: 'Full delete not supported for s3' }));
    const mapcache = new Mapcache(createHttp(fetchFn));

    await expect(mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads')).rejects.toMatchObject({ status: 400 });
  });

  it('deleteMapcacheTileset scopes by bbox, zoom and grid', async () => {
    const fetchFn = mockFetch(202, '{"success":true}');
    const mapcache = new Mapcache(createHttp(fetchFn));

    await mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads.mvt', {
      bbox: '890000,7260000,1730000,7870000',
      zoom: '0,12',
      grid: 'g20',
    });

    const [url] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/mapcache/database/my_database/tileset/my_schema.roads.mvt?bbox=890000%2C7260000%2C1730000%2C7870000&zoom=0%2C12&grid=g20',
    );
  });

  it('deleteMapcacheTileset accepts a single numeric zoom', async () => {
    const fetchFn = mockFetch(202, '{"success":true}');
    const mapcache = new Mapcache(createHttp(fetchFn));

    await mapcache.deleteMapcacheTileset('my_database', 'my_schema.roads', { zoom: 8 });

    const [url] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/mapcache/database/my_database/tileset/my_schema.roads?zoom=8',
    );
  });

  it('mapcacheUrl appends query params', () => {
    const mapcache = new Mapcache(createHttp(mockFetch(200, '')));

    const url = mapcache.mapcacheUrl('my_database', 'wms', { SERVICE: 'WMS', REQUEST: 'GetMap' });

    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database/wms?SERVICE=WMS&REQUEST=GetMap');
  });
});
