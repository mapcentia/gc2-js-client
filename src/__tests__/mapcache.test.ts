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

  it('mapcacheUrl appends query params', () => {
    const mapcache = new Mapcache(createHttp(mockFetch(200, '')));

    const url = mapcache.mapcacheUrl('my_database', 'wms', { SERVICE: 'WMS', REQUEST: 'GetMap' });

    expect(url).toBe('https://api.example.com/api/v4/mapcache/database/my_database/wms?SERVICE=WMS&REQUEST=GetMap');
  });
});
