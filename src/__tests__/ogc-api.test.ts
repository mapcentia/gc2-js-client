import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Ogc, OGC_CRS84, ogcEpsgCrs } from '../ogc/Ogc';
import { CentiaApiError } from '../http/errors';

function mockFetch(status: number, body: unknown, headers?: Record<string, string>): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => (typeof body === 'string' ? body : body != null ? JSON.stringify(body) : ''),
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

const BASE = 'https://api.example.com/api/v4/ogc/database/my_database';
const point = { type: 'Point', coordinates: [10.0, 55.0] };

describe('Ogc CRS helpers', () => {
  it('exposes CRS84 and builds EPSG URIs', () => {
    expect(OGC_CRS84).toBe('http://www.opengis.net/def/crs/OGC/1.3/CRS84');
    expect(ogcEpsgCrs(25832)).toBe('http://www.opengis.net/def/crs/EPSG/0/25832');
  });
});

describe('Ogc', () => {
  it('getLandingPage sends GET to the database root', async () => {
    const landing = { title: 'my_database OGC API', links: [{ rel: 'data', href: `${BASE}/collections` }] };
    const fetchFn = mockFetch(200, landing);
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getLandingPage('my_database');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(BASE);
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toEqual(landing);
  });

  it('getConformance sends GET to /conformance', async () => {
    const fetchFn = mockFetch(200, { conformsTo: ['http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core'] });
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getConformance('my_database');

    expect(lastCall(fetchFn)[0]).toBe(`${BASE}/conformance`);
    expect(result.conformsTo).toHaveLength(1);
  });

  it('getCollections sends limit and offset', async () => {
    const page = { links: [], numberMatched: 3, numberReturned: 1, collections: [{ id: 'my_schema.roads' }] };
    const fetchFn = mockFetch(200, page);
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getCollections('my_database', { limit: 1, offset: 2 });

    expect(lastCall(fetchFn)[0]).toBe(`${BASE}/collections?limit=1&offset=2`);
    expect(result.collections[0].id).toBe('my_schema.roads');
  });

  it('getCollections without options sends no query string', async () => {
    const fetchFn = mockFetch(200, { links: [], numberMatched: 0, numberReturned: 0, collections: [] });
    const ogc = new Ogc(createHttp(fetchFn));

    await ogc.getCollections('my_database');

    expect(lastCall(fetchFn)[0]).toBe(`${BASE}/collections`);
  });

  it('getCollection URL-encodes the collection id', async () => {
    const collection = { id: 'my schema.roads', itemType: 'feature', crs: [OGC_CRS84], links: [] };
    const fetchFn = mockFetch(200, collection);
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getCollection('my_database', 'my schema.roads');

    expect(lastCall(fetchFn)[0]).toBe(`${BASE}/collections/my%20schema.roads`);
    expect(result.id).toBe('my schema.roads');
  });

  it('getItems sends every parameter and asks for GeoJSON', async () => {
    const collection = {
      type: 'FeatureCollection',
      numberMatched: 1,
      numberReturned: 1,
      timeStamp: '2026-09-11T00:00:00Z',
      features: [{ type: 'Feature', id: 1, geometry: point, properties: { gid: 1, name: 'a' } }],
      links: [],
    };
    const fetchFn = mockFetch(200, collection, { 'content-crs': `<${OGC_CRS84}>` });
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getItems<{ gid: number; name: string }>('my_database', 'my_schema.roads', {
      limit: 50,
      offset: 100,
      bbox: [9, 55, 10, 56],
      bboxCrs: OGC_CRS84,
      crs: ogcEpsgCrs(25832),
      datetime: '2024-01-01T00:00:00Z',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      `${BASE}/collections/my_schema.roads/items?limit=50&offset=100&bbox=9%2C55%2C10%2C56` +
        '&bbox-crs=http%3A%2F%2Fwww.opengis.net%2Fdef%2Fcrs%2FOGC%2F1.3%2FCRS84' +
        '&crs=http%3A%2F%2Fwww.opengis.net%2Fdef%2Fcrs%2FEPSG%2F0%2F25832' +
        '&datetime=2024-01-01T00%3A00%3A00Z',
    );
    expect((init.headers as Record<string, string>)['Accept']).toBe('application/geo+json');
    expect(result.numberMatched).toBe(1);
    expect(result.features[0].properties.name).toBe('a');
  });

  it('getItems accepts bbox as a string and omits undefined options', async () => {
    const fetchFn = mockFetch(200, { type: 'FeatureCollection', features: [], numberMatched: 0, numberReturned: 0, links: [] });
    const ogc = new Ogc(createHttp(fetchFn));

    await ogc.getItems('my_database', 'my_schema.roads', { bbox: '9,55,10,56' });

    expect(lastCall(fetchFn)[0]).toBe(`${BASE}/collections/my_schema.roads/items?bbox=9%2C55%2C10%2C56`);
  });

  it('getItem sends GET for one feature with crs', async () => {
    const feature = { type: 'Feature', id: 7, geometry: point, properties: { gid: 7 }, links: [] };
    const fetchFn = mockFetch(200, feature);
    const ogc = new Ogc(createHttp(fetchFn));

    const result = await ogc.getItem('my_database', 'my_schema.roads', 7, { crs: ogcEpsgCrs(4326) });

    expect(lastCall(fetchFn)[0]).toBe(
      `${BASE}/collections/my_schema.roads/items/7?crs=http%3A%2F%2Fwww.opengis.net%2Fdef%2Fcrs%2FEPSG%2F0%2F4326`,
    );
    expect(result.id).toBe(7);
  });

  it('getItem throws CentiaApiError on 404', async () => {
    const fetchFn = mockFetch(404, { success: false, message: 'Feature 9 not found', code: 404, errorCode: 'FEATURE_NOT_FOUND' });
    const ogc = new Ogc(createHttp(fetchFn));

    await expect(ogc.getItem('my_database', 'my_schema.roads', 9)).rejects.toBeInstanceOf(CentiaApiError);
  });

  it('mapUrl builds the collection map URL without fetching', () => {
    const fetchFn = mockFetch(200, null);
    const ogc = new Ogc(createHttp(fetchFn));

    const url = ogc.mapUrl('my_database', 'my_schema.roads', {
      bbox: [9, 55, 10, 56],
      width: 512,
      height: 256,
      format: 'jpeg',
      transparent: false,
      bgcolor: '0xFFFFFF',
    });

    expect(url).toBe(
      `${BASE}/collections/my_schema.roads/map?bbox=9%2C55%2C10%2C56&width=512&height=256&f=jpeg&transparent=false&bgcolor=0xFFFFFF`,
    );
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('datasetMapUrl joins collections with commas', () => {
    const ogc = new Ogc(createHttp(mockFetch(200, null)));

    const url = ogc.datasetMapUrl('my_database', ['my_schema.roads', 'my_schema.buildings'], { width: 64 });

    expect(url).toBe(`${BASE}/map?collections=my_schema.roads%2Cmy_schema.buildings&width=64`);
  });
});
