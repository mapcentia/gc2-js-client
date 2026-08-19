import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Ows } from '../ogc/Ows';
import { Wfs } from '../ogc/Wfs';

const XML = '<?xml version="1.0"?><WFS_Capabilities/>';

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

describe('Ows', () => {
  it('getOws sends GET with query params to the database-qualified endpoint', async () => {
    const fetchFn = mockFetch(200, XML);
    const ows = new Ows(createHttp(fetchFn));

    const result = await ows.getOws('my_schema', 'my_database', {
      SERVICE: 'WFS',
      REQUEST: 'GetCapabilities',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/ows/schema/my_schema/database/my_database?SERVICE=WFS&REQUEST=GetCapabilities',
    );
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toBe(XML);
  });

  it('postOws sends XML body with text/xml content type', async () => {
    const fetchFn = mockFetch(200, XML);
    const ows = new Ows(createHttp(fetchFn));

    const request = '<wfs:GetFeature/>';
    await ows.postOws('my_schema', 'my_database', request);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/ows/schema/my_schema/database/my_database');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(request);
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('text/xml');
  });
});

describe('Wfs', () => {
  it('getWfs sends GET with WFS params and defaults SERVICE to WFS', async () => {
    const fetchFn = mockFetch(200, XML);
    const wfs = new Wfs(createHttp(fetchFn));

    const result = await wfs.getWfs('my_schema', 'my_database', {
      REQUEST: 'GetFeature',
      TYPENAME: 'my_table',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/wfs/schema/my_schema/database/my_database?SERVICE=WFS&REQUEST=GetFeature&TYPENAME=my_table',
    );
    expect(init.method).toBe('GET');
    expect(result).toBe(XML);
  });

  it('getWfs includes srs and ts path segments', async () => {
    const fetchFn = mockFetch(200, XML);
    const wfs = new Wfs(createHttp(fetchFn));

    await wfs.getWfs(
      'my_schema',
      'my_database',
      { REQUEST: 'GetFeature', MAXFEATURES: 100 },
      { srs: 25832, timeSlice: '2020-01-01' },
    );

    const [url] = lastCall(fetchFn);
    expect(url).toBe(
      'https://api.example.com/api/v4/wfs/schema/my_schema/database/my_database/srs/25832/ts/2020-01-01?SERVICE=WFS&REQUEST=GetFeature&MAXFEATURES=100',
    );
  });

  it('getWfs rejects timeSlice without srs', async () => {
    const fetchFn = mockFetch(200, XML);
    const wfs = new Wfs(createHttp(fetchFn));

    await expect(
      wfs.getWfs('my_schema', 'my_database', { REQUEST: 'GetFeature' }, { timeSlice: '2020-01-01' }),
    ).rejects.toThrow(/srs/);
  });

  it('postWfs sends XML with text/xml content type', async () => {
    const fetchFn = mockFetch(200, XML);
    const wfs = new Wfs(createHttp(fetchFn));

    const transaction = '<wfs:Transaction/>';
    await wfs.postWfs('my_schema', 'my_database', transaction, { srs: 25832 });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/wfs/schema/my_schema/database/my_database/srs/25832');
    expect(init.method).toBe('POST');
    expect(init.body).toBe(transaction);
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('text/xml');
  });

  it('postWfs works without optional path segments', async () => {
    const fetchFn = mockFetch(200, XML);
    const wfs = new Wfs(createHttp(fetchFn));

    await wfs.postWfs('my_schema', 'my_database', '<wfs:GetFeature/>');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/wfs/schema/my_schema/database/my_database');
    expect(init.method).toBe('POST');
  });
});
