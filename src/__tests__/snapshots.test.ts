import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { isCentiaApiError } from '../http/errors';
import { Snapshots } from '../snapshots/Snapshots';

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

const job = {
  id: 'a1b2', schema: 'geodanmark', relation: 'bygning', srs: null,
  status: 'succeeded', snapshot_date: '2026-09-16', s3_path: 's3://x/',
  row_count: 10, schema_version: 'abc', relation_schema: [{ column_name: 'gid', data_type: 'integer' }],
  error: null, username: 'mh', created: 'c', started: 's', finished: 'f',
};

describe('Snapshots job API', () => {
  it('postSnapshot sends POST and expects 202', async () => {
    const accepted = { id: 'a1b2', status: 'pending', _links: { self: '/api/v4/snapshots/a1b2' } };
    const fetchFn = mockFetch(202, accepted);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.postSnapshot({ schema: 'geodanmark', relation: 'bygning', srs: 25832 });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/snapshots');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ schema: 'geodanmark', relation: 'bygning', srs: 25832 });
    expect(result).toEqual(accepted);
  });

  it('getSnapshot fetches one job by id', async () => {
    const fetchFn = mockFetch(200, job);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.getSnapshot('a1b2');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/snapshots/a1b2');
    expect(init.method).toBe('GET');
    expect(result).toEqual(job);
  });

  it('postSnapshot accepts an array and returns the accepted jobs in order', async () => {
    const accepted = [
      { id: 'a1', status: 'pending', _links: { self: '/api/v4/snapshots/a1' } },
      { id: 'b2', status: 'pending', _links: { self: '/api/v4/snapshots/b2' } },
    ];
    const fetchFn = mockFetch(202, accepted);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.postSnapshot([
      { schema: 'geodanmark', relation: 'bygning' },
      { schema: 'geodanmark', relation: 'vej' },
    ]);

    const [, init] = lastCall(fetchFn);
    expect(JSON.parse(init.body as string)).toHaveLength(2);
    expect(result).toEqual(accepted);
  });

  it('getSnapshot joins multiple ids with commas and returns an array', async () => {
    const fetchFn = mockFetch(200, [job, { ...job, id: 'c3d4' }]);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.getSnapshot(['a1b2', 'c3d4']);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/snapshots/a1b2,c3d4');
    expect(result).toHaveLength(2);
  });

  it('getSnapshots sends schema and relation as query', async () => {
    const fetchFn = mockFetch(200, [job]);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.getSnapshots({ schema: 'geodanmark', relation: 'bygning' });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/snapshots?schema=geodanmark&relation=bygning');
    expect(result).toEqual([job]);
  });

  it('waitForSnapshot polls until a terminal status', async () => {
    const pending = { ...job, status: 'pending' };
    const running = { ...job, status: 'running' };
    const fetchFn = vi.fn()
      .mockResolvedValueOnce({ status: 200, text: async () => JSON.stringify(pending), headers: { get: () => null } })
      .mockResolvedValueOnce({ status: 200, text: async () => JSON.stringify(running), headers: { get: () => null } })
      .mockResolvedValueOnce({ status: 200, text: async () => JSON.stringify(job), headers: { get: () => null } });
    const snapshots = new Snapshots(createHttp(fetchFn as unknown as typeof globalThis.fetch));

    const result = await snapshots.waitForSnapshot('a1b2', { intervalMs: 1 });

    expect(fetchFn).toHaveBeenCalledTimes(3);
    expect(result.status).toBe('succeeded');
  });

  it('waitForSnapshot throws on timeout', async () => {
    const pending = { ...job, status: 'pending' };
    const fetchFn = mockFetch(200, pending);
    const snapshots = new Snapshots(createHttp(fetchFn));

    await expect(snapshots.waitForSnapshot('a1b2', { intervalMs: 1, timeoutMs: 5 }))
      .rejects.toThrow(/[Tt]ime/);
  });
});

describe('Snapshots read API', () => {
  it('getRelationSnapshots lists published snapshots', async () => {
    const entry = {
      snapshot_date: '2026-09-16', snapshot_id: 'a1b2', row_count: 10, size_bytes: 1000,
      schema_version: 'abc', files: [{ name: 'data-a1b2.parquet', size_bytes: 1000, href: 'h' }], published: 'p',
    };
    const fetchFn = mockFetch(200, [entry]);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const result = await snapshots.getRelationSnapshots('geodanmark', 'bygning');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/geodanmark/relations/bygning/snapshots');
    expect(result).toEqual([entry]);
  });

  it('getRelationSnapshot fetches one date', async () => {
    const fetchFn = mockFetch(200, { snapshot_date: '2026-09-16' });
    const snapshots = new Snapshots(createHttp(fetchFn));

    await snapshots.getRelationSnapshot('geodanmark', 'bygning', '2026-09-16');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/geodanmark/relations/bygning/snapshots/2026-09-16');
  });

  it('getRelationSnapshotDataUrl returns the absolute URL without fetching', () => {
    const fetchFn = mockFetch(200, null);
    const snapshots = new Snapshots(createHttp(fetchFn));

    const url = snapshots.getRelationSnapshotDataUrl('geodanmark', 'bygning', '2026-09-16');

    expect(url).toBe('https://api.example.com/api/v4/schemas/geodanmark/relations/bygning/snapshots/2026-09-16/data');
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it('getRelationSnapshotData returns the raw response with auth and follows redirects', async () => {
    const fetchFn = mockFetch(200, null, { 'content-type': 'application/vnd.apache.parquet' });
    const snapshots = new Snapshots(createHttp(fetchFn));

    const res = await snapshots.getRelationSnapshotData('geodanmark', 'bygning', '2026-09-16');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/geodanmark/relations/bygning/snapshots/2026-09-16/data');
    expect(init.method).toBe('GET');
    expect(init.redirect).toBe('follow');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined();
    expect(res.status).toBe(200);
  });

  it('getRelationSnapshotData sends a Range header and accepts 206', async () => {
    const fetchFn = mockFetch(206, null, { 'content-range': 'bytes 0-99/1000' });
    const snapshots = new Snapshots(createHttp(fetchFn));

    const res = await snapshots.getRelationSnapshotData('geodanmark', 'bygning', '2026-09-16', { range: [0, 99] });

    const [, init] = lastCall(fetchFn);
    expect((init.headers as Record<string, string>)['Range']).toBe('bytes=0-99');
    expect(res.status).toBe(206);
  });

  it('getRelationSnapshotData throws CentiaApiError on error statuses', async () => {
    const fetchFn = mockFetch(409, { message: 'Snapshot has several files', code: 'MULTI_FILE_SNAPSHOT' });
    const snapshots = new Snapshots(createHttp(fetchFn));

    const err = await snapshots.getRelationSnapshotData('geodanmark', 'bygning', '2026-09-16').catch((e) => e);

    expect(isCentiaApiError(err)).toBe(true);
    expect(err.status).toBe(409);
    expect(err.code).toBe('MULTI_FILE_SNAPSHOT');
  });

  it('headRelationSnapshotData sends HEAD', async () => {
    const fetchFn = mockFetch(200, null, { 'content-length': '1000', etag: 'W/"abc"' });
    const snapshots = new Snapshots(createHttp(fetchFn));

    const res = await snapshots.headRelationSnapshotData('geodanmark', 'bygning', '2026-09-16');

    const [, init] = lastCall(fetchFn);
    expect(init.method).toBe('HEAD');
    expect(res.headers.get('content-length')).toBe('1000');
  });

  it('getRelationSnapshotFile fetches one file by catalog name', async () => {
    const fetchFn = mockFetch(200, null);
    const snapshots = new Snapshots(createHttp(fetchFn));

    await snapshots.getRelationSnapshotFile('geodanmark', 'bygning', '2026-09-16', 'metadata-a1b2.json');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/schemas/geodanmark/relations/bygning/snapshots/2026-09-16/files/metadata-a1b2.json');
  });
});
