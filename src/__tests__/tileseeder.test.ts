import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Tileseeder } from '../tileseeder/Tileseeder';

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
  uuid: 'c4a3797e-ec6b-4dac-9474-ada9083620f3', name: 'Seed roads', status: 'pending', stale: false,
  username: 'mh', tileset: 'myschema.roads', grid: 'g20', zoom_start: 0, zoom_end: 12,
  extent_layer: null, threads: 2, host: null, pid: null, created: 'c', started: null, finished: null,
  heartbeat: null, cancel_requested: null, error: null,
  _links: { self: '/api/v4/tileseeder/jobs/c4a3797e-ec6b-4dac-9474-ada9083620f3' },
};

const input = { tileset: 'myschema.roads', grid: 'g20', zoom_start: 0, zoom_end: 12 };

describe('Tileseeder', () => {
  it('postSeedJob queues one job (202) and returns it', async () => {
    const fetchFn = mockFetch(202, job, { location: '/api/v4/tileseeder/jobs/c4a3797e-ec6b-4dac-9474-ada9083620f3' });
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.postSeedJob({ ...input, name: 'Seed roads', extent_layer: null, threads: 2 });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs');
    expect(init.method).toBe('POST');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(JSON.parse(init.body as string)).toEqual({ ...input, name: 'Seed roads', extent_layer: null, threads: 2 });
    expect(result).toEqual(job);
  });

  it('postSeedJob accepts an array and returns an array', async () => {
    const fetchFn = mockFetch(202, [job, { ...job, uuid: 'd5b4' }]);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.postSeedJob([input, { ...input, zoom_end: 14 }]);

    const [, init] = lastCall(fetchFn);
    expect(JSON.parse(init.body as string)).toHaveLength(2);
    expect(result).toHaveLength(2);
  });

  it('getSeedJobs lists jobs with status and tileset filters', async () => {
    const fetchFn = mockFetch(200, [job]);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.getSeedJobs({ status: 'running', tileset: 'myschema.roads' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs?status=running&tileset=myschema.roads');
    expect(init.method).toBe('GET');
    expect(result).toEqual([job]);
  });

  it('getSeedJobs without filters sends no query', async () => {
    const fetchFn = mockFetch(200, []);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    await tileseeder.getSeedJobs();

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs');
  });

  it('getSeedJob fetches one job with its log', async () => {
    const fetchFn = mockFetch(200, { ...job, log: 'seeding level 3' });
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.getSeedJob('c4a3797e-ec6b-4dac-9474-ada9083620f3');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs/c4a3797e-ec6b-4dac-9474-ada9083620f3');
    expect(result.log).toBe('seeding level 3');
  });

  it('getSeedJob joins several uuids with commas and returns an array', async () => {
    const fetchFn = mockFetch(200, [job, job]);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.getSeedJob(['a1', 'b2']);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs/a1,b2');
    expect(result).toHaveLength(2);
  });

  it('deleteSeedJob resolves to null when the job was cancelled outright (204)', async () => {
    const fetchFn = mockFetch(204, null);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.deleteSeedJob('a1');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs/a1');
    expect(init.method).toBe('DELETE');
    expect(result).toBeNull();
  });

  it('deleteSeedJob returns the stopping info when a job is running (202)', async () => {
    const stopping = {
      success: true, message: 'Stopping', uuid: ['a1', 'b2'],
      _links: { self: '/api/v4/tileseeder/jobs/a1,b2' },
    };
    const fetchFn = mockFetch(202, stopping);
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    const result = await tileseeder.deleteSeedJob(['a1', 'b2']);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/tileseeder/jobs/a1,b2');
    expect(result).toEqual(stopping);
    expect(result?._links.self).toBe('/api/v4/tileseeder/jobs/a1,b2');
  });

  it('deleteSeedJob throws on other statuses', async () => {
    const fetchFn = mockFetch(404, { message: 'Not found', code: 'JOB_NOT_FOUND' });
    const tileseeder = new Tileseeder(createHttp(fetchFn));

    await expect(tileseeder.deleteSeedJob('a1')).rejects.toMatchObject({ status: 404, code: 'JOB_NOT_FOUND' });
  });
});
