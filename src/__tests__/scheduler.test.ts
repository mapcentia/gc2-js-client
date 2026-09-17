import { describe, it, expect, vi } from 'vitest';
import { createCentiaClient } from '../http/client';
import { Scheduler } from '../scheduler/Scheduler';

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
  id: 5497, name: 'import buildings', schema: 'geodanmark', url: 'https://example.com/data.zip',
  schedule: '0 3 * * *', epsg: 25832, type: 'AUTO', encoding: 'UTF8', extra: null,
  delete_append: false, download_schema: true, presql: null, postsql: null,
  active: true, snapshot: false, lastcheck: true, lasttimestamp: 't', lastrun: 'r', report: null,
};

const run = {
  uuid: 'u-1', job: 5497, name: 'import buildings', pid: 123, host: 'w1', slot: 1,
  status: 'running', stale: false, started_at: 's', heartbeat: 'h', finished_at: null, exit_reason: null,
};

describe('Scheduler jobs', () => {
  it('getSchedulerJobs lists all jobs', async () => {
    const fetchFn = mockFetch(200, [job]);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.getSchedulerJobs();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer test-token');
    expect(result).toEqual([job]);
  });

  it('getSchedulerJob fetches one job by id', async () => {
    const fetchFn = mockFetch(200, job);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.getSchedulerJob(5497);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs/5497');
    expect(result).toEqual(job);
  });

  it('getSchedulerJob joins multiple ids with commas and returns an array', async () => {
    const fetchFn = mockFetch(200, [job, { ...job, id: 5498 }]);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.getSchedulerJob([5497, 5498]);

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs/5497,5498');
    expect(result).toHaveLength(2);
  });

  it('postSchedulerJob sends POST, expects 201 and parses ids from Location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/scheduler/jobs/5497' });
    const scheduler = new Scheduler(createHttp(fetchFn));
    const input = { name: 'import buildings', schema: 'geodanmark', url: 'https://example.com/d.zip', schedule: '0 3 * * *' };

    const result = await scheduler.postSchedulerJob(input);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(input);
    expect(result.location).toBe('/api/v4/scheduler/jobs/5497');
    expect(result.ids).toEqual([5497]);
  });

  it('postSchedulerJob accepts an array and parses several ids', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/scheduler/jobs/5497,5498' });
    const scheduler = new Scheduler(createHttp(fetchFn));
    const input = { name: 'a', schema: 's', url: 'u', schedule: '* * * * *' };

    const result = await scheduler.postSchedulerJob([input, { ...input, name: 'b' }]);

    const [, init] = lastCall(fetchFn);
    expect(JSON.parse(init.body as string)).toHaveLength(2);
    expect(result.ids).toEqual([5497, 5498]);
  });

  it('patchSchedulerJob sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/scheduler/jobs/5497' });
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.patchSchedulerJob(5497, { active: false });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs/5497');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({ active: false });
    expect(result.location).toBe('/api/v4/scheduler/jobs/5497');
  });

  it('deleteSchedulerJob sends DELETE 204 with comma-joined ids', async () => {
    const fetchFn = mockFetch(204, null);
    const scheduler = new Scheduler(createHttp(fetchFn));

    await scheduler.deleteSchedulerJob([5497, 5498]);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/jobs/5497,5498');
    expect(init.method).toBe('DELETE');
  });
});

describe('Scheduler runs', () => {
  it('getSchedulerRuns lists runs with job and status filters', async () => {
    const fetchFn = mockFetch(200, [run]);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.getSchedulerRuns({ job: 5497, status: 'running' });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/runs?job=5497&status=running');
    expect(result).toEqual([run]);
  });

  it('getSchedulerRun fetches one run by uuid', async () => {
    const fetchFn = mockFetch(200, run);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.getSchedulerRun('u-1');

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/runs/u-1');
    expect(result).toEqual(run);
  });

  it('postSchedulerRun starts a job run and expects 202', async () => {
    const accepted = { job: 5497, status: 'starting', _links: { runs: '/api/v4/scheduler/runs?job=5497' } };
    const fetchFn = mockFetch(202, accepted);
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.postSchedulerRun({ job: 5497, force: true });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/runs');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ job: 5497, force: true });
    expect(result).toEqual(accepted);
  });

  it('deleteSchedulerRun stops a run and returns the signal', async () => {
    const fetchFn = mockFetch(200, { uuid: 'u-1', signal: 'SIGINT' });
    const scheduler = new Scheduler(createHttp(fetchFn));

    const result = await scheduler.deleteSchedulerRun('u-1');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/scheduler/runs/u-1');
    expect(init.method).toBe('DELETE');
    expect(result).toEqual({ uuid: 'u-1', signal: 'SIGINT' });
  });
});
