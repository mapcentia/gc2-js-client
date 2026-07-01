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

describe('Functions', () => {
  it('getFunctions sends GET for all functions', async () => {
    const fns = [{ name: 'greet', runtime: 'nodejs20', handler: 'index.handler' }];
    const fetchFn = mockFetch(200, fns);
    const result = await createClient(fetchFn).provisioning.functions.getFunctions();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions');
    expect(init.method).toBe('GET');
    expect(result).toEqual(fns);
  });

  it('getFunctions sends GET for a specific function', async () => {
    const fn = { name: 'greet', runtime: 'nodejs20', handler: 'index.handler' };
    const fetchFn = mockFetch(200, fn);
    const result = await createClient(fetchFn).provisioning.functions.getFunctions('greet');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet');
    expect(init.method).toBe('GET');
    expect(result).toEqual(fn);
  });

  it('postFunction sends POST 201 and returns location', async () => {
    const fetchFn = mockFetch(201, null, { location: '/api/v4/functions/greet' });
    const result = await createClient(fetchFn).provisioning.functions.postFunction({
      name: 'greet',
      runtime: 'nodejs20',
      handler: 'index.handler',
      code: 'export const handler = async () => ({ ok: true });',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions');
    expect(init.method).toBe('POST');
    expect(result.location).toBe('/api/v4/functions/greet');
  });

  it('patchFunction sends PATCH 303 and returns location', async () => {
    const fetchFn = mockFetch(303, null, { location: '/api/v4/functions/greet' });
    const result = await createClient(fetchFn).provisioning.functions.patchFunction('greet', {
      timeout_s: 60,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet');
    expect(init.method).toBe('PATCH');
    expect(result.location).toBe('/api/v4/functions/greet');
  });

  it('deleteFunction sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    await createClient(fetchFn).provisioning.functions.deleteFunction('greet');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet');
    expect(init.method).toBe('DELETE');
  });

  it('invoke sends POST with the event body', async () => {
    const body = { invocation: 'i1', status: 'succeeded', result: { greeting: 'Hi' } };
    const fetchFn = mockFetch(200, body);
    const result = await createClient(fetchFn).provisioning.functions.invoke('greet', { name: 'Ada' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet/invocations');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ name: 'Ada' });
    expect(result).toEqual(body);
  });

  it('invokeAsync sends POST ?async=true expecting 202', async () => {
    const fetchFn = mockFetch(202, { invocation: 'i2', status: 'pending' });
    const result = await createClient(fetchFn).provisioning.functions.invokeAsync('greet', { name: 'Ada' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet/invocations?async=true');
    expect(init.method).toBe('POST');
    expect(result.status).toBe('pending');
  });

  it('dryRun sends POST ?dry=true', async () => {
    const fetchFn = mockFetch(200, { dry_run: true, status: 'succeeded', input_schema: {}, output_schema: {} });
    const result = await createClient(fetchFn).provisioning.functions.dryRun('greet', { name: 'Ada' });

    const [url] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet/invocations?dry=true');
    expect(result.dry_run).toBe(true);
  });

  it('getInvocation fetches a stored invocation record', async () => {
    const rec = { invocation: 'i2', function: 'greet', status: 'succeeded' };
    const fetchFn = mockFetch(200, rec);
    const result = await createClient(fetchFn).provisioning.functions.getInvocation('greet', 'i2');

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/functions/greet/invocations/i2');
    expect(init.method).toBe('GET');
    expect(result).toEqual(rec);
  });

  it('getInterfaces requests text/plain', async () => {
    const ts = 'export interface Functions {}\n';
    const fetchFn = mockFetch(200, ts);
    const result = await createClient(fetchFn).provisioning.functions.getInterfaces();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/function-interfaces');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Accept']).toBe('text/plain');
    expect(result).toBe(ts);
  });
});
