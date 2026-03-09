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

describe('Rules', () => {
  it('getRule sends GET for all rules', async () => {
    const rules = [{ id: 1, access: 'allow', priority: 100 }];
    const fetchFn = mockFetch(200, rules);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rules.getRule();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/rules');
    expect(init.method).toBe('GET');
    expect(result).toEqual(rules);
  });

  it('getRule sends GET for specific rule', async () => {
    const rule = { id: 42, access: 'deny', schema: 'public' };
    const fetchFn = mockFetch(200, rule);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rules.getRule(42);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/rules/42');
    expect(init.method).toBe('GET');
    expect(result).toEqual(rule);
  });

  it('postRule sends POST 201', async () => {
    const newRule = { id: 1, access: 'allow', priority: 50 };
    const fetchFn = mockFetch(201, newRule);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rules.postRule({
      access: 'allow',
      priority: 50,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/rules');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      access: 'allow',
      priority: 50,
    });
    expect(result).toEqual(newRule);
  });

  it('postRule sends POST with array body', async () => {
    const fetchFn = mockFetch(201, [{ id: 1 }, { id: 2 }]);
    const client = createClient(fetchFn);

    const body = [
      { access: 'allow' as const, priority: 10 },
      { access: 'deny' as const, priority: 20 },
    ];
    await client.provisioning.rules.postRule(body);

    const [, init] = lastCall(fetchFn);
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual(body);
  });

  it('patchRule sends PATCH to correct path', async () => {
    const updated = { id: 5, access: 'deny' };
    const fetchFn = mockFetch(200, updated);
    const client = createClient(fetchFn);

    const result = await client.provisioning.rules.patchRule(5, { access: 'deny' });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/rules/5');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({ access: 'deny' });
    expect(result).toEqual(updated);
  });

  it('deleteRule sends DELETE 204', async () => {
    const fetchFn = mockFetch(204, null);
    const client = createClient(fetchFn);

    await client.provisioning.rules.deleteRule(7);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/rules/7');
    expect(init.method).toBe('DELETE');
  });
});
