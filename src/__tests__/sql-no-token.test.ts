import { describe, it, expect, vi } from 'vitest';
import { CentiaHttpClient } from '../http/client';
import SqlNoToken from '../SqlNoToken';

function mockFetch(status: number, body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => (body !== null && body !== undefined ? JSON.stringify(body) : ''),
    headers: {
      get: () => null,
    },
  } as unknown as Response);
}

function lastCall(fetchFn: typeof globalThis.fetch) {
  const calls = (fetchFn as ReturnType<typeof vi.fn>).mock.calls;
  return calls[calls.length - 1] as [string, RequestInit];
}

describe('SqlNoToken', () => {
  it('postSqlNoToken sends POST to database path', async () => {
    const sqlResult = [{ id: 1 }];
    const fetchFn = mockFetch(200, sqlResult);
    const http = new CentiaHttpClient({
      baseUrl: 'https://api.example.com',
      fetch: fetchFn,
    });
    const sqlNoToken = new SqlNoToken(http);

    const result = await sqlNoToken.postSqlNoToken('mydb', {
      q: 'SELECT 1 AS id',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/sql/database/mydb');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      q: 'SELECT 1 AS id',
    });
    expect(result).toEqual(sqlResult);
  });
});
