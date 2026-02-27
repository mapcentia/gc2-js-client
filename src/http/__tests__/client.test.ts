import { describe, it, expect, vi } from 'vitest';
import { CentiaHttpClient, createCentiaClient } from '../client';
import { CentiaApiError, isCentiaApiError } from '../errors';

// Helper: create a mock fetch that returns a given Response
function mockFetch(status: number, body: unknown, headers?: Record<string, string>): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    status,
    text: async () => (body !== null && body !== undefined ? JSON.stringify(body) : ''),
    headers: {
      get: (name: string) => headers?.[name.toLowerCase()] ?? null,
    },
  } as unknown as Response);
}

describe('CentiaHttpClient', () => {
  describe('request basics', () => {
    it('makes a GET request with correct URL', async () => {
      const fetchFn = mockFetch(200, { ok: true });
      const client = createCentiaClient({
        baseUrl: 'https://api.example.com',
        fetch: fetchFn,
      });

      const result = await client.request({ path: 'api/v4/stats', method: 'GET' });

      expect(result).toEqual({ ok: true });
      expect(fetchFn).toHaveBeenCalledOnce();
      const [url, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(url).toBe('https://api.example.com/api/v4/stats');
      expect(init.method).toBe('GET');
    });

    it('strips trailing slashes from baseUrl', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({ baseUrl: 'https://api.example.com/', fetch: fetchFn });

      await client.request({ path: 'api/v4/sql', method: 'POST', body: { q: 'SELECT 1' } });

      const [url] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(url).toBe('https://api.example.com/api/v4/sql');
    });

    it('strips leading slashes from path', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      await client.request({ path: '/api/v4/sql', method: 'POST', body: { q: 'SELECT 1' } });

      const [url] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(url).toBe('https://api.example.com/api/v4/sql');
    });

    it('sends JSON body for POST', async () => {
      const fetchFn = mockFetch(200, { data: [] });
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      await client.request({
        path: 'api/v4/sql',
        method: 'POST',
        body: { q: 'SELECT 1' },
      });

      const [, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.body).toBe('{"q":"SELECT 1"}');
      expect(init.headers['Content-Type']).toBe('application/json');
    });

    it('appends query parameters', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      await client.request({
        path: 'api/v4/schemas',
        method: 'GET',
        query: { namesOnly: 'true' },
      });

      const [url] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(url).toBe('https://api.example.com/api/v4/schemas?namesOnly=true');
    });

    it('returns null for 204 empty response', async () => {
      const fetchFn = mockFetch(204, null);
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      const result = await client.request({
        path: 'api/v4/schemas/test/tables/foo',
        method: 'DELETE',
        expectedStatus: 204,
      });

      expect(result).toBeNull();
    });
  });

  describe('auth injection', () => {
    it('adds Bearer token from getAccessToken', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({
        baseUrl: 'https://api.example.com',
        fetch: fetchFn,
        auth: {
          getAccessToken: async () => 'my-secret-token',
        },
      });

      await client.request({ path: 'api/v4/stats', method: 'GET' });

      const [, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer my-secret-token');
    });

    it('skips Authorization when getAccessToken returns undefined', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({
        baseUrl: 'https://api.example.com',
        fetch: fetchFn,
        auth: {
          getAccessToken: async () => undefined,
        },
      });

      await client.request({ path: 'api/v4/stats', method: 'GET' });

      const [, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.headers['Authorization']).toBeUndefined();
    });

    it('getHeaders merges and can override Authorization', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({
        baseUrl: 'https://api.example.com',
        fetch: fetchFn,
        auth: {
          getAccessToken: async () => 'from-token',
          getHeaders: async () => ({
            'Authorization': 'Bearer from-headers',
            'X-Custom': 'value',
          }),
        },
      });

      await client.request({ path: 'api/v4/stats', method: 'GET' });

      const [, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer from-headers');
      expect(init.headers['X-Custom']).toBe('value');
    });

    it('getHeaders works without getAccessToken', async () => {
      const fetchFn = mockFetch(200, {});
      const client = createCentiaClient({
        baseUrl: 'https://api.example.com',
        fetch: fetchFn,
        auth: {
          getHeaders: async () => ({
            'Authorization': 'Bearer custom',
          }),
        },
      });

      await client.request({ path: 'api/v4/stats', method: 'GET' });

      const [, init] = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer custom');
    });
  });

  describe('error normalization', () => {
    it('throws CentiaApiError on non-expected status with JSON body', async () => {
      const fetchFn = mockFetch(
        400,
        { message: 'Bad request', code: 'INVALID_QUERY' },
        { 'x-request-id': 'req-123' },
      );
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      try {
        await client.request({ path: 'api/v4/sql', method: 'POST', body: {} });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(isCentiaApiError(e)).toBe(true);
        const err = e as CentiaApiError;
        expect(err.name).toBe('CentiaApiError');
        expect(err.status).toBe(400);
        expect(err.code).toBe('INVALID_QUERY');
        expect(err.message).toBe('Bad request');
        expect(err.requestId).toBe('req-123');
        expect(err.method).toBe('POST');
        expect(err.url).toBe('https://api.example.com/api/v4/sql');
        expect(err.details).toEqual({ message: 'Bad request', code: 'INVALID_QUERY' });
      }
    });

    it('throws CentiaApiError with fallback message for non-JSON error', async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        status: 500,
        text: async () => 'Internal Server Error',
        headers: { get: () => null },
      } as unknown as Response);
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      try {
        await client.request({ path: 'api/v4/stats', method: 'GET' });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(isCentiaApiError(e)).toBe(true);
        const err = e as CentiaApiError;
        expect(err.status).toBe(500);
        expect(err.message).toBe('Internal Server Error');
      }
    });

    it('throws CentiaApiError with status message for empty error body', async () => {
      const fetchFn = vi.fn().mockResolvedValue({
        status: 403,
        text: async () => '',
        headers: { get: () => null },
      } as unknown as Response);
      const client = createCentiaClient({ baseUrl: 'https://api.example.com', fetch: fetchFn });

      try {
        await client.request({ path: 'api/v4/stats', method: 'GET' });
        expect.fail('Should have thrown');
      } catch (e) {
        expect(isCentiaApiError(e)).toBe(true);
        const err = e as CentiaApiError;
        expect(err.status).toBe(403);
        expect(err.message).toBe('Unexpected status 403');
      }
    });

    it('isCentiaApiError returns false for plain Error', () => {
      expect(isCentiaApiError(new Error('nope'))).toBe(false);
    });
  });
});
