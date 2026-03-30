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

describe('MetadataWrite', () => {
  it('patchMetaData sends PATCH to /meta', async () => {
    const result = { ok: true };
    const fetchFn = mockFetch(200, result);
    const client = createClient(fetchFn);

    const res = await client.provisioning.metadata.patchMetaData({
      relations: {
        'public.cities': { title: 'Cities', abstract: 'World cities' },
      },
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/meta');
    expect(init.method).toBe('PATCH');
    expect(JSON.parse(init.body as string)).toEqual({
      relations: {
        'public.cities': { title: 'Cities', abstract: 'World cities' },
      },
    });
    expect(res).toEqual(result);
  });
});

describe('TypeScriptInterfaces', () => {
  it('getTypeScript sends GET to /interfaces with text/plain Accept', async () => {
    const tsCode = 'export interface MyMethod { id: number; }';
    // Simulate a text/plain response (not JSON-wrapped)
    const fetchFn = vi.fn().mockResolvedValue({
      status: 200,
      text: async () => tsCode,
      headers: { get: () => null },
    } as unknown as Response);
    const client = createClient(fetchFn);

    const result = await client.provisioning.typeScript.getTypeScript();

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/interfaces');
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['Accept']).toBe('text/plain');
    expect(result).toBe(tsCode);
  });
});

describe('FileImport', () => {
  it('postFileUpload sends POST with null contentType', async () => {
    const fetchFn = mockFetch(201, { filename: 'test.csv' });
    const client = createClient(fetchFn);

    const formData = new FormData();
    formData.append('file', new Blob(['data']), 'test.csv');

    const result = await client.provisioning.fileImport.postFileUpload(formData);

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/file/upload');
    expect(init.method).toBe('POST');
    expect(result).toEqual({ filename: 'test.csv' });
  });

  it('postFileUpload sends chunked requests when chunkSize is set', async () => {
    const fetchFn = vi.fn().mockResolvedValue({
      status: 201,
      text: async () => JSON.stringify({ filename: 'big.gpkg' }),
      headers: { get: () => null },
    } as unknown as Response);
    const client = createClient(fetchFn);

    // Create a 10-byte file so we get 3 chunks with chunkSize=4
    const file = new File(['0123456789'], 'big.gpkg');
    const formData = new FormData();
    formData.append('filename', file);

    const result = await client.provisioning.fileImport.postFileUpload(formData, {
      chunkSize: 4,
    });

    expect(result).toEqual({ filename: 'big.gpkg' });
    expect(fetchFn).toHaveBeenCalledTimes(3);

    // Verify each call has correct query params
    const calls = (fetchFn as ReturnType<typeof vi.fn>).mock.calls as [string, RequestInit][];
    expect(calls[0][0]).toContain('chunk=0');
    expect(calls[0][0]).toContain('chunks=3');
    expect(calls[1][0]).toContain('chunk=1');
    expect(calls[2][0]).toContain('chunk=2');
  });

  it('postFileUpload throws if FormData has no "filename" entry for chunked upload', async () => {
    const fetchFn = mockFetch(201, {});
    const client = createClient(fetchFn);

    const formData = new FormData();
    formData.append('other', new Blob(['data']));

    await expect(
      client.provisioning.fileImport.postFileUpload(formData, { chunkSize: 1024 }),
    ).rejects.toThrow('FormData must contain a "filename" entry');
  });

  it('postFileProcess sends POST with body', async () => {
    const processResult = { rows: 100 };
    const fetchFn = mockFetch(201, processResult);
    const client = createClient(fetchFn);

    const result = await client.provisioning.fileImport.postFileProcess({
      file: 'test.csv',
      schema: 'public',
      import: true,
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/file/process');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      file: 'test.csv',
      schema: 'public',
      import: true,
    });
    expect(result).toEqual(processResult);
  });
});

describe('GitCommit', () => {
  it('postCommit sends POST to /commit', async () => {
    const commitResult = { message: 'committed' };
    const fetchFn = mockFetch(200, commitResult);
    const client = createClient(fetchFn);

    const result = await client.provisioning.gitCommit.postCommit({
      schema: 'public',
      repo: 'https://github.com/example/repo.git',
      message: 'feat: add cities table',
    });

    const [url, init] = lastCall(fetchFn);
    expect(url).toBe('https://api.example.com/api/v4/commit');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({
      schema: 'public',
      repo: 'https://github.com/example/repo.git',
      message: 'feat: add cities table',
    });
    expect(result).toEqual(commitResult);
  });
});
