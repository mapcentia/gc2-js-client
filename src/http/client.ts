/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaClientConfig, CentiaAuth, RequestOptions, FullResponse } from './types';
import { CentiaApiError } from './errors';

/**
 * Unified HTTP client for the Centia API.
 * Works in both Node.js and browser environments.
 */
export class CentiaHttpClient {
  private readonly baseUrl: string;
  private readonly auth: CentiaAuth;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly userAgent: string | undefined;

  constructor(config: CentiaClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/+$/, '');
    this.auth = config.auth ?? {};
    this.fetchFn = config.fetch ?? globalThis.fetch.bind(globalThis);
    this.userAgent = config.userAgent;
  }

  /**
   * Execute an HTTP request against the Centia API.
   * Returns parsed JSON on success. Throws CentiaApiError on non-expected status.
   */
  async request<T = unknown>(opts: RequestOptions): Promise<T> {
    const result = await this.requestFull<T>(opts);
    return result.body;
  }

  /**
   * Execute an HTTP request and return the full response including headers.
   * Useful for operations that return Location headers (POST 201, PATCH 303).
   */
  async requestFull<T = unknown>(opts: RequestOptions): Promise<FullResponse<T>> {
    const url = this.buildUrl(opts.path, opts.query);
    const headers = await this.buildHeaders(opts);

    const init: RequestInit = {
      method: opts.method,
      headers,
      redirect: 'manual',
    };

    if (opts.body !== undefined && opts.body !== null) {
      const ct = this.resolveContentType(opts.contentType);
      init.body = ct === 'application/json'
        ? JSON.stringify(opts.body)
        : opts.body as BodyInit;
    }

    const response = await this.fetchFn(url, init);
    const body = await this.handleResponse<T>(response, opts, url);
    return {
      body,
      status: response.status,
      getHeader: (name: string) => response.headers.get(name),
    };
  }

  private buildUrl(path: string, query?: Record<string, string>): string {
    const cleanPath = path.replace(/^\/+/, '');
    let url = `${this.baseUrl}/${cleanPath}`;
    if (query) {
      const params = new URLSearchParams(query);
      url += `?${params.toString()}`;
    }
    return url;
  }

  private async buildHeaders(opts: RequestOptions): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Accept': 'application/json',
    };

    // Auth: getAccessToken sets Bearer token
    if (this.auth.getAccessToken) {
      const token = await this.auth.getAccessToken();
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }

    // Auth: getHeaders merges (can override Authorization)
    if (this.auth.getHeaders) {
      const authHeaders = await this.auth.getHeaders();
      Object.assign(headers, authHeaders);
    }

    // User-Agent only in non-browser environments
    if (this.userAgent && typeof navigator === 'undefined') {
      headers['User-Agent'] = this.userAgent;
    }

    // Content-Type
    const ct = this.resolveContentType(opts.contentType);
    if (ct) {
      headers['Content-Type'] = ct;
    }

    return headers;
  }

  private resolveContentType(contentType: string | null | undefined): string | null {
    if (contentType === null) return null;
    return contentType ?? 'application/json';
  }

  private async handleResponse<T>(
    response: Response,
    opts: RequestOptions,
    url: string,
  ): Promise<T> {
    const expectedStatus = opts.expectedStatus ?? 200;

    let bodyText = '';
    try {
      bodyText = await response.text();
    } catch {
      // Body read errors are handled below
    }

    let parsed: any = null;
    if (bodyText) {
      try {
        parsed = JSON.parse(bodyText);
      } catch {
        // Not JSON — keep parsed as null
      }
    }

    if (response.status !== expectedStatus) {
      const msg = (parsed?.message ?? parsed?.error ?? bodyText)
        || `Unexpected status ${response.status}`;

      throw new CentiaApiError({
        message: msg,
        status: response.status,
        code: parsed?.code,
        details: parsed,
        requestId: response.headers.get('x-request-id') ?? undefined,
        method: opts.method,
        url,
      });
    }

    return parsed as T;
  }
}

/**
 * Create a new Centia HTTP client.
 *
 * Node.js usage:
 * ```ts
 * const client = createCentiaClient({
 *   baseUrl: 'https://example.centia.io',
 *   auth: { getAccessToken: async () => process.env.CENTIA_TOKEN },
 * });
 * ```
 *
 * Browser usage:
 * ```ts
 * const client = createCentiaClient({
 *   baseUrl: 'https://example.centia.io',
 *   auth: { getAccessToken: async () => getStoredToken() },
 * });
 * ```
 */
export function createCentiaClient(config: CentiaClientConfig): CentiaHttpClient {
  return new CentiaHttpClient(config);
}
