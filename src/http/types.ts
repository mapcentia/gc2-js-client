/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

/** Auth injection callbacks for the HTTP client. */
export interface CentiaAuth {
  /** Returns a Bearer token. Called before each request. */
  getAccessToken?: () => Promise<string | undefined>;
  /**
   * Returns additional headers. Merged after getAccessToken,
   * so it can override Authorization if needed.
   */
  getHeaders?: () => Promise<Record<string, string>>;
}

/** Configuration for createCentiaClient(). */
export interface CentiaClientConfig {
  /** Base URL of the Centia API (e.g. "https://example.centia.io"). */
  baseUrl: string;
  /** Auth injection. If omitted, requests are unauthenticated. */
  auth?: CentiaAuth;
  /** Custom fetch implementation. Defaults to globalThis.fetch. */
  fetch?: typeof globalThis.fetch;
  /** User-Agent header (ignored in browsers). */
  userAgent?: string;
}

/** Options for a single HTTP request via CentiaHttpClient. */
export interface RequestOptions {
  /** URL path relative to baseUrl (e.g. "api/v4/sql"). Leading slash is stripped. */
  path: string;
  /** HTTP method. */
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Request body. Serialized as JSON unless contentType overrides. */
  body?: unknown;
  /** Query parameters appended to the URL. */
  query?: Record<string, string>;
  /** Content-Type header. Defaults to "application/json". Set to null to omit. */
  contentType?: string | null;
  /** Accept header. Defaults to "application/json". */
  accept?: string;
  /** Expected HTTP status code. Defaults to 200. Non-match throws CentiaApiError. */
  expectedStatus?: number;
}

/** Full HTTP response with metadata, returned by CentiaHttpClient.requestFull(). */
export interface FullResponse<T> {
  /** Parsed response body (null for empty responses like 204). */
  body: T;
  /** HTTP status code. */
  status: number;
  /** Get a response header value by name. */
  getHeader(name: string): string | null;
}
