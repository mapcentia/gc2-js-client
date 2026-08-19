/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/**
 * Query parameters for OWS (WMS/WFS/UTFGRID) requests, e.g.
 * `{ SERVICE: 'WMS', REQUEST: 'GetCapabilities' }`.
 */
export type OwsParams = Record<string, string | number | boolean>;

function toQuery(params?: OwsParams): Record<string, string> | undefined {
  if (!params) return undefined;
  const query: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      query[key] = String(value);
    }
  }
  return Object.keys(query).length > 0 ? query : undefined;
}

/**
 * OWS (WMS/WFS/UTFGRID) endpoint wrapper.
 *
 * The endpoint accepts Bearer token, HTTP Basic and anonymous requests. A
 * Bearer token must match the `database` in the path; protected layers
 * challenge token-less requests with HTTP Basic auth.
 *
 * Responses are streamed from the backend and returned as text (XML) or, for
 * JSON responses such as UTFGRID, as parsed JSON. Binary responses (e.g. WMS
 * GetMap images) are not supported by this wrapper — request those directly.
 */
export class Ows {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string, database: string): string {
    return `api/v4/ows/schema/${encodeURIComponent(schema)}/database/${encodeURIComponent(database)}`;
  }

  /** OWS GET (WMS/WFS/UTFGRID). */
  async getOws<T = string>(schema: string, database: string, params?: OwsParams): Promise<T> {
    return this.client.request<T>({
      path: this.basePath(schema, database),
      method: 'GET',
      query: toQuery(params),
      accept: '*/*',
    });
  }

  /** OWS POST (WFS XML). */
  async postOws(schema: string, database: string, xml: string): Promise<string> {
    return this.client.request<string>({
      path: this.basePath(schema, database),
      method: 'POST',
      body: xml,
      contentType: 'text/xml',
      accept: '*/*',
    });
  }
}
