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
 * Token-authenticated clients use `getOws`/`postOws`; anonymous and HTTP-Basic
 * clients use the `...NoToken` variants, which include the database in the path.
 *
 * Responses are streamed from the backend and returned as text (XML) or, for
 * JSON responses such as UTFGRID, as parsed JSON. Binary responses (e.g. WMS
 * GetMap images) are not supported by this wrapper — request those directly.
 */
export class Ows {
  constructor(private readonly client: CentiaHttpClient) {}

  /** Token-authenticated OWS GET (WMS/WFS/UTFGRID). */
  async getOws<T = string>(schema: string, params?: OwsParams): Promise<T> {
    return this.client.request<T>({
      path: `api/v4/ows/schema/${encodeURIComponent(schema)}`,
      method: 'GET',
      query: toQuery(params),
      accept: '*/*',
    });
  }

  /** Token-authenticated OWS POST (WFS XML). */
  async postOws(schema: string, xml: string): Promise<string> {
    return this.client.request<string>({
      path: `api/v4/ows/schema/${encodeURIComponent(schema)}`,
      method: 'POST',
      body: xml,
      contentType: 'text/xml',
      accept: '*/*',
    });
  }

  /** Anonymous/HTTP-Basic OWS GET (WMS/WFS/UTFGRID). */
  async getOwsNoToken<T = string>(schema: string, database: string, params?: OwsParams): Promise<T> {
    return this.client.request<T>({
      path: `api/v4/ows/schema/${encodeURIComponent(schema)}/database/${encodeURIComponent(database)}`,
      method: 'GET',
      query: toQuery(params),
      accept: '*/*',
    });
  }

  /** Anonymous/HTTP-Basic OWS POST (WFS XML). */
  async postOwsNoToken(schema: string, database: string, xml: string): Promise<string> {
    return this.client.request<string>({
      path: `api/v4/ows/schema/${encodeURIComponent(schema)}/database/${encodeURIComponent(database)}`,
      method: 'POST',
      body: xml,
      contentType: 'text/xml',
      accept: '*/*',
    });
  }
}
