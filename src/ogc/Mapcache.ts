/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/** Query parameters for MapCache requests (e.g. WMS key/values). */
export type MapcacheParams = Record<string, string | number | boolean>;

function toQuery(params?: MapcacheParams): Record<string, string> | undefined {
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
 * Authorizing MapCache proxy wrapper (WMTS, TMS, WMS, Google Maps).
 *
 * The endpoint accepts anonymous, HTTP Basic and Bearer token requests; tile
 * requests are authorized against the tileset's layer.
 *
 * `getMapcache` fetches text responses (capabilities documents and other XML).
 * Binary tile responses (PNG/JPEG) are not supported by the fetch wrapper —
 * instead hand `mapcacheUrl(...)` to your map library as a tile URL template.
 */
export class Mapcache {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(database: string, path?: string): string {
    let p = `api/v4/mapcache/database/${encodeURIComponent(database)}`;
    if (path) {
      p += `/${path.replace(/^\/+/, '')}`;
    }
    return p;
  }

  /**
   * Fetch a MapCache resource, e.g. a WMTS/WMS capabilities document.
   * `path` is the MapCache service path, e.g. `wmts/1.0.0/WMTSCapabilities.xml` or `wms`.
   */
  async getMapcache<T = string>(database: string, path?: string, params?: MapcacheParams): Promise<T> {
    return this.client.request<T>({
      path: this.basePath(database, path),
      method: 'GET',
      query: toQuery(params),
      accept: '*/*',
    });
  }

  /**
   * Build the full URL for a MapCache service path without fetching it.
   * Template placeholders such as `{z}/{x}/{y}` are preserved, so the result
   * can be used directly as a tile URL template in OpenLayers, MapLibre or
   * Leaflet, e.g. `tms/1.0.0/my_schema.my_table@g20/{z}/{x}/{y}.png`.
   *
   * Note that the URL carries no Authorization header — protected tilesets
   * require the map library to send credentials (HTTP Basic) or the layer to
   * be anonymously readable.
   */
  mapcacheUrl(database: string, path?: string, params?: MapcacheParams): string {
    let url = `${this.client.baseUrl}/${this.basePath(database, path)}`;
    const query = toQuery(params);
    if (query) {
      url += `?${new URLSearchParams(query).toString()}`;
    }
    return url;
  }
}
