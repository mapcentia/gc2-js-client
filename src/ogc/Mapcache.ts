/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/** Query parameters for MapCache requests (e.g. WMS key/values). */
export type MapcacheParams = Record<string, string | number | boolean>;

/** Options scoping a tileset deletion. */
export interface DeleteMapcacheTilesetOptions {
  /** Extent to delete: minx,miny,maxx,maxy in the grid SRS. */
  bbox?: string;
  /** Zoom range to delete: minzoom,maxzoom (or a single zoom). */
  zoom?: string | number;
  /** Grid name (default g20). */
  grid?: string;
}

/** 202 from a scoped delete (bbox and/or zoom): a background mapcache_seed job. */
export interface MapcacheTilesetSeedJob {
  success: boolean;
  mode: 'seed';
  message: string;
  backend: string;
  uuid: string;
  pid: number;
  tileset: string;
  grid: string;
  scope: { bbox: string | null; zoom: string | null };
  _links: { self: string };
}

/** 202 from a full delete on a disk backend: the directory is removed in the background. */
export interface MapcacheTilesetWipeStarted {
  success: boolean;
  mode: 'wipe';
  message: string;
  backend: 'disk';
  uuid: string;
  tileset: string;
}

/** 200 from a full delete that wiped the store synchronously (sqlite/bdb, or the disk fallback). */
export interface MapcacheTilesetWipeCompleted {
  success: boolean;
  mode: 'wipe';
  message: string;
  backend: string;
  tileset: string;
  /** Tiles removed (sqlite), or 1/0 for whether a directory existed (bdb/disk). */
  removed: number;
}

/**
 * Result of deleteMapcacheTileset. Narrow on `mode`, then on `'removed' in result`
 * to tell a completed wipe from one still running in the background.
 */
export type MapcacheTilesetDeleteResult =
  | MapcacheTilesetSeedJob
  | MapcacheTilesetWipeStarted
  | MapcacheTilesetWipeCompleted;

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
   * The endpoint authorizes via the Authorization header (Bearer token or
   * HTTP Basic) — a token cannot be embedded in the URL itself. For protected
   * tilesets, inject the header per tile request through the map library's
   * request hook (e.g. MapLibre's `transformRequest` or OpenLayers'
   * `tileLoadFunction`).
   */
  /**
   * Delete a tileset's cached tiles (optionally scoped by extent and zoom).
   * A scoped delete runs `mapcache_seed -m delete` as a background job (202,
   * `mode: 'seed'`). A full delete wipes the backend store: synchronously
   * for sqlite/bdb (200, `mode: 'wipe'` with `removed`), in the background
   * for disk (202, `mode: 'wipe'` with `uuid`). s3/memcache reject a full
   * delete with 400 `UNSUPPORTED_BACKEND` — a scoped delete works for every
   * backend and is the only way to clear an s3-backed cache.
   *
   * `tileset` is either a layer tileset, "schema.table" (vector variants
   * "schema.table.mvt"/".json"), which needs write on the layer; or a merged
   * per-schema tileset, a bare "schema" or "schema.mvt", which needs a
   * super-user (403 `SUPER_USER_ONLY` otherwise) and an existing schema
   * (404 `SCHEMA_NOT_FOUND`).
   */
  async deleteMapcacheTileset(
    database: string,
    tileset: string,
    options?: DeleteMapcacheTilesetOptions,
  ): Promise<MapcacheTilesetDeleteResult> {
    const query: Record<string, string> = {};
    if (options?.bbox != null) query.bbox = options.bbox;
    if (options?.zoom != null) query.zoom = String(options.zoom);
    if (options?.grid != null) query.grid = options.grid;
    return this.client.request<MapcacheTilesetDeleteResult>({
      path: `api/v4/mapcache/database/${encodeURIComponent(database)}/tileset/${encodeURIComponent(tileset)}`,
      method: 'DELETE',
      query: Object.keys(query).length > 0 ? query : undefined,
      expectedStatus: [200, 202],
    });
  }

  mapcacheUrl(database: string, path?: string, params?: MapcacheParams): string {
    let url = `${this.client.baseUrl}/${this.basePath(database, path)}`;
    const query = toQuery(params);
    if (query) {
      url += `?${new URLSearchParams(query).toString()}`;
    }
    return url;
  }
}
