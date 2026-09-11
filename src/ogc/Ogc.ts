/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { GeoJsonFeature, GeoJsonFeatureCollection } from '../features/Features';

/** Default CRS of the OGC API: WGS 84 in longitude/latitude order. */
export const OGC_CRS84 = 'http://www.opengis.net/def/crs/OGC/1.3/CRS84';

/**
 * CRS URI for an EPSG code, e.g. `ogcEpsgCrs(25832)`. Note that
 * `ogcEpsgCrs(4326)` is latitude/longitude order; use `OGC_CRS84` for lon/lat.
 */
export function ogcEpsgCrs(epsg: number): string {
  return `http://www.opengis.net/def/crs/EPSG/0/${epsg}`;
}

/** A link object as used throughout the OGC API. */
export interface OgcLink {
  rel: string;
  href: string;
  type?: string;
  title?: string;
}

/** The landing page of a database's OGC API. */
export interface OgcLandingPage {
  title: string;
  description?: string;
  links: OgcLink[];
}

/** Conformance classes implemented by the server. */
export interface OgcConformance {
  conformsTo: string[];
}

/** Spatial and temporal extent of a collection. */
export interface OgcExtent {
  spatial?: { bbox: number[][]; crs?: string };
  temporal?: { interval: Array<Array<string | null>>; trs?: string };
}

/** One collection (an OWS-enabled layer, id = `schema.table`). */
export interface OgcCollection {
  id: string;
  title?: string;
  description?: string;
  /** `feature` for vector layers; absent for raster layers (map only). */
  itemType?: string;
  extent?: OgcExtent;
  /** CRS URIs accepted by `crs`/`bbox-crs`. */
  crs?: string[];
  storageCrs?: string;
  links: OgcLink[];
}

/** A page of collections. */
export interface OgcCollections {
  links: OgcLink[];
  numberMatched: number;
  numberReturned: number;
  collections: OgcCollection[];
}

/** A GeoJSON Feature as returned by the OGC API (with links on single items). */
export interface OgcFeature<P = Record<string, unknown>> extends GeoJsonFeature<P> {
  links?: OgcLink[];
}

/** A GeoJSON FeatureCollection page as returned by `/items`. */
export interface OgcFeatureCollection<P = Record<string, unknown>> extends GeoJsonFeatureCollection<P> {
  features: OgcFeature<P>[];
  numberMatched?: number;
  numberReturned: number;
  timeStamp?: string;
  links: OgcLink[];
}

/** Options for `getCollections`. */
export interface OgcCollectionsOptions {
  /** Page size (default 100, max 1000). */
  limit?: number;
  /** Collections to skip. */
  offset?: number;
}

/** A bounding box: `[minx, miny, maxx, maxy]` in the axis order of its CRS, or the same as a comma-separated string. */
export type OgcBbox = [number, number, number, number] | number[] | string;

/** Options shared by items and map requests. */
export interface OgcSpatialOptions {
  /** Bounding box in the axis order of `bboxCrs` (default CRS84 = lon/lat). */
  bbox?: OgcBbox;
  /** CRS URI of `bbox`. Defaults to CRS84. */
  bboxCrs?: string;
  /** Output CRS URI from the collection's `crs` list. Defaults to CRS84. */
  crs?: string;
  /**
   * ISO 8601 instant. On a versioned layer, the version valid at that time;
   * ignored on other layers. Intervals are not supported.
   */
  datetime?: string;
}

/** Options for `getItems`. */
export interface OgcItemsOptions extends OgcSpatialOptions {
  /** Page size (default 10, max 10000). */
  limit?: number;
  /** Features to skip. */
  offset?: number;
}

/** Options for `getItem`. */
export interface OgcItemOptions {
  crs?: string;
  datetime?: string;
}

/** Options for map URLs. */
export interface OgcMapOptions extends OgcSpatialOptions {
  /** Image width in pixels (max 16384). */
  width?: number;
  /** Image height in pixels (max 16384). Missing dimensions follow the bbox aspect ratio. */
  height?: number;
  /** `png` (default, transparent) or `jpeg` (opaque). */
  format?: 'png' | 'jpeg';
  transparent?: boolean;
  /** Background colour as `0xRRGGBB`. */
  bgcolor?: string;
}

function bboxToString(bbox: OgcBbox): string {
  return typeof bbox === 'string' ? bbox : bbox.join(',');
}

function spatialQuery(options?: OgcSpatialOptions): Record<string, string> {
  const query: Record<string, string> = {};
  if (options?.bbox !== undefined) query.bbox = bboxToString(options.bbox);
  if (options?.bboxCrs !== undefined) query['bbox-crs'] = options.bboxCrs;
  if (options?.crs !== undefined) query.crs = options.crs;
  if (options?.datetime !== undefined) query.datetime = options.datetime;
  return query;
}

function nonEmpty(query: Record<string, string>): Record<string, string> | undefined {
  return Object.keys(query).length > 0 ? query : undefined;
}

/**
 * OGC API Features (Part 1 Core, Part 2 CRS) and OGC API Maps (Part 1 Core)
 * wrapper for `/api/v4/ogc/database/{database}`.
 *
 * The endpoints accept Bearer token, HTTP Basic and anonymous requests. A
 * Bearer token must match the `database` in the path. Anonymous callers read
 * layers below `Read/write`; a `Read/write` collection answers 401 (Basic
 * challenge) for anonymous callers and 403 for identities without privilege.
 * Geofence rules, versioning and workflow are applied server-side.
 *
 * Map images cannot be fetched through this client; use `mapUrl` /
 * `datasetMapUrl` to build image URLs for `<img>` tags or map libraries.
 *
 * ```ts
 * const ogc = new Ogc(createCentiaClient({ baseUrl, auth }));
 * const page = await ogc.getItems('my_database', 'my_schema.roads', { bbox: [9, 55, 10, 56], limit: 100 });
 * ```
 */
export class Ogc {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(database: string): string {
    return `api/v4/ogc/database/${encodeURIComponent(database)}`;
  }

  private collectionPath(database: string, collectionId: string): string {
    return `${this.basePath(database)}/collections/${encodeURIComponent(collectionId)}`;
  }

  /** The landing page with links to conformance, collections and the OpenAPI document. */
  async getLandingPage(database: string): Promise<OgcLandingPage> {
    return this.client.request<OgcLandingPage>({ path: this.basePath(database), method: 'GET' });
  }

  /** Conformance classes implemented by the server. */
  async getConformance(database: string): Promise<OgcConformance> {
    return this.client.request<OgcConformance>({ path: `${this.basePath(database)}/conformance`, method: 'GET' });
  }

  /** The collections (OWS-enabled layers) the caller may read, paged. */
  async getCollections(database: string, options?: OgcCollectionsOptions): Promise<OgcCollections> {
    const query: Record<string, string> = {};
    if (options?.limit !== undefined) query.limit = String(options.limit);
    if (options?.offset !== undefined) query.offset = String(options.offset);
    return this.client.request<OgcCollections>({
      path: `${this.basePath(database)}/collections`,
      method: 'GET',
      query: nonEmpty(query),
    });
  }

  /**
   * One collection. Throws a `CentiaApiError` with status 404 (unknown),
   * 401 (anonymous caller, credentials required) or 403 (no privilege).
   */
  async getCollection(database: string, collectionId: string): Promise<OgcCollection> {
    return this.client.request<OgcCollection>({ path: this.collectionPath(database, collectionId), method: 'GET' });
  }

  /**
   * Features of a collection as a GeoJSON FeatureCollection page. The default
   * page size is 10; follow `links` with `rel: 'next'` or pass `offset`.
   */
  async getItems<P = Record<string, unknown>>(
    database: string,
    collectionId: string,
    options?: OgcItemsOptions,
  ): Promise<OgcFeatureCollection<P>> {
    const query: Record<string, string> = {};
    if (options?.limit !== undefined) query.limit = String(options.limit);
    if (options?.offset !== undefined) query.offset = String(options.offset);
    Object.assign(query, spatialQuery(options));
    return this.client.request<OgcFeatureCollection<P>>({
      path: `${this.collectionPath(database, collectionId)}/items`,
      method: 'GET',
      query: nonEmpty(query),
      accept: 'application/geo+json',
    });
  }

  /** One feature by primary key. Throws a 404 `CentiaApiError` when it does not exist. */
  async getItem<P = Record<string, unknown>>(
    database: string,
    collectionId: string,
    featureId: string | number,
    options?: OgcItemOptions,
  ): Promise<OgcFeature<P>> {
    const query: Record<string, string> = {};
    if (options?.crs !== undefined) query.crs = options.crs;
    if (options?.datetime !== undefined) query.datetime = options.datetime;
    return this.client.request<OgcFeature<P>>({
      path: `${this.collectionPath(database, collectionId)}/items/${encodeURIComponent(String(featureId))}`,
      method: 'GET',
      query: nonEmpty(query),
      accept: 'application/geo+json',
    });
  }

  /**
   * URL of a rendered map of one collection (PNG/JPEG), without fetching it.
   * Authorization travels in the `Authorization` header, so for protected
   * collections fetch the image with the header set (or use Basic auth).
   */
  mapUrl(database: string, collectionId: string, options?: OgcMapOptions): string {
    return this.buildUrl(`${this.collectionPath(database, collectionId)}/map`, this.mapQuery(options));
  }

  /** URL of a rendered map of several collections of the same schema. */
  datasetMapUrl(database: string, collections: string[], options?: OgcMapOptions): string {
    const query = { collections: collections.join(','), ...this.mapQuery(options) };
    return this.buildUrl(`${this.basePath(database)}/map`, query);
  }

  private mapQuery(options?: OgcMapOptions): Record<string, string> {
    const query = spatialQuery(options);
    if (options?.width !== undefined) query.width = String(options.width);
    if (options?.height !== undefined) query.height = String(options.height);
    if (options?.format !== undefined) query.f = options.format;
    if (options?.transparent !== undefined) query.transparent = String(options.transparent);
    if (options?.bgcolor !== undefined) query.bgcolor = options.bgcolor;
    return query;
  }

  private buildUrl(path: string, query: Record<string, string>): string {
    let url = `${this.client.baseUrl}/${path}`;
    if (Object.keys(query).length > 0) {
      url += `?${new URLSearchParams(query).toString()}`;
    }
    return url;
  }
}
