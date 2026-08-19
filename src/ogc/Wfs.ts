/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/** Query parameters for WFS GET requests. Extra vendor parameters are allowed. */
export interface WfsGetParams {
  /** OGC service. Defaults to `WFS`. */
  SERVICE?: string;
  /** WFS operation. */
  REQUEST: 'GetCapabilities' | 'DescribeFeatureType' | 'GetFeature';
  /** WFS protocol version. */
  VERSION?: '1.0.0' | '1.1.0';
  /** Feature type (table) name(s), comma-separated. */
  TYPENAME?: string;
  /** Output format, e.g. `gml3`. */
  OUTPUTFORMAT?: string;
  /** Requested output CRS, e.g. `urn:ogc:def:crs:EPSG::25832`. */
  SRSNAME?: string;
  /** Bounding-box filter (minx,miny,maxx,maxy). */
  BBOX?: string;
  /** Maximum number of features to return. */
  MAXFEATURES?: number;
  /** OGC Filter Encoding XML. */
  FILTER?: string;
  [key: string]: string | number | boolean | undefined;
}

/** Optional path segments for WFS requests. */
export interface WfsPathOptions {
  /** Output EPSG code (SRID). */
  srs?: number;
  /** Version time slice (ISO date) for versioned layers. Requires `srs`. */
  timeSlice?: string;
}

function wfsPath(base: string, options?: WfsPathOptions): string {
  let path = base;
  if (options?.timeSlice != null && options.srs == null) {
    throw new Error('timeSlice requires srs to be set');
  }
  if (options?.srs != null) {
    path += `/srs/${encodeURIComponent(options.srs)}`;
    if (options.timeSlice != null) {
      path += `/ts/${encodeURIComponent(options.timeSlice)}`;
    }
  }
  return path;
}

function toQuery(params: WfsGetParams): Record<string, string> {
  const query: Record<string, string> = { SERVICE: 'WFS' };
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      query[key] = String(value);
    }
  }
  return query;
}

/**
 * WFS endpoint wrapper (GetCapabilities, DescribeFeatureType, GetFeature and
 * WFS-T transactions).
 *
 * The endpoint accepts Bearer token, HTTP Basic and anonymous requests. A
 * Bearer token must match the `database` in the path; protected layers
 * challenge token-less requests with HTTP Basic auth, and transactions on a
 * protected layer require credentials. Responses are returned as XML text.
 */
export class Wfs {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string, database: string): string {
    return `api/v4/wfs/schema/${encodeURIComponent(schema)}/database/${encodeURIComponent(database)}`;
  }

  /** WFS GET. */
  async getWfs(
    schema: string,
    database: string,
    params: WfsGetParams,
    options?: WfsPathOptions,
  ): Promise<string> {
    return this.client.request<string>({
      path: wfsPath(this.basePath(schema, database), options),
      method: 'GET',
      query: toQuery(params),
      accept: 'text/xml',
    });
  }

  /** WFS POST (XML-encoded GetFeature or Transaction). */
  async postWfs(
    schema: string,
    database: string,
    xml: string,
    options?: WfsPathOptions,
  ): Promise<string> {
    return this.client.request<string>({
      path: wfsPath(this.basePath(schema, database), options),
      method: 'POST',
      body: xml,
      contentType: 'text/xml',
      accept: 'text/xml',
    });
  }
}
