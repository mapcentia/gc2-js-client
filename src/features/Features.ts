/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse } from '../provisioning/types';

/** A GeoJSON geometry object. Coordinates are lon/lat for EPSG:4326. */
export interface GeoJsonGeometry {
  type: string;
  coordinates?: unknown;
  geometries?: GeoJsonGeometry[];
}

/** A GeoJSON Feature. The primary-key value lives in `properties`. */
export interface GeoJsonFeature<P = Record<string, unknown>> {
  type: 'Feature';
  geometry: GeoJsonGeometry | null;
  properties: P;
  id?: string | number;
}

/** A GeoJSON FeatureCollection. */
export interface GeoJsonFeatureCollection<P = Record<string, unknown>> {
  type: 'FeatureCollection';
  features: GeoJsonFeature<P>[];
}

/** A single primary-key value, or a list of values for multi-feature operations. */
export type FeatureKey = string | number | Array<string | number>;

/** SRID options for feature requests. */
export interface FeatureSrsOptions {
  /** EPSG code (SRID) of the GeoJSON geometry. Defaults to 4326 server-side. */
  srs?: number;
}

/** Options for `patchFeature`. */
export interface PatchFeatureOptions extends FeatureSrsOptions {
  /**
   * Primary-key value to update. When omitted, each feature in the body must
   * carry its primary-key value in `properties`.
   */
  feature?: string | number;
}

function featurePath(schema: string, table: string, feature?: FeatureKey): string {
  const base = `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/features`;
  if (feature === undefined) {
    return base;
  }
  const keys = Array.isArray(feature) ? feature : [feature];
  return `${base}/${keys.map((k) => encodeURIComponent(String(k))).join(',')}`;
}

/**
 * Client for the Feature API (`/api/v4/schemas/{schema}/tables/{table}/features`).
 *
 * Reads and writes table rows as GeoJSON through WFS-T transactions. Read auth,
 * geofence rules and versioning filters are applied by the WFS engine.
 *
 * ```ts
 * const features = new Features(createCentiaClient({ baseUrl, auth }));
 * const feature = await features.getFeature('my_schema', 'my_table', 1);
 * ```
 */
export class Features {
  constructor(private readonly client: CentiaHttpClient) {}

  /**
   * Get one or more features by primary key. A single match returns a bare
   * GeoJSON `Feature`; several matches return a `FeatureCollection`.
   * Throws a 404 `CentiaApiError` when no keys match.
   */
  async getFeature<P = Record<string, unknown>>(
    schema: string,
    table: string,
    feature: FeatureKey,
    options?: FeatureSrsOptions,
  ): Promise<GeoJsonFeature<P> | GeoJsonFeatureCollection<P>> {
    return this.client.request({
      path: featurePath(schema, table, feature),
      method: 'GET',
      query: options?.srs !== undefined ? { srs: String(options.srs) } : undefined,
    });
  }

  /**
   * Insert features from a GeoJSON `Feature` or `FeatureCollection`.
   * A primary-key value in `properties` is used as the new key; otherwise one
   * is generated. The returned location points at the new feature(s).
   */
  async postFeature(
    schema: string,
    table: string,
    body: GeoJsonFeature | GeoJsonFeatureCollection,
    options?: FeatureSrsOptions,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: featurePath(schema, table),
      method: 'POST',
      body,
      query: options?.srs !== undefined ? { srs: String(options.srs) } : undefined,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /**
   * Update features from a GeoJSON `Feature` or `FeatureCollection`. Pass
   * `options.feature` to address a single feature by path; otherwise each
   * feature must carry its primary-key value in `properties`.
   */
  async patchFeature(
    schema: string,
    table: string,
    body: GeoJsonFeature | GeoJsonFeatureCollection,
    options?: PatchFeatureOptions,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: featurePath(schema, table, options?.feature),
      method: 'PATCH',
      body,
      query: options?.srs !== undefined ? { srs: String(options.srs) } : undefined,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /**
   * Delete one or more features by primary key. Keys that match are deleted
   * in one WFS-T transaction; a 404 `CentiaApiError` is thrown only when
   * none of the keys match.
   */
  async deleteFeature(schema: string, table: string, feature: FeatureKey): Promise<void> {
    await this.client.request({
      path: featurePath(schema, table, feature),
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
