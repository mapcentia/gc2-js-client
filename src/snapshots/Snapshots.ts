/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/** Status of a snapshot job. */
export type SnapshotStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'superseded';

/** A request to snapshot a table or view to Parquet on S3. */
export interface SnapshotRequest {
  /** Schema of the relation. */
  schema: string;
  /** Table or view name. */
  relation: string;
  /** Optional EPSG code to reproject to. Omit to keep the native SRID. */
  srs?: number;
}

/** 202 response from postSnapshot; poll `_links.self` (or getSnapshot) for status. */
export interface SnapshotAccepted {
  id: string;
  status: 'pending';
  _links: { self: string };
}

/** One column of the relation at snapshot time. */
export interface SnapshotColumn {
  column_name: string;
  data_type: string;
}

/** Status of a snapshot job. */
export interface SnapshotJob {
  id: string;
  schema: string;
  relation: string;
  srs: number | null;
  status: SnapshotStatus;
  /** UTC date the export ran; the {date} segment of the relation snapshot read API. */
  snapshot_date: string | null;
  s3_path: string | null;
  row_count: number | null;
  /** md5 fingerprint of relation_schema, for drift detection. */
  schema_version: string | null;
  relation_schema: SnapshotColumn[] | null;
  error: string | null;
  username: string;
  created: string;
  started: string | null;
  finished: string | null;
}

/** One file of a published snapshot. */
export interface RelationSnapshotFile {
  name: string;
  size_bytes: number;
  href: string;
}

/** A published snapshot of a relation, as returned by the list endpoint. */
export interface RelationSnapshot {
  snapshot_date: string;
  snapshot_id: string;
  row_count: number;
  size_bytes: number;
  schema_version: string;
  files: RelationSnapshotFile[];
  published: string;
}

/** One published snapshot with full metadata, as returned by the single-date endpoint. */
export interface RelationSnapshotDetails extends RelationSnapshot {
  srs: number | null;
  relation_schema: SnapshotColumn[] | null;
  crs: string | null;
  _links: { data: string; files: { name: string; href: string }[] };
}

/** Filters for getSnapshots. */
export interface GetSnapshotsOptions {
  schema?: string;
  relation?: string;
}

/** Polling options for waitForSnapshot. */
export interface WaitForSnapshotOptions {
  /** Milliseconds between polls. Default 2000. */
  intervalMs?: number;
  /** Give up after this many milliseconds. Default 300000 (5 minutes). */
  timeoutMs?: number;
}

/** Options for the snapshot data/file download methods. */
export interface SnapshotDataOptions {
  /** Inclusive byte range to request, e.g. `[0, 1023]` for the first KiB. */
  range?: [number, number];
}

/**
 * Client for the snapshot API: GeoParquet exports of a relation.
 *
 * The job API (`/api/v4/snapshots`) queues and inspects exports and is
 * super-user only; exports run asynchronously — poll with `getSnapshot` or
 * use `waitForSnapshot`. The read API
 * (`/api/v4/schemas/{schema}/relations/{relation}/snapshots`) serves the
 * published snapshots to any user with read access to the relation, with
 * HEAD + byte-range support so Parquet readers can fetch footers and row
 * groups selectively.
 *
 * ```ts
 * const snapshots = new Snapshots(createCentiaClient({ baseUrl, auth }));
 * const { id } = await snapshots.postSnapshot({ schema: 'geodanmark', relation: 'bygning' });
 * const done = await snapshots.waitForSnapshot(id);
 * ```
 */
export class Snapshots {
  constructor(private readonly client: CentiaHttpClient) {}

  private relationPath(schema: string, relation: string, rest = ''): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/relations/${encodeURIComponent(relation)}/snapshots${rest}`;
  }

  /**
   * Queue Parquet snapshots of one or more tables or views (an array returns
   * an array, in request order; all-or-nothing). Returns 202 with the job
   * id(s). Throws `CentiaApiError`: 400 (duplicates or an empty list),
   * 403 (super-user only), 404 (relation not found), 409 (a snapshot of a
   * relation is already pending or running), 501 (storage not configured).
   */
  async postSnapshot(body: SnapshotRequest): Promise<SnapshotAccepted>;
  async postSnapshot(body: SnapshotRequest[]): Promise<SnapshotAccepted[]>;
  async postSnapshot(body: SnapshotRequest | SnapshotRequest[]): Promise<SnapshotAccepted | SnapshotAccepted[]> {
    return this.client.request({
      path: 'api/v4/snapshots',
      method: 'POST',
      body,
      expectedStatus: 202,
    });
  }

  /**
   * Get one snapshot job by id, or several (an array returns an array).
   * Throws a 404 `CentiaApiError` when any id is unknown. Super-user only.
   */
  async getSnapshot(id: string): Promise<SnapshotJob>;
  async getSnapshot(ids: string[]): Promise<SnapshotJob[]>;
  async getSnapshot(id: string | string[]): Promise<SnapshotJob | SnapshotJob[]> {
    const keys = Array.isArray(id) ? id : [id];
    return this.client.request({
      path: `api/v4/snapshots/${keys.map((k) => encodeURIComponent(k)).join(',')}`,
      method: 'GET',
    });
  }

  /** List the newest snapshot jobs (50), optionally filtered by schema/relation. Super-user only. */
  async getSnapshots(options?: GetSnapshotsOptions): Promise<SnapshotJob[]> {
    const query: Record<string, string> = {};
    if (options?.schema !== undefined) query.schema = options.schema;
    if (options?.relation !== undefined) query.relation = options.relation;
    return this.client.request({
      path: 'api/v4/snapshots',
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  /**
   * Poll a snapshot job until it reaches a terminal status (succeeded, failed
   * or superseded) and return it — check `status`/`error` on the result.
   * Throws an `Error` when `timeoutMs` elapses first.
   */
  async waitForSnapshot(id: string, options?: WaitForSnapshotOptions): Promise<SnapshotJob> {
    const intervalMs = options?.intervalMs ?? 2000;
    const timeoutMs = options?.timeoutMs ?? 300000;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const job = await this.getSnapshot(id);
      if (job.status === 'succeeded' || job.status === 'failed' || job.status === 'superseded') {
        return job;
      }
      if (Date.now() + intervalMs > deadline) {
        throw new Error(`Timed out after ${timeoutMs} ms waiting for snapshot ${id} (status: ${job.status})`);
      }
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  /** List the published snapshots of a relation, newest first. */
  async getRelationSnapshots(schema: string, relation: string): Promise<RelationSnapshot[]> {
    return this.client.request({
      path: this.relationPath(schema, relation),
      method: 'GET',
    });
  }

  /** Get one published snapshot (metadata) by date (`YYYY-MM-DD`). */
  async getRelationSnapshot(schema: string, relation: string, date: string): Promise<RelationSnapshotDetails> {
    return this.client.request({
      path: this.relationPath(schema, relation, `/${encodeURIComponent(date)}`),
      method: 'GET',
    });
  }

  /**
   * Absolute URL of the snapshot's Parquet file, without fetching it — for
   * DuckDB/GDAL or a plain fetch. Authorization travels in the request
   * header, so protected relations need the caller to attach the token.
   */
  getRelationSnapshotDataUrl(schema: string, relation: string, date: string): string {
    return `${this.client.baseUrl}/${this.relationPath(schema, relation, `/${encodeURIComponent(date)}/data`)}`;
  }

  /**
   * Fetch the snapshot's Parquet file and return the raw `Response` (stream
   * or buffer it yourself). Follows the 302 redirect the server answers in
   * redirect mode. Pass `range` for a single byte range (206). Throws
   * `CentiaApiError`: 403, 404, 409 (several files; use
   * getRelationSnapshotFile), 416, 502.
   */
  async getRelationSnapshotData(
    schema: string,
    relation: string,
    date: string,
    options?: SnapshotDataOptions,
  ): Promise<Response> {
    return this.rawGet(this.relationPath(schema, relation, `/${encodeURIComponent(date)}/data`), 'GET', options);
  }

  /** HEAD request for the snapshot's Parquet file — Content-Length, Accept-Ranges and ETag without the body. */
  async headRelationSnapshotData(schema: string, relation: string, date: string): Promise<Response> {
    return this.rawGet(this.relationPath(schema, relation, `/${encodeURIComponent(date)}/data`), 'HEAD');
  }

  /**
   * Fetch one file of the snapshot by catalog name (`data-<id>.parquet`,
   * `metadata-<id>.json`). Same redirect/range semantics as
   * getRelationSnapshotData.
   */
  async getRelationSnapshotFile(
    schema: string,
    relation: string,
    date: string,
    file: string,
    options?: SnapshotDataOptions,
  ): Promise<Response> {
    return this.rawGet(
      this.relationPath(schema, relation, `/${encodeURIComponent(date)}/files/${encodeURIComponent(file)}`),
      'GET',
      options,
    );
  }

  /** HEAD request for one file of the snapshot. */
  async headRelationSnapshotFile(schema: string, relation: string, date: string, file: string): Promise<Response> {
    return this.rawGet(
      this.relationPath(schema, relation, `/${encodeURIComponent(date)}/files/${encodeURIComponent(file)}`),
      'HEAD',
    );
  }

  private async rawGet(path: string, method: 'GET' | 'HEAD', options?: SnapshotDataOptions): Promise<Response> {
    const headers: Record<string, string> = {};
    if (options?.range) {
      headers['Range'] = `bytes=${options.range[0]}-${options.range[1]}`;
    }
    return this.client.requestRaw({
      path,
      method,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
      expectedStatus: [200, 206],
    });
  }
}
