/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

/** Status of a seed job. */
export type SeedJobStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'cancelled';

/**
 * A seed job to queue. Every other field is server-owned and rejected
 * with 400 if sent. String fields are limited to 255 characters.
 */
export interface SeedJobInput {
  /** The mapcache tileset (layer key), e.g. "myschema.roads". */
  tileset: string;
  /**
   * One of the grids this tileset declares in the database's mapcache
   * config — GC2 generates one called `g20` for every tileset. Any other
   * name is 400 `UNKNOWN_GRID`, and the message lists the tileset's grids,
   * so it is worth showing to the user. This is the grid's name, not its
   * title: `GoogleMapsCompatible`, seen in capabilities documents, is the
   * title of `g20` and is rejected.
   */
  grid: string;
  /** Must lie within the grid's zoom levels; out of range is 400 with the valid range in the message. */
  zoom_start: number;
  /** Must lie within the grid's zoom levels. */
  zoom_end: number;
  /** Optional label for the job. Defaults to `tileset` when omitted. */
  name?: string;
  /**
   * Relation whose features bound the seeded area. Must be a registered
   * layer the caller can read: 403 `INSUFFICIENT_PRIVILEGES` otherwise, or
   * 404 if the relation does not exist.
   */
  extent_layer?: string | null;
  threads?: number;
}

/**
 * A seed job as returned by the API. `tileset`, `grid`, `zoom_start`,
 * `zoom_end`, `threads`, `status` and `username` are null only for legacy
 * rows written before v4.
 */
export interface SeedJob {
  uuid: string;
  name: string;
  status: SeedJobStatus | null;
  /** Computed: running, but no heartbeat for 10 minutes, so the run or its node is gone. */
  stale: boolean;
  username: string | null;
  tileset: string | null;
  grid: string | null;
  zoom_start: number | null;
  zoom_end: number | null;
  extent_layer: string | null;
  threads: number | null;
  /** The node that claimed the job. */
  host: string | null;
  pid: number | null;
  created: string;
  started: string | null;
  finished: string | null;
  heartbeat: string | null;
  cancel_requested: string | null;
  error: string | null;
  /** The tail of the seed output. Only present on getSeedJob — the list omits it. */
  log?: string | null;
  _links: { self: string };
}

/** Filters for getSeedJobs. */
export interface GetSeedJobsOptions {
  status?: SeedJobStatus;
  tileset?: string;
}

/** 202 from deleteSeedJob: at least one job was running and its worker will finish the cancel. */
export interface SeedJobStopping {
  success: boolean;
  message: string;
  uuid: string[];
  /** The stopping job(s), for polling until the worker has acted. */
  _links: { self: string };
}

function uuidsPath(uuid: string | string[]): string {
  const keys = Array.isArray(uuid) ? uuid : [uuid];
  return keys.map((k) => encodeURIComponent(k)).join(',');
}

/**
 * Client for the tile seeder (`/api/v4/tileseeder/jobs`): queued jobs that
 * pre-render a mapcache tileset. Open to sub-users; queueing requires
 * write/owner on the tileset's relation. A sub-user sees its own jobs, a
 * super-user every job of the database.
 *
 * Jobs are asynchronous — poll getSeedJob until `status` is succeeded,
 * failed or cancelled.
 *
 * ```ts
 * const tileseeder = new Tileseeder(createCentiaClient({ baseUrl, auth }));
 * const job = await tileseeder.postSeedJob({ tileset: 'myschema.roads', grid: 'g20', zoom_start: 0, zoom_end: 12 });
 * const current = await tileseeder.getSeedJob(job.uuid);
 * ```
 */
export class Tileseeder {
  constructor(private readonly client: CentiaHttpClient) {}

  /**
   * Queue one seed job, or several (an array returns an array). Every job is
   * validated and authorized before any is queued. Throws `CentiaApiError`:
   * 400 (malformed body, empty list, invalid field), 403 (no write access to
   * the tileset), 404 with code `TILESET_NOT_FOUND` (the tileset is not in
   * the database's mapcache config) or `NOT_FOUND` (the database has no
   * mapcache config at all), 429 (too many pending jobs).
   */
  async postSeedJob(body: SeedJobInput): Promise<SeedJob>;
  async postSeedJob(body: SeedJobInput[]): Promise<SeedJob[]>;
  async postSeedJob(body: SeedJobInput | SeedJobInput[]): Promise<SeedJob | SeedJob[]> {
    return this.client.request({
      path: 'api/v4/tileseeder/jobs',
      method: 'POST',
      body,
      expectedStatus: 202,
    });
  }

  /** The caller's seed jobs, newest first, without the log. */
  async getSeedJobs(options?: GetSeedJobsOptions): Promise<SeedJob[]> {
    const query: Record<string, string> = {};
    if (options?.status !== undefined) query.status = options.status;
    if (options?.tileset !== undefined) query.tileset = options.tileset;
    return this.client.request({
      path: 'api/v4/tileseeder/jobs',
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  /**
   * One seed job with its log tail, or several (an array returns an array).
   * Throws `CentiaApiError`: 400 (malformed uuid), 404 (unknown uuid).
   */
  async getSeedJob(uuid: string): Promise<SeedJob>;
  async getSeedJob(uuids: string[]): Promise<SeedJob[]>;
  async getSeedJob(uuid: string | string[]): Promise<SeedJob | SeedJob[]> {
    return this.client.request({
      path: `api/v4/tileseeder/jobs/${uuidsPath(uuid)}`,
      method: 'GET',
    });
  }

  /**
   * Ask one or more seed jobs to stop. Resolves to `null` when every job was
   * still queued (cancelled outright) or already finished (204), or to the
   * stopping info when at least one was running and its worker has to act
   * (202). After a 202 the job is not stopped yet — poll getSeedJob until its
   * status is cancelled. Every uuid is checked before anything is written.
   * Throws 400 (malformed uuid) or 404 (unknown uuid).
   */
  async deleteSeedJob(uuid: string | string[]): Promise<SeedJobStopping | null> {
    return this.client.request({
      path: `api/v4/tileseeder/jobs/${uuidsPath(uuid)}`,
      method: 'DELETE',
      expectedStatus: [202, 204],
    });
  }
}
