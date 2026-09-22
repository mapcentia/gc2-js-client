/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse } from '../provisioning/types';
import type { SnapshotFormat } from '../snapshots/Snapshots';

/** Status of a scheduler run. */
export type SchedulerRunStatus = 'running' | 'succeeded' | 'failed' | 'skipped' | 'lost';

/** Body for creating a scheduler job. Server defaults: epsg 4326, type "AUTO", encoding "UTF8", delete_append false, download_schema true, active true, snapshot false. */
export interface SchedulerJobInput {
  name: string;
  schema: string;
  url: string;
  /** 5-field cron expression, e.g. "0 3 * * *". */
  schedule: string;
  epsg?: number;
  type?: string;
  encoding?: string;
  extra?: string | null;
  delete_append?: boolean;
  download_schema?: boolean;
  presql?: string | null;
  postsql?: string | null;
  active?: boolean;
  snapshot?: boolean;
  /**
   * Formats of the snapshot queued after a successful import when
   * `snapshot` is true. `null` (the default) means the server default;
   * must otherwise be non-empty and free of duplicates. A PATCH with an
   * explicit `null` resets to the default.
   */
  snapshot_formats?: SnapshotFormat[] | null;
}

/** Partial update of a scheduler job. */
export type PatchSchedulerJobRequest = Partial<SchedulerJobInput>;

/** A scheduler job as returned by the API. */
export interface SchedulerJob {
  id: number;
  name: string;
  schema: string;
  url: string;
  /** 5-field cron expression. */
  schedule: string;
  epsg: number | null;
  type: string;
  encoding: string;
  extra: string | null;
  delete_append: boolean;
  download_schema: boolean;
  presql: string | null;
  postsql: string | null;
  active: boolean;
  snapshot: boolean;
  /** Formats of the snapshot queued after a successful import; null means the server default. */
  snapshot_formats: SnapshotFormat[] | null;
  lastcheck: boolean | null;
  lasttimestamp: string | null;
  lastrun: string | null;
  report: Record<string, unknown> | null;
}

/** 201 response info from postSchedulerJob: the Location header and the ids parsed from it. */
export interface SchedulerJobsCreated extends LocationResponse {
  ids: number[];
}

/** One run of a scheduler job. */
export interface SchedulerRun {
  uuid: string;
  job: number;
  name: string | null;
  pid: number;
  host: string | null;
  slot: number | null;
  status: SchedulerRunStatus;
  stale: boolean;
  started_at: string;
  heartbeat: string | null;
  finished_at: string | null;
  exit_reason: string | null;
  /**
   * The run's stdout (Info/Warning/Error lines), updated at every heartbeat
   * while running and complete on finish. Capped at 1 MB with the tail kept
   * (first line says so when truncated). Only present on getSchedulerRun —
   * the getSchedulerRuns list omits it.
   */
  log?: string | null;
}

/** Body for starting a run. */
export interface PostSchedulerRunRequest {
  job: number;
  /** Ignore delete_append and overwrite. */
  force?: boolean;
}

/** 202 response from postSchedulerRun. */
export interface SchedulerRunAccepted {
  job: number;
  status: 'starting';
  _links: { runs: string };
}

/** 200 response from deleteSchedulerRun. The server escalates SIGINT to SIGKILL after 30 s. */
export interface SchedulerRunStopped {
  uuid: string;
  signal: string;
}

/** Filters for getSchedulerRuns. */
export interface GetSchedulerRunsOptions {
  job?: number;
  status?: SchedulerRunStatus;
}

function idsPath(id: number | number[]): string {
  const keys = Array.isArray(id) ? id : [id];
  return keys.map((k) => encodeURIComponent(String(k))).join(',');
}

/**
 * Client for the scheduler API (`/api/v4/scheduler`). Super-user only.
 *
 * Jobs describe recurring data imports (cron-scheduled); runs are their
 * executions. Starting a run is asynchronous — poll `getSchedulerRuns`
 * (the `_links.runs` of the 202) until the run finishes.
 *
 * ```ts
 * const scheduler = new Scheduler(createCentiaClient({ baseUrl, auth }));
 * const { ids } = await scheduler.postSchedulerJob({ name, schema, url, schedule: '0 3 * * *' });
 * await scheduler.postSchedulerRun({ job: ids[0] });
 * ```
 */
export class Scheduler {
  constructor(private readonly client: CentiaHttpClient) {}

  /** List all scheduler jobs. */
  async getSchedulerJobs(): Promise<SchedulerJob[]> {
    return this.client.request({
      path: 'api/v4/scheduler/jobs',
      method: 'GET',
    });
  }

  /**
   * Get one job by id, or several (an array returns an array). Throws a 404
   * `CentiaApiError` when any id is unknown.
   */
  async getSchedulerJob(id: number): Promise<SchedulerJob>;
  async getSchedulerJob(ids: number[]): Promise<SchedulerJob[]>;
  async getSchedulerJob(id: number | number[]): Promise<SchedulerJob | SchedulerJob[]> {
    return this.client.request({
      path: `api/v4/scheduler/jobs/${idsPath(id)}`,
      method: 'GET',
    });
  }

  /**
   * Create one or more jobs (201; all-or-nothing for arrays). Returns the
   * Location header and the new ids parsed from it, in request order.
   */
  async postSchedulerJob(body: SchedulerJobInput | SchedulerJobInput[]): Promise<SchedulerJobsCreated> {
    const res = await this.client.requestFull({
      path: 'api/v4/scheduler/jobs',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    const location = res.getHeader('Location') ?? '';
    const last = location.split('/').pop() ?? '';
    const ids = last
      .split(',')
      .map((s) => Number(s))
      .filter((n) => Number.isFinite(n));
    return { location, ids };
  }

  /** Partially update a job (303 + Location). */
  async patchSchedulerJob(id: number, body: PatchSchedulerJobRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/scheduler/jobs/${idsPath(id)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /**
   * Delete one or more jobs (204). Nothing is deleted if any id fails:
   * throws 404 (unknown id) or 409 (a run is in progress).
   */
  async deleteSchedulerJob(id: number | number[]): Promise<void> {
    await this.client.request({
      path: `api/v4/scheduler/jobs/${idsPath(id)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }

  /** List runs (running plus the newest 50 finished), optionally filtered by job and status. */
  async getSchedulerRuns(options?: GetSchedulerRunsOptions): Promise<SchedulerRun[]> {
    const query: Record<string, string> = {};
    if (options?.job !== undefined) query.job = String(options.job);
    if (options?.status !== undefined) query.status = options.status;
    return this.client.request({
      path: 'api/v4/scheduler/runs',
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  /** Get one run by uuid. */
  async getSchedulerRun(uuid: string): Promise<SchedulerRun> {
    return this.client.request({
      path: `api/v4/scheduler/runs/${encodeURIComponent(uuid)}`,
      method: 'GET',
    });
  }

  /**
   * Start a run of a job (202). Throws 404 (unknown job) or 409 (a run of
   * the job is already running).
   */
  async postSchedulerRun(body: PostSchedulerRunRequest): Promise<SchedulerRunAccepted> {
    return this.client.request({
      path: 'api/v4/scheduler/runs',
      method: 'POST',
      body,
      expectedStatus: 202,
    });
  }

  /**
   * Stop a running run: sends SIGINT, which the server escalates to SIGKILL
   * after 30 s — the request itself can take up to ~30 s, so do not use a
   * short timeout. Throws 404 (no running run with that uuid) or 409 (the
   * run is on another host).
   */
  async deleteSchedulerRun(uuid: string): Promise<SchedulerRunStopped> {
    return this.client.request({
      path: `api/v4/scheduler/runs/${encodeURIComponent(uuid)}`,
      method: 'DELETE',
    });
  }
}
