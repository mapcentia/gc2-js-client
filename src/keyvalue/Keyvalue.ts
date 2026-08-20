/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse } from '../provisioning/types';

/** A stored key/value entry. */
export interface KeyvalueEntry<T = unknown> {
  id: number;
  key: string;
  /** The stored JSON value, returned decoded. */
  value: T;
  /** Screen name of the owning user; null for legacy keys created without an owner. */
  owner: string | null;
  /** When true the key is readable by any user in the database. */
  public: boolean;
}

/** Body for creating a key. `owner` is always set server-side from the JWT and cannot be sent. */
export interface CreateKeyvalueRequest<T = unknown> {
  value: T;
  public?: boolean;
}

/** Partial update of a key's value and/or public flag. */
export interface PatchKeyvalueRequest<T = unknown> {
  value?: T;
  public?: boolean;
}

/** Result of a paths-projected GET: only the requested sub-trees, keyed by each path string. */
export interface KeyvalueProjection {
  value: Record<string, unknown>;
}

/**
 * Client for the key/value store (`/api/v4/keyvalue`).
 *
 * Keys are globally unique. Super users have full CRUD on all keys; sub-users
 * can read their own keys plus all public keys, and can only modify their own.
 *
 * ```ts
 * const kv = new Keyvalue(createCentiaClient({ baseUrl, auth }));
 * await kv.postKeyvalue('settings', { value: { theme: 'dark' } });
 * const entry = await kv.getKeyvalue('settings');
 * ```
 */
export class Keyvalue {
  constructor(private readonly client: CentiaHttpClient) {}

  async getKeyvalue(): Promise<KeyvalueEntry[]>;
  async getKeyvalue<T = unknown>(key: string): Promise<KeyvalueEntry<T>>;
  async getKeyvalue(key: string, paths: string | string[]): Promise<KeyvalueProjection>;
  async getKeyvalue<T = unknown>(
    key?: string,
    paths?: string | string[],
  ): Promise<KeyvalueEntry<T> | KeyvalueEntry[] | KeyvalueProjection> {
    const path = key != null
      ? `api/v4/keyvalue/${encodeURIComponent(key)}`
      : 'api/v4/keyvalue';
    const pathsParam = Array.isArray(paths) ? paths.join(',') : paths;
    return this.client.request({
      path,
      method: 'GET',
      query: pathsParam ? { paths: pathsParam } : undefined,
    });
  }

  async postKeyvalue<T = unknown>(key: string, body: CreateKeyvalueRequest<T>): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/keyvalue/${encodeURIComponent(key)}`,
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchKeyvalue<T = unknown>(key: string, body: PatchKeyvalueRequest<T>): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/keyvalue/${encodeURIComponent(key)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteKeyvalue(key: string): Promise<void> {
    await this.client.request({
      path: `api/v4/keyvalue/${encodeURIComponent(key)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
