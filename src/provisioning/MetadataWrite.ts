/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  GetMetaDataOptions,
  LocationResponse,
  MetaConfigFieldset,
  MetadataResponse,
  PatchMetadataRequest,
} from './types';

export default class MetadataWrite {
  constructor(private readonly client: CentiaHttpClient) {}

  /**
   * Get relation metadata. `query` is a schema-qualified relation name, a schema name or a
   * tag (`tag:name`); pass an array (or a comma-separated string) to combine several.
   */
  async getMetaData(query: string | string[], opts?: GetMetaDataOptions): Promise<MetadataResponse> {
    const parts = Array.isArray(query) ? query : query.split(',');
    const path = `api/v4/meta/${parts
      .map((p) => encodeURIComponent(p.trim()).replace(/%3A/gi, ':'))
      .join(',')}`;
    const res = await this.client.request<MetadataResponse>({
      path,
      method: 'GET',
      query: opts?.noRestriction !== undefined
        ? { noRestriction: String(opts.noRestriction) }
        : undefined,
    });
    // The server serialises an empty relation map as `[]`.
    return { ...res, relations: Array.isArray(res.relations) ? {} : res.relations };
  }

  async patchMetaData(body: PatchMetadataRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/meta',
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /**
   * Get the effective meta config: the fieldsets and fields used to edit the free-form
   * relation `properties`. Built-in fieldsets merged with the server's custom ones (custom wins).
   */
  async getMetaConfig(): Promise<MetaConfigFieldset[]> {
    return this.client.request<MetaConfigFieldset[]>({
      path: 'api/v4/meta-config',
      method: 'GET',
    });
  }
}
