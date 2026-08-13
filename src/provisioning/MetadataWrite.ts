/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse, PatchMetadataRequest } from './types';

export default class MetadataWrite {
  constructor(private readonly client: CentiaHttpClient) {}

  async patchMetaData(body: PatchMetadataRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/meta',
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }
}
