/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { PatchMetadataRequest } from './types';

export default class MetadataWrite {
  constructor(private readonly client: CentiaHttpClient) {}

  async patchMetaData(body: PatchMetadataRequest): Promise<unknown> {
    return this.client.request({
      path: 'api/v4/meta',
      method: 'PATCH',
      body,
    });
  }
}
