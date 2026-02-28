/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  PatchPrivilegeRequest,
  PrivilegeInfo,
} from './types';

export default class Privileges {
  constructor(private readonly client: CentiaHttpClient) {}

  async getPrivileges(schema: string, table: string): Promise<PrivilegeInfo[]> {
    return this.client.request<PrivilegeInfo[]>({
      path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/privileges`,
      method: 'GET',
    });
  }

  async patchPrivileges(schema: string, table: string, body: PatchPrivilegeRequest): Promise<PrivilegeInfo[]> {
    return this.client.request<PrivilegeInfo[]>({
      path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/privileges`,
      method: 'PATCH',
      body,
    });
  }
}
