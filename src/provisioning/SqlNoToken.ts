/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

export interface SqlNoTokenRequest {
  q: string;
  output_format?: string;
  srs?: number;
  params?: Record<string, unknown>[];
  type_formats?: Record<string, unknown>;
  type_hints?: Record<string, unknown>;
}

export default class SqlNoToken {
  constructor(private readonly client: CentiaHttpClient) {}

  async postSqlNoToken(database: string, body: SqlNoTokenRequest): Promise<unknown> {
    return this.client.request({
      path: `api/v4/sql/database/${encodeURIComponent(database)}`,
      method: 'POST',
      body,
    });
  }
}
