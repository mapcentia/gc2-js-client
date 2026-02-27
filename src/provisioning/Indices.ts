/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateIndexRequest,
  IndexInfo,
  LocationResponse,
} from './types';

export default class Indices {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string, table: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/indices`;
  }

  async getIndex(schema: string, table: string, index?: string): Promise<IndexInfo | IndexInfo[]> {
    const path = index
      ? `${this.basePath(schema, table)}/${encodeURIComponent(index)}`
      : this.basePath(schema, table);
    return this.client.request({ path, method: 'GET' });
  }

  async postIndex(
    schema: string,
    table: string,
    body: CreateIndexRequest,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.basePath(schema, table),
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteIndex(schema: string, table: string, index: string): Promise<void> {
    await this.client.request({
      path: `${this.basePath(schema, table)}/${encodeURIComponent(index)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
