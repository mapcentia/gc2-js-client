/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateColumnRequest,
  PatchColumnRequest,
  ColumnInfo,
  LocationResponse,
} from './types';

export default class Columns {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string, table: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/columns`;
  }

  async getColumn(schema: string, table: string): Promise<ColumnInfo[]>;
  async getColumn(schema: string, table: string, column: string): Promise<ColumnInfo>;
  async getColumn(schema: string, table: string, column?: string): Promise<ColumnInfo | ColumnInfo[]> {
    const path = column
      ? `${this.basePath(schema, table)}/${encodeURIComponent(column)}`
      : this.basePath(schema, table);
    return this.client.request({ path, method: 'GET' });
  }

  async postColumn(schema: string, table: string, body: CreateColumnRequest | CreateColumnRequest[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.basePath(schema, table),
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchColumn(
    schema: string,
    table: string,
    column: string,
    body: PatchColumnRequest,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.basePath(schema, table)}/${encodeURIComponent(column)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteColumn(schema: string, table: string, column: string): Promise<void> {
    await this.client.request({
      path: `${this.basePath(schema, table)}/${encodeURIComponent(column)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
