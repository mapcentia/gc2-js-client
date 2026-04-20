/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { TableInfo, GetTableOptions, LocationResponse } from './types';

export default class ProvisioningTables {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/tables`;
  }

  async getTable(schema: string, table?: undefined, opts?: GetTableOptions): Promise<TableInfo[]>;
  async getTable(schema: string, table: string, opts?: GetTableOptions): Promise<TableInfo>;
  async getTable(schema: string, table?: string, opts?: GetTableOptions): Promise<TableInfo | TableInfo[]> {
    const path = table
      ? `${this.basePath(schema)}/${encodeURIComponent(table)}`
      : this.basePath(schema);
    const query: Record<string, string> = {};
    if (opts?.namesOnly) {
      query.namesOnly = 'true';
    }
    return this.client.request({
      path,
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  async postTable(schema: string, body: { name: string; [key: string]: unknown } | { name: string; [key: string]: unknown }[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.basePath(schema),
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchTable(schema: string, table: string, body: Record<string, unknown>): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.basePath(schema)}/${encodeURIComponent(table)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteTable(schema: string, table: string): Promise<void> {
    await this.client.request({
      path: `${this.basePath(schema)}/${encodeURIComponent(table)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
