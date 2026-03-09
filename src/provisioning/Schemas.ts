/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateSchemaRequest,
  RenameSchemaRequest,
  GetSchemaOptions,
  SchemaInfo,
  LocationResponse,
} from './types';

export default class Schemas {
  constructor(private readonly client: CentiaHttpClient) {}

  async getSchema(schema?: undefined, opts?: GetSchemaOptions): Promise<SchemaInfo[]>;
  async getSchema(schema: string, opts?: GetSchemaOptions): Promise<SchemaInfo>;
  async getSchema(schema?: string, opts?: GetSchemaOptions): Promise<SchemaInfo | SchemaInfo[]> {
    const path = schema
      ? `api/v4/schemas/${encodeURIComponent(schema)}`
      : 'api/v4/schemas';
    const query: Record<string, string> = {};
    if (opts?.namesOnly) {
      query.namesOnly = 'true';
    }
    return this.client.request<SchemaInfo | SchemaInfo[]>({
      path,
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  async postSchema(body: CreateSchemaRequest | CreateSchemaRequest[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/schemas',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchSchema(schema: string, body: RenameSchemaRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/schemas/${encodeURIComponent(schema)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteSchema(schema: string): Promise<void> {
    await this.client.request({
      path: `api/v4/schemas/${encodeURIComponent(schema)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
