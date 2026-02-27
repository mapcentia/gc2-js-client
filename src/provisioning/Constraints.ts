/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateConstraintRequest,
  ConstraintInfo,
  LocationResponse,
} from './types';

export default class Constraints {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string, table: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}/constraints`;
  }

  async getConstraint(
    schema: string,
    table: string,
    constraint?: string,
  ): Promise<ConstraintInfo | ConstraintInfo[]> {
    const path = constraint
      ? `${this.basePath(schema, table)}/${encodeURIComponent(constraint)}`
      : this.basePath(schema, table);
    return this.client.request({ path, method: 'GET' });
  }

  async postConstraint(
    schema: string,
    table: string,
    body: CreateConstraintRequest,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.basePath(schema, table),
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteConstraint(schema: string, table: string, constraint: string): Promise<void> {
    await this.client.request({
      path: `${this.basePath(schema, table)}/${encodeURIComponent(constraint)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
