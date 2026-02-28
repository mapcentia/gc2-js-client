/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateSequenceRequest,
  PatchSequenceRequest,
  SequenceInfo,
  LocationResponse,
} from './types';

export default class Sequences {
  constructor(private readonly client: CentiaHttpClient) {}

  private basePath(schema: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/sequences`;
  }

  async getSequence(schema: string): Promise<SequenceInfo[]>;
  async getSequence(schema: string, sequence: string): Promise<SequenceInfo>;
  async getSequence(schema: string, sequence?: string): Promise<SequenceInfo | SequenceInfo[]> {
    const path = sequence
      ? `${this.basePath(schema)}/${encodeURIComponent(sequence)}`
      : this.basePath(schema);
    return this.client.request({ path, method: 'GET' });
  }

  async postSequence(schema: string, body: CreateSequenceRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.basePath(schema),
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchSequence(
    schema: string,
    sequence: string,
    body: PatchSequenceRequest,
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.basePath(schema)}/${encodeURIComponent(sequence)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteSequence(schema: string, sequence: string): Promise<void> {
    await this.client.request({
      path: `${this.basePath(schema)}/${encodeURIComponent(sequence)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
