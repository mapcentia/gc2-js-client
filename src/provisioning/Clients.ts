/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateClientRequest,
  PatchClientRequest,
  ClientInfo,
  CreateClientResponse,
  LocationResponse,
} from './types';

export default class ProvisioningClients {
  constructor(private readonly client: CentiaHttpClient) {}

  async getClient(): Promise<ClientInfo[]>;
  async getClient(id: string): Promise<ClientInfo>;
  async getClient(id?: string): Promise<ClientInfo | ClientInfo[]> {
    const path = id
      ? `api/v4/clients/${encodeURIComponent(id)}`
      : 'api/v4/clients';
    return this.client.request<ClientInfo | ClientInfo[]>({
      path,
      method: 'GET',
    });
  }

  async postClient(body: CreateClientRequest | CreateClientRequest[]): Promise<CreateClientResponse> {
    const res = await this.client.requestFull<{ secret: string }>({
      path: 'api/v4/clients',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return {
      location: res.getHeader('Location') ?? '',
      secret: res.body.secret,
    };
  }

  async patchClient(id: string, body: PatchClientRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/clients/${encodeURIComponent(id)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteClient(id: string): Promise<void> {
    await this.client.request({
      path: `api/v4/clients/${encodeURIComponent(id)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
