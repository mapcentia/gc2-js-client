/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateUserRequest,
  PatchUserRequest,
  UserInfo,
  LocationResponse,
} from './types';

export default class ProvisioningUsers {
  constructor(private readonly client: CentiaHttpClient) {}

  async getUser(): Promise<UserInfo[]>;
  async getUser(name: string): Promise<UserInfo>;
  async getUser(name?: string): Promise<UserInfo | UserInfo[]> {
    const path = name
      ? `api/v4/users/${encodeURIComponent(name)}`
      : 'api/v4/users';
    return this.client.request<UserInfo | UserInfo[]>({
      path,
      method: 'GET',
    });
  }

  async postUser(body: CreateUserRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/users',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchUser(name: string, body: PatchUserRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/users/${encodeURIComponent(name)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteUser(name: string): Promise<void> {
    await this.client.request({
      path: `api/v4/users/${encodeURIComponent(name)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
