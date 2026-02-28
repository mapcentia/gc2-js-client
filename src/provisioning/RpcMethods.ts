/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateRpcMethodRequest,
  PatchRpcMethodRequest,
  RpcMethodInfo,
  LocationResponse,
} from './types';

export default class RpcMethods {
  constructor(private readonly client: CentiaHttpClient) {}

  async getRpc(): Promise<RpcMethodInfo[]>;
  async getRpc(method: string): Promise<RpcMethodInfo>;
  async getRpc(method?: string): Promise<RpcMethodInfo | RpcMethodInfo[]> {
    const path = method
      ? `api/v4/methods/${encodeURIComponent(method)}`
      : 'api/v4/methods';
    return this.client.request<RpcMethodInfo | RpcMethodInfo[]>({
      path,
      method: 'GET',
    });
  }

  async postRpc(body: CreateRpcMethodRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/methods',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async patchRpc(method: string, body: PatchRpcMethodRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/methods/${encodeURIComponent(method)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteRpc(method: string): Promise<void> {
    await this.client.request({
      path: `api/v4/methods/${encodeURIComponent(method)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }

  async postCallDry(body: unknown): Promise<unknown> {
    return this.client.request({
      path: 'api/v4/call/dry',
      method: 'POST',
      body,
    });
  }
}
