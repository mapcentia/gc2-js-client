/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateRuleRequest,
  LocationResponse,
  PatchRuleRequest,
  RuleInfo,
} from './types';

export default class Rules {
  constructor(private readonly client: CentiaHttpClient) {}

  async getRule(): Promise<RuleInfo[]>;
  async getRule(id: number): Promise<RuleInfo>;
  async getRule(id?: number): Promise<RuleInfo | RuleInfo[]> {
    const path = id != null
      ? `api/v4/rules/${encodeURIComponent(id)}`
      : 'api/v4/rules';
    return this.client.request<RuleInfo | RuleInfo[]>({
      path,
      method: 'GET',
    });
  }

  async postRule(body: CreateRuleRequest): Promise<RuleInfo> {
    return this.client.request<RuleInfo>({
      path: 'api/v4/rules',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
  }

  async patchRule(id: number, body: PatchRuleRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/rules/${encodeURIComponent(id)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  async deleteRule(id: number): Promise<void> {
    await this.client.request({
      path: `api/v4/rules/${encodeURIComponent(id)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
