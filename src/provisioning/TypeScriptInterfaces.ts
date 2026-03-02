/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';

export default class TypeScriptInterfaces {
  constructor(private readonly client: CentiaHttpClient) {}

  async getTypeScript(): Promise<string> {
    return this.client.request<string>({
      path: 'api/v4/interfaces',
      method: 'GET',
      accept: 'text/plain',
    });
  }
}
