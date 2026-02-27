/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";

export default class Users {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    async get(user: string): Promise<any> {
        return this.client.request({
            path: `api/v4/users/${user}`,
            method: 'GET',
        });
    }
}
