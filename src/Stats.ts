/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";

export default class Stats {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    async get(): Promise<any> {
        return this.client.request({
            path: 'api/v4/stats',
            method: 'GET',
        });
    }
}
