/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";

export default class Meta {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    async query(rel: string, options?: { noRestriction?: boolean }): Promise<any> {
        return this.client.request({
            path: `api/v4/meta/${rel}`,
            method: 'GET',
            query: options?.noRestriction !== undefined
                ? { noRestriction: String(options.noRestriction) }
                : undefined,
        });
    }
}
