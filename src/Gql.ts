/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";
import {GqlRequest, GqlResponse} from "./types/pgTypes";

export default class Gql {
    private schema: string
    private client: CentiaHttpClient;

    constructor(schema: string, client?: CentiaHttpClient) {
        this.schema = schema;
        this.client = client ?? getLegacyClient();
    }

    async request(request: GqlRequest): Promise<GqlResponse> {
        return this.client.request({
            path: `api/graphql/schema/${this.schema}`,
            method: 'POST',
            body: request,
        });
    }
}
