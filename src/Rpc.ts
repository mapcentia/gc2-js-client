/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";
import {RpcRequest, RpcResponse} from "./types/pgTypes";

export default class Rpc {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    async call(request: RpcRequest): Promise<RpcResponse> {
        return this.client.request({
            path: 'api/v4/call',
            method: 'POST',
            body: request,
        });
    }
}
