/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";
import {RpcRequest, RpcResponse} from "./types/pgTypes";

export default class Rpc {
    async call(request: RpcRequest): Promise<RpcResponse> {
        const response = await make('4', `call`, 'POST', request)
        return await get(response, 200)
    }
}
