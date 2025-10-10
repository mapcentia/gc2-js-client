import make from "./util/make-request";
import get from "./util/get-response";
import {RpcRequest, RpcResponse} from "./types/pgTypes";

export default class Rpc {
    async call(request: RpcRequest): Promise<RpcResponse> {
        const response = await make('4', `call`, 'POST', request)
        return await get(response, 200)
    }
}
