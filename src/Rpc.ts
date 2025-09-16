import make from "./util/make-request";
import get from "./util/get-response";

export type RpcRequest = {
    jsonrpc: "2.0"
    method: string
    id?: number|string
    params?: object
}

export type RpcResponse = {
    jsonrpc: "2.0"
    result: {
        schema: object
        data: object[]
    }
    id: number|string
}

export class Rpc {
    async call(request: RpcRequest): Promise<RpcResponse> {
        const response = await make('4', `call`, 'POST', request)
        return get(response, 200)
    }
}
