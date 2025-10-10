import Rpc from "./Rpc"
import {RpcRequest} from "./types/pgTypes"

type MethodsOf<T> = {
    [K in keyof T]: T[K] extends (...args: infer A) => infer R ? (...args: A) => R : never;
};

// Implementation signature (wide) — overloads above control the public typing
async function dispatch<K extends keyof any & string>(name: K, args: object|Array<object>): Promise<any> {
    console.log("Dispatch:", name, args);
    // route to real implementations:
    const rpc = new Rpc()
    const request: RpcRequest = {
        jsonrpc: "2.0",
        method: name,
        id: 1,
        params: args as Record<string, unknown>,
    }
    const res = await rpc.call(request)
    return res.result.data
}

export function createApi<T>(): MethodsOf<T> {
    return new Proxy(
        {},
        {
            get(_target, prop) {
                if (typeof prop !== "string") return undefined;
                return (...args: any[]) => (dispatch as any)(prop, ...args);
            },
        }
    ) as unknown as MethodsOf<T>;
}
