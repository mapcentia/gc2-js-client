import Rpc from "./Rpc"
import {RpcRequest} from "./types/pgTypes"

type MethodsOf<T> = {
    [K in keyof T]: T[K] extends (...args: infer A) => infer R ? (...args: A) => R : never;
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}

function validateParamsForMethod(method: string, params: unknown): Record<string, unknown> | Array<Record<string, unknown>> {
    // Allow either a single plain object or an array of plain objects
    if (Array.isArray(params)) {
        const badIndex = params.findIndex(p => !isPlainObject(p));
        if (badIndex !== -1) {
            throw new TypeError(`createApi: Invalid argument at index ${badIndex} for RPC method "${method}". Expected a plain object.`);
        }
        return params as Array<Record<string, unknown>>;
    }
    if (params === undefined) {
        return {};
    }
    if (!isPlainObject(params)) {
        throw new TypeError(`createApi: Invalid argument for RPC method "${method}". Expected a plain object.`);
    }
    return params as Record<string, unknown>;
}

function extractDataFromResponse(method: string, res: any): any[] {
    if (!res || typeof res !== "object") {
        throw new TypeError(`createApi: Invalid RPC response for method "${method}". Expected an object.`);
    }
    if ((res as any).jsonrpc !== "2.0") {
        throw new TypeError(`createApi: Invalid RPC response for method "${method}". Missing or invalid jsonrpc version.`);
    }

    // Handle JSON-RPC error shape: { jsonrpc: "2.0", error: { code, message, data? }, id }
    const err = (res as any).error;
    if (err !== undefined) {
        if (!err || typeof err !== "object") {
            throw new TypeError(`createApi: Invalid RPC error for method "${method}". Expected 'error' to be an object.`);
        }
        const code = (err as any).code;
        const message = (err as any).message;
        const data = (err as any).data;
        const codeIsNum = typeof code === "number" && Number.isFinite(code);
        const msgIsStr = typeof message === "string" && message.length > 0;
        const details = msgIsStr ? message : "Unknown error";
        const e = new Error(`createApi: RPC error for method "${method}"${codeIsNum ? ` (${code})` : ""}: ${details}`);
        // Attach JSON-RPC specific properties for consumers to inspect
        ;(e as any).code = code;
        if (data !== undefined) (e as any).data = data;
        (e as any).method = method;
        (e as any).name = "JsonRpcError";
        throw e;
    }

    const result = (res as any).result;
    if (!result || typeof result !== "object") {
        throw new TypeError(`createApi: Invalid RPC response for method "${method}". Missing result object.`);
    }
    const data = (result as any).data;
    if (!Array.isArray(data)) {
        throw new TypeError(`createApi: Invalid RPC response for method "${method}". Expected result.data to be an array.`);
    }
    return data;
}

// Implementation signature (wide) — overloads above control the public typing
async function dispatch<K extends keyof any & string>(name: K, paramsLike: unknown): Promise<any> {
    if (typeof name !== "string" || name.length === 0) {
        throw new TypeError("createApi: RPC method name must be a non-empty string.");
    }

    const params = validateParamsForMethod(String(name), paramsLike);

    const rpc = new Rpc()
    const request: RpcRequest = {
        jsonrpc: "2.0",
        method: name,
        id: 1,
        // JSON-RPC allows both object and array params; the SDK type is object-based, so cast for wire-compat.
        params: params as any,
    }
    const res = await rpc.call(request)
    return extractDataFromResponse(String(name), res)
}

export default function createApi<T>(): MethodsOf<T> {
    return new Proxy(
        {},
        {
            get(_target, prop) {
                if (typeof prop !== "string") return undefined;
                return (...args: any[]) => {
                    const packed = args.length === 0 ? {} : (args.length === 1 ? args[0] : args);
                    return (dispatch as any)(prop, packed);
                };
            },
        }
    ) as unknown as MethodsOf<T>;
}
