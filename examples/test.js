import {createApi} from "./../dist/Api.js";
import Rpc from "./../dist/Rpc.js";
import Sql from "./../dist/Sql.js";

// Create the stubbed API
const api = createApi();

const sql = new Sql()
const rpc = new Rpc()

// Usage with autocompletion + type-checking
export async function testApi() {

    const payload = {
        a: 1,
        b: "hej",
        c: "3.4",
        d: ["ds", "sdsd"],
        e: {"zdsd": [2, 3, 4, 5, 6, 7, 8, 9, 10]}
    }

    const res1 = await api.typeTest(payload)
    console.log(res1)

    const res2 = await sql.exec({
        "q": "select :a::int as a, :b::varchar as b, :c::numeric as c, :d::varchar[] as d, :e::jsonb as e",
        "params": payload
    })
    console.log(res2)

    const res3 = await rpc.call({
        "jsonrpc": "2.0",
        "method": "typeTest",
        "params": payload,
        "id": 1
    })
    console.log(res3)

}

testApi();
