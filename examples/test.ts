import {createApi, Rpc, Sql, PasswordFlow, PasswordFlowOptions, PgTypes} from "./../dist/centia-io-sdk.js";
import {Api} from "./MyApi.ts";


const options: PasswordFlowOptions = {username: 'mydb', password: 'hawk2000', clientId: 'gc2-cli', database: 'mydb', host: 'http://localhost:8080'}
const passwordFlow = new PasswordFlow(options)


// Create the stubbed API
const api = createApi<Api>();

const sql = new Sql()
const rpc = new Rpc()

// Usage with autocompletion + type-checking
export async function testApi<Api>() {

    await passwordFlow.signIn()

    const payload = {
        a: 1,
        b: "hej",
        c: "3.4",
        d: ["ds", "sdsd"],
        e: {"zdsd": [2, 3, 4, 5, 6, 7, 8, 9, 10]},
        f: "1.4",

    }

    const res1 = await api.typeTest(payload)
    console.log(res1)

    // const res2 = await sql.exec({
    //     "q": "select :a::int as a, :b::varchar as b, :c::numeric as c, :d::varchar[] as d, :e::jsonb as e",
    //     "params": payload
    // })
    // console.log(res2)

    const res3 = await rpc.call({
        "jsonrpc": "2.0",
        "method": "typeTest",
        "params": payload,
        "id": 1
    })
    console.log(res3)

    passwordFlow.signOut()


}

testApi().catch((err) => {
  console.error('Example error:', err);
  // Prevent unhandled promise rejection from crashing Node
  process.exitCode = 1;
});

import WebSocket from 'ws';
const token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS5jZW50aWEuaW8iLCJ1aWQiOiJtaG1hcGNlbnRpYWNvbV9zbHVnIiwiZXhwIjoxNzYxMDY4NjIzLCJpYXQiOjE3NjEwNjUwMjMsImRhdGFiYXNlIjoibWhtYXBjZW50aWFjb21fc2x1ZyIsInN1cGVyVXNlciI6dHJ1ZSwidXNlckdyb3VwIjpudWxsLCJyZXNwb25zZV90eXBlIjoidG9rZW4iLCJwcm9wZXJ0aWVzIjpudWxsLCJlbWFpbCI6Im1oQG1hcGNlbnRpYS5jb20ifQ.WqZhqzeLLnkxIUM0C5xdMr8JCND8aDw3ajRZhFp0uig';
const ws = new WebSocket(`wss://api.centia.io/?token=${encodeURIComponent(token)}`);
ws.on('open', () => ws.send('SELECT 42 AS answer'));
ws.on('message', (data) => console.log(JSON.parse(data.toString())));
