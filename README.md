# SDK

TypeScript/JavaScript client SDK for Centia-io. It provides:

- Authentication helpers:
    - CodeFlow (OAuth 2.0 Authorization Code + PKCE) for browser apps
    - PasswordFlow for trusted/CLI/server environments
- Data access:
    - Sql: Execute parameterized SQL
    - Rpc: Call JSON-RPC methods
    - createApi: A tiny type-safe helper that maps TypeScript interfaces to JSON‑RPC calls

## Installation

```bash
npm install @centia-io/sdk
yarn add @centia-io/sdk
pnpm add @centia-io/sdk
```  

Or from CDN:

```html
<script src="https://cdn.jsdelivr.net/npm/@centia-io/sdk@latest/dist/centia-io-sdk.umd.js"></script>
```

Requirements:
- Browser or Node.js 18+ (for global `fetch`).
- An accessible Centia.io host URL and client credentials.

ESM import:
```ts
import { CodeFlow, PasswordFlow, Sql, Rpc, createApi } from "@centia-io/sdk";
import type { RpcRequest, RpcResponse, PgTypes } from "@centia-io/sdk";
```

---

## Authentication

The SDK handles token storage and refresh for you.
- Tokens and minimal options are saved to `localStorage` in browsers. In non‑browser environments, an in‑memory store is used for the lifetime of the process.
- Authorization headers are added automatically for Sql/Rpc requests.

### CodeFlow (Browser, OAuth 2.0 Authorization Code + PKCE)

Use this flow in browser applications where you can redirect the user to the Centia-io login page.

Required options:
- `host`: Base URL of your Centia-io instance, e.g. `https://api.centia.io`
- `clientId`: OAuth client id configured in Centia.io
- `redirectUri`: The URL in your app that handles the redirect back from Centia.io (must be whitelisted)
- `scope` (optional): Not in use yet, but will be used to request additional permissions from the user.

Example (vanilla JS/TS + SPA):
```ts
import { CodeFlow } from "@centia-io/sdk";

const codeFlow = new CodeFlow({
  host: "https://api.centia.io",
  clientId: "your-client-id",
  redirectUri: window.location.origin + "/auth/callback"
});

// On app startup, call redirectHandle() once to complete a login redirect (if any)
codeFlow.redirectHandle().then((signedIn) => {
  if (signedIn) {
    console.log("User signed in");
  }
});

// Start sign-in when user clicks Login
function onLoginClick() {
  codeFlow.signIn(); // Redirects to GC2 auth page
}

// Sign out (clears tokens/options and redirects to signout endpoint)
function onLogoutClick() {
  codeFlow.signOut();
}
```

Notes:
- `redirectHandle()` detects errors from the auth server, validates `state` (CSRF protection), exchanges the `code` for tokens, performs `PKCE` (Proof Key for Code Exchange), stores tokens and cleans up the URL.
- `signOut()` clears local tokens/options and redirects to the sign-out URL. If you only need to clear local state without redirect, call `codeFlow.clear()`.

### PasswordFlow (Trusted environments, CLI/Server)

Use only in trusted environments. The user’s database credentials are exchanged directly for tokens.

Required options:
- `host`
- `clientId`
- `username`
- `password`
- `database`

Example (Node.js):
```ts
import { PasswordFlow } from "@centia-io/sdk";

const flow = new PasswordFlow({
  host: "https://api.centia.io",
  clientId: "your-client-id",
  username: "your-username",
  password: "your-password",
  database: "parent-database" // The database to connect to. If superuser, this is the sam as username.
});

await flow.signIn();
// Tokens are now stored; subsequent Sql/Rpc calls will include Authorization header.

// ... your code ...

flow.signOut(); // Clears tokens/options in local storage (no redirect)
```

## SQL

Execute parameterized SQL against GC2.

- Class: `new Sql()`
- Method: `exec(request: SqlRequest): Promise<SQLResponse>`
- Endpoint: `POST https://api.centia.io/api/v4/sql`

Types (simplified):
- `SqlRequest` has:
    - `q`: SQL string, you can use named placeholders like `:a` (server-side feature)
    - `params?`: object with values for placeholders
    - `type_hints?`: optional explicit type hints
    - `type_formats?`: optional per-column format strings
- `SQLResponse` has:
    - `schema`: a map of column name -> `{ type: string, array: boolean }`
    - `data`: an array of rows (records)

Example:
```ts
import { Sql } from "@centia-io/sdk";

const sql = new Sql();

const payload = {
  a: 1,
  b: "hello",
  c: "3.14",          // numeric/decimal values are strings
  d: ["x", "y"],      // arrays are supported
  e: { nested: [1,2] } // JSON
};

const res = await sql.exec({
  q: "select :a::int as a, :b::varchar as b, :c::numeric as c, :d::varchar[] as d, :e::jsonb as e",
  params: payload,
  type_hints: { d: "varchar[]" } // Arrays are not inferred by default, and must be specified explicitly
});

console.log(res.schema); // { a: {type: 'int4', array: false}, ... }
console.log(res.data);   // [{ a: 1, b: 'hello', c: '3.14', d: ['x','y'], e: {nested:[1,2]} }]
```

Typing the rows:
```ts
import type { PgTypes } from "@centia-io/sdk";

interface Row extends PgTypes.DataRow {
  a: number;
  b: Pgtypes.Varchar;
  c: PgTypes.NumericString;
  d: PgTypes.PgArray<Pgtypes.Varchar>;
  e: PgTypes.JsonValue;
}

// res: PgTypes.SQLResponse<Row>
const res = await sql.exec({ q: "...", params: payload }) as PgTypes.SQLResponse<Row>;
```

## RPC

Call JSON‑RPC methods exposed by GC2.

- Class: `new Rpc()`
- Method: `call(request: RpcRequest): Promise<RpcResponse>`
- Endpoint: `POST {host}/api/v4/call`

Types (simplified):
- `RpcRequest` has `jsonrpc: "2.0"`, `method`, optional `params`, optional `id`
- `RpcResponse` has `jsonrpc: "2.0"`, `id`, and `result` with `{ schema, data }`

Example:
```ts
import { Rpc } from "@centia-io/sdk";

const rpc = new Rpc();

const payload = { a: 1, b: "hello" };

const res = await rpc.call({
  jsonrpc: "2.0",
  method: "typeTest",
  params: payload,
  id: 1
});

console.log(res.result.schema);
console.log(res.result.data); // array of rows
```

Typing the rows:
```ts
import type { PgTypes } from "@centia-io/sdk";

interface Row extends PgTypes.DataRow {
  a: number;
  b: string;
}

const res = await rpc.call({ jsonrpc: "2.0", method: "typeTest", params: payload }) as PgTypes.RpcResponse<Row>;
```

## createApi

A tiny helper that builds a Proxy around `Rpc` so you can call `api.someMethod(params)` directly, with TypeScript autocompletion and type‑checking based on your own interface.

Under the hood, each property access becomes a JSON‑RPC call with the property name as the method. The helper returns `result.data` (array of rows) from the RPC response.

Example with typing:
```ts
import { createApi } from "@centia-io/sdk";
import type { PgTypes } from "@centia-io/sdk";

// Define the shape of your RPC methods and return types
interface MyApi {
  typeTest(params: {
    a: number;
    b: Pgtypes.Varchar;
    c: PgTypes.NumericString;
    d: PgTypes.PgArray<Pgtypes.Varchar>;
    e: PgTypes.JsonValue;
  }): Promise<Array<{
    a: number;
    b: Pgtypes.Varchar;
    c: PgTypes.NumericString;
    d: PgTypes.PgArray<Pgtypes.Varchar>;
    e: PgTypes.JsonValue;
  }>>;
}

const api = createApi<MyApi>();

const rows = await api.typeTest({
  a: 1,
  b: "Hello world",
  c: "3.4",
  d: ["Hello", "world"],
  e: { "x": [1,2,3,4,5,6,7,8,9,10] }
});

console.log(rows); // typed row array
```

Notes:
- `createApi<T>()` relies on naming conventions: the property name is the JSON‑RPC `method` name.
- Each call returns `result.data` from the RPC response (array of rows).

## Error handling

- Network/HTTP errors: thrown as `Error` with the status/body text when available.
- Auth errors: the SDK auto‑refreshes access tokens when possible. If the refresh token is expired or missing, you’ll get an error and should re‑authenticate.


## Environment details

- Storage: tokens/options stored in `localStorage` when available; otherwise a global in‑memory store is used (`globalThis.__gc2_memory_storage`).
- Fetch: Node.js 18+ recommended (includes native `fetch`). For older Node versions, add a Fetch polyfill.

## License

The SDK is licensed under [The MIT License](https://opensource.org/license/mit)
