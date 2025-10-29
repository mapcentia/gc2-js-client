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
import { CodeFlow, PasswordFlow, Sql, Rpc, createApi, SignUp, createSqlBuilder } from "@centia-io/sdk";
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

### SignUp (Browser – Create a new user)

Use this helper in browser applications to redirect the user to the Centia‑io sign‑up page. 
The user will create an account under a specified parent database/tenant and then be redirected back to your application.

Required options:
- host: Base URL of your Centia‑io instance, e.g. https://api.centia.io
- clientId: OAuth client id configured in Centia.io
- parentDb: The parent/tenant database under which the new user should be created
- redirectUri: URL in your app to return to after sign‑up

Example (vanilla JS/TS):
```ts
import { SignUp } from "@centia-io/sdk";

const signUp = new SignUp({
  host: "https://api.centia.io",
  clientId: "your-client-id",
  parentDb: "your-parent-database",
  redirectUri: window.location.origin + "/auth/callback"
});

// Start sign-up when the user clicks "Create account"
function onSignUpClick() {
  signUp.signUp(); // Redirects to GC2 sign-up page
}
```

Notes:
- Default endpoint is {host}/signup/. You can override with authUri if needed.
- After the user completes sign‑up and is redirected back to your app, start your normal sign‑in flow (e.g., CodeFlow. A session is started when the user signed up, so the user will be signed in automatically in the flow.)

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

## SQL Builder

Build strongly typed SQL requests from a DB schema so you don't write raw SQL.

- Function: `createSqlBuilder(schema)`
- Types: `DBSchema`, `TableDef`, `ColumnDef`
- Supports: `select` (andWhere/orWhere, andWhereOp/orWhereOp, grouped predicates, orderBy, limit, offset, join, selectFrom), `insert(returning)`, `update(where, returning)`, `delete(where, returning)`
- Produces an object with `toSql(): SqlRequest` which you pass to `new Sql().exec()`

Example:
```ts
import { createSqlBuilder, Sql } from "@centia-io/sdk";
import type { DBSchema } from "@centia-io/sdk";

// Minimal schema (compatible with schema/schema.json).
const schema = {
  name: "public",
  tables: [
    {
      name: "items",
      columns: [
        { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
        { name: "name", _typname: "varchar", _is_array: false, is_nullable: true },
        { name: "type", _typname: "int4", _is_array: false, is_nullable: true }
      ]
    }
  ]
} as const satisfies DBSchema;

const b = createSqlBuilder(schema);

// SELECT with where/order/limit
const selectReq = b.table("items")
  .select(["id", "name"]) // or omit to select all: .select()
  .andWhere({ type: [1, 2, 3] }) // => "type" = ANY(:param)
  .orderBy([["id","desc"]])
  .limit(10)
  .toSql();

const sql = new Sql();
const rows = (await sql.exec(selectReq)).data;

// INSERT
const insertReq = b.table("items")
  .insert({ id: 10, name: "Thing", type: 1 })
  .returning(["id"])
  .toSql();
await sql.exec(insertReq);

// UPDATE
const updateReq = b.table("items")
  .update({ name: "Updated" })
  .where({ id: 10 })
  .returning(["id","name"])
  .toSql();
await sql.exec(updateReq);

// DELETE
const deleteReq = b.table("items")
  .delete()
  .where({ id: 10 })
  .toSql();
await sql.exec(deleteReq);
```

Notes:
- The builder automatically adds `type_hints` for array parameters (e.g., `int4[]`), as arrays are not inferred by default by the server.
- Value types are inferred from `_typname` and `_is_array`. For `numeric/decimal`, use strings (`NumericString`).
- You can pass the same `SqlRequest` object to `Sql.exec`.

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


---

## Advanced SqlBuilder examples (developer guide)

Below are practical, copy/paste‑ready snippets that demonstrate the SqlBuilder API in real scenarios. These mirror and condense the exhaustive examples in examples/test_builder.ts.

Setup (minimal schema with a foreign key for joins):
```ts
import { createSqlBuilder } from "@centia-io/sdk";
import type { DBSchema } from "@centia-io/sdk";

const schema = {
  name: "public",
  tables: [
    {
      name: "items",
      columns: [
        { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
        { name: "name", _typname: "varchar", _is_array: false, is_nullable: false },
        { name: "type", _typname: "int4", _is_array: false, is_nullable: false },
      ],
      constraints: [
        { name: "items-pk", constraint: "primary", columns: ["id"] },
        {
          name: "items-type-fk",
          constraint: "foreign",
          columns: ["type"],
          referenced_table: "item_types",
          referenced_columns: ["id"],
        },
      ],
    },
    {
      name: "item_types",
      columns: [
        { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
        { name: "type", _typname: "varchar", _is_array: false, is_nullable: true },
      ],
      constraints: [{ name: "item_types-pk", constraint: "primary", columns: ["id"] }],
    },
  ],
} as const satisfies DBSchema;

const b = createSqlBuilder(schema);
```

- Selecting all or specific columns
```ts
b.table("items").select().toSql();
// select "items".* from "public"."items"

b.table("items").select(["id", "name"]).toSql();
// select "items"."id", "items"."name" from "public"."items"
```

- AND filters (equality and arrays -> ANY)
```ts
b.table("items").select()
  .andWhere({ id: 3, type: [1,2,3] })
  .toSql();
// where "items"."id" = :items_id_1 and "items"."type" = ANY(:items_type_2)
```

- OR filters (object groups)
```ts
b.table("items").select()
  .orWhere({ id: 1 })
  .orWhere({ id: 2 })
  .toSql();
// where ("items"."id" = :items_id_1) or ("items"."id" = :items_id_2)
```

- Operator predicates: comparisons, LIKE variants, IN/NOT IN, NULL checks
```ts
b.table("items").select()
  .andWhereOp("id", ">", 10)
  .andWhereOp("name", "ilike", "%foo%")
  .andWhereOp("type", "in", [1,2])
  .andWhereOp("name", "isnull")
  .toSql();
```

- Grouped predicates and OR chains
```ts
b.table("items").select()
  .andWhereOpGroup([
    ["type", "in", [1,2]],
    ["id", ">=", 10],
  ])
  .orWhereOpGroup([["name", "ilike", "%foo%"]])
  .orWhereOpGroup([["name", "ilike", "%bar%"], ["id", "<", 50]])
  .toSql();
```

- JOIN by foreign key + selecting from the joined table
```ts
// Auto-detects ON using FK items.type -> item_types.id
b.table("items").select(["id","name"]).join("item_types").toSql();
// select ... from "public"."items" inner join "public"."item_types" on "items"."type" = "item_types"."id"

// Select specific columns from joined table
b.table("items")
  .select(["id"])                // base table columns
  .join("item_types", "left")    // join type: inner|left|right|full
  .selectFrom("item_types", ["type"]) // joined table columns
  .toSql();

// Select all columns from the joined table
b.table("items").select(["id"]).join("item_types").selectFrom("item_types").toSql();
```

- ORDER BY, LIMIT, OFFSET
```ts
b.table("items").select().orderBy("id").toSql();
// order by "items"."id" asc

b.table("items").select().orderBy([["type","desc"],["id","asc"]]).toSql();

b.table("items").select().limit(25).offset(50).toSql();
```

- INSERT, UPDATE, DELETE
```ts
b.table("items").insert({ id: 1, name: "A", type: 1 }).returning(["id"]).toSql();

b.table("items").update({ name: "B" }).where({ id: 1 }).returning(["id","name"]).toSql();

b.table("items").delete().where({ id: 1 }).toSql();
```

- Special value types (ranges, intervals, geometry) – supported at compile‑time and runtime
```ts
// Ranges (e.g., tstzrange)
const events = {
  name: "public",
  tables: [{
    name: "events",
    columns: [
      { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
      { name: "period", _typname: "tstzrange", _is_array: false, is_nullable: true },
    ]
  }]
} as const satisfies DBSchema;

createSqlBuilder(events).table("events").select().andWhere({
  period: {
    lower: "2024-01-01T00:00:00+00:00",
    upper: "2024-12-31T23:59:59+00:00",
    lowerInclusive: true,
    upperInclusive: false,
  }
}).toSql();

// Interval
const durations = {
  name: "public",
  tables: [{
    name: "durations",
    columns: [
      { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
      { name: "duration", _typname: "interval", _is_array: false, is_nullable: true },
    ]
  }]
} as const satisfies DBSchema;

createSqlBuilder(durations).table("durations").select().andWhere({
  duration: { y: 0, m: 1, d: 0, h: 2, i: 0, s: 0 }
}).toSql();

// Geometry (point example)
const shapes = {
  name: "public",
  tables: [{
    name: "shapes",
    columns: [
      { name: "id", _typname: "int4", _is_array: false, is_nullable: false },
      { name: "pt", _typname: "point", _is_array: false, is_nullable: true },
    ]
  }]
} as const satisfies DBSchema;

createSqlBuilder(shapes).table("shapes").select().andWhere({ pt: { x: 1, y: 2 } }).toSql();
```

Notes and tips:
- All SQL is schema‑qualified: from "schema"."table" and in JOINs.
- Type hints are added automatically for all parameters (scalars and arrays). Arrays are hinted as e.g. int4[], scalars as their base type (e.g., int4, varchar, jsonb).
- Runtime validation mirrors the editor’s type checks: invalid column names, wrong orderBy direction, bad join type, negative limit/offset, wrong where/whereOp value shapes (including range/interval/geometry), and nulls on non‑nullable columns produce clear errors.
- For more, see the full script in examples/test_builder.ts which prints the generated SQL and parameters for dozens of cases.
