# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`@centia-io/sdk` — a TypeScript/JavaScript client SDK for Centia-io (formerly GC2, hence the repo name and `gc2-*` naming in storage keys and configstore files). Runs in both browsers and Node.js 18+ (relies on global `fetch`). Package manager is **pnpm**.

## Commands

```bash
pnpm build              # tsdown → dist/ (ESM + CJS + UMD, single entry src/index.ts)
pnpm build-watch        # tsdown --watch
pnpm test               # vitest run (all tests, fully mocked fetch — no network)
pnpm test:watch         # vitest watch mode
pnpm vitest run src/__tests__/tokenProvider.test.ts        # single file
pnpm vitest run -t "patchRule sends PATCH to correct path" # single test by name
```

Tests live in `src/__tests__/` and `src/provisioning/__tests__/`. There is no vitest config file; defaults apply. There is no lint script.

## centia-api.json is the source of truth

`centia-api.json` in the repo root (a symlink to the OpenAPI spec in `../mcp-server`) describes the API this SDK is built on. **It is continuously updated** — when working on endpoint wrappers, read the spec first and bring the SDK in line with it: paths, request/response shapes, and expected status codes (e.g. PATCH endpoints return `303` with a `Location` header, POST returns `201`, DELETE returns `204`). When the SDK and the spec disagree, the spec wins — adjust the SDK (and its tests) accordingly.

## Browser-bundle constraint (important)

The build targets `platform: "browser"` (see `tsdown.config.ts`). The Node-only dependencies `configstore`, `proper-lockfile`, and `node:*` modules are declared `external` and must only ever be loaded via **dynamic `await import(...)`** inside functions (see `src/auth/configstoreTokenStore.ts`). Never add a static top-level import of these — it breaks the browser bundle. The UMD global is `CentiaSDK`.

## Architecture: two coexisting API layers

Everything public is exported from the barrel `src/index.ts`.

### 1. Legacy/runtime layer (implicit global auth state)

Classes instantiated without arguments: `Sql`, `SqlNoToken`, `Rpc`, `Gql`, `Meta`, `Status`, `Claims`, `Users`, `Tables`, `Stats`, `Ws`, plus `createApi` and `createSqlBuilder`.

- Auth state (host, tokens, options) lives in a global key-value store: `localStorage` in browsers, an in-memory fallback otherwise (`src/util/storage.ts`).
- State is written by the auth flows `CodeFlow` (OAuth Authorization Code + PKCE, browser), `PasswordFlow` (trusted/CLI/server), and `SignUp`. The actual OAuth HTTP calls live in `src/services/gc2.services.ts` (`Gc2Service`).
- Requests go through `src/util/make-request.ts` or the bridge `src/http/legacy.ts` (`getLegacyClient()`), which wraps the global state in the new `CentiaHttpClient`. Token refresh happens automatically via `isLogin()` in `src/util/utils.ts`.
- `createApi<T>()` (`src/Api.ts`) is a Proxy over `Rpc`: each property access becomes a JSON-RPC call (`POST /api/v4/call`) with the property name as method name, returning `result.data`.
- `createSqlBuilder(schema)` (`src/SqlBuilder.ts`) builds typed `SqlRequest` objects from a `DBSchema` literal (compile-time typing via `as const satisfies DBSchema`) for `Sql.exec()`; it auto-adds `type_hints` for all parameters.
- `Ws` (`src/Ws.ts`) is the realtime WebSocket client (broadcast/subscriptions).

### 2. Explicit-client layer (dependency-injected, used by new code)

- `createCentiaClient(config)` → `CentiaHttpClient` (`src/http/client.ts`): takes `baseUrl`, auth callbacks (`getAccessToken` / `getHeaders`), and an injectable `fetch` (this is how all provisioning tests mock the network). Non-expected statuses throw `CentiaApiError` (`src/http/errors.ts`) carrying status/code/details/requestId. Handles `redirect: 'manual'` quirks: browsers return opaque-redirect responses for the 303-with-Location pattern the API uses.
- `createCentiaAdminClient(config)` (`src/admin.ts`) wraps a `CentiaHttpClient` with one resource class per provisioning area (`src/provisioning/`: Schemas, Tables, Columns, Constraints, Indices, Sequences, Users, Clients, Rules, Privileges, RpcMethods, MetadataWrite, TypeScriptInterfaces, FileImport, GitCommit). Each class takes the http client in its constructor and maps to `/api/v4/...` endpoints.

New endpoint wrappers should follow the explicit-client pattern, not the legacy global-state pattern.

### Auth subsystem (`src/auth/`) — shared cross-process sessions

Built so `gc2-cli` (`../gc2-cli`) and a local MCP server (`../mcp-server`) can share one login session:

- `TokenStore` interface; `createConfigstoreTokenStore(name = 'gc2-env')` is the Node-only file-backed implementation at `~/.config/configstore/<name>.json`. The default name deliberately matches `gc2-cli`'s configstore, so one `gc2 login` is visible to every consumer. Cross-process write safety via `proper-lockfile`; in-process safety via a serial promise chain.
- `createTokenProvider({ store, authService })` returns `getAccessToken()` with expiry-skew checking, single in-flight refresh per process, and persistence back to the store. Known limitation (documented in the source): refresh is NOT coordinated across processes — concurrent processes can race on refresh-token rotation and should treat `invalid_grant` as transient.
- Errors: `NotLoggedInError`, `SessionExpiredError`.

## Conventions and context

- Strict TypeScript; source files start with the MapCentia author/copyright/MIT header comment — keep it on new files.
- `examples/` contains runnable scratch scripts (run with `tsx`); `README.md` is the user-facing API documentation with extensive SqlBuilder examples — update it when changing public behavior.
- Background for the auth design is in `.claude/prompts/auth-refactor.md`.
