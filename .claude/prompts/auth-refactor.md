# SDK auth refactor — extract shared TokenStore + token provider

## Context

This SDK (`@centia-io/sdk`) currently exports `CodeFlow`, `PasswordFlow`, and a
service object whose `getRefreshToken(refreshToken)` exchanges a refresh token
for a new access token.

Two consumers need shared auth state:

- `../gc2-cli` — already implements its own `getAccessToken` in `src/centiaClient.ts`
  (reads `Configstore('gc2-env')`, checks expiry via `jwtDecode`, calls
  `getRefreshToken`, writes back to configstore).
- `../mcp-server` — a new local stdio MCP server that needs to read the same
  credentials so the user only logs in once via `gc2 login`.

Without coordination, the two processes will race on refresh-token rotation and
clobber each other's session.

## What to do

Add a small auth subsystem to the SDK:

### 1. `TokenStore` interface

```ts
export interface StoredCredentials {
  token?: string;           // access token (JWT)
  refresh_token?: string;
  host?: string;            // optional — useful for CLI/MCP that read host from store
}

export interface TokenStore {
  get(): Promise<StoredCredentials>;
  set(patch: Partial<StoredCredentials>): Promise<void>;
}
```

### 2. Default file-based implementation

`createConfigstoreTokenStore(name = "gc2-env"): TokenStore` — wraps the
`configstore` package (same one `gc2-cli` already uses, so the file path stays
identical: `~/.config/configstore/<name>.json`).

**Critical:** wrap `set()` in a file lock using `proper-lockfile` (or equivalent
cross-platform advisory lock) so concurrent CLI+MCP refreshes don't lose a
rotated refresh token. Acquire lock → read → merge → write → release. Lock the
configstore file path; use a short retry window (e.g. 5 retries, 100ms backoff).

### 3. `createTokenProvider`

```ts
export interface TokenProvider {
  getAccessToken(): Promise<string>;
}

export function createTokenProvider(opts: {
  store: TokenStore;
  authService: AuthService;        // existing type, returned by CodeFlow#service
  expirySkewSeconds?: number;      // default 30
}): TokenProvider;
```

Behaviour:
- Read `{token, refresh_token}` from store.
- If `token` missing → throw `NotLoggedInError` (new exported error class).
- If `token` not expired → return it.
- If expired and `refresh_token` missing/expired → throw `SessionExpiredError`.
- Else call `authService.getRefreshToken(refresh_token)`, persist both new
  `token` and (if present) new `refresh_token` via `store.set()` under the
  lock, return the new access token.
- Use `jwtDecode` for expiry check (already a dep via `gc2-cli`; add to SDK).

Export `NotLoggedInError` and `SessionExpiredError` so consumers can
distinguish "user must run login" from "user must run login again".

### 4. Wire up exports in `src/index.ts`

```ts
export {
  createConfigstoreTokenStore,
  createTokenProvider,
  NotLoggedInError,
  SessionExpiredError,
} from "./auth/tokenProvider";
export type { TokenStore, StoredCredentials, TokenProvider } from "./auth/tokenProvider";
```

### 5. Tests

- `__tests__/tokenProvider.test.ts`:
  - returns cached token when not expired
  - calls refresh + persists new tokens when access token expired
  - throws `NotLoggedInError` when store empty
  - throws `SessionExpiredError` when refresh token also expired
  - concurrent `getAccessToken()` calls only refresh once (use a mock store
    that records writes; assert single call to `authService.getRefreshToken`)
- For the lock test: spawn two child processes that both call `set()`
  simultaneously and assert the final file is valid JSON containing one of the
  two writes (not corrupted).

## Don't break

- All existing exports (`CodeFlow`, `PasswordFlow`, `Sql`, `Rpc`, `createApi`,
  `SignUp`, `createSqlBuilder`, etc.) must stay in place with the same types.
- The existing `localStorage` token persistence used by `CodeFlow` in browsers
  is separate — leave it untouched. `TokenStore` is a new orthogonal mechanism
  for Node.js consumers that want to manage their own storage.

## Deps to add

- `configstore` (^7)
- `proper-lockfile` (^4)
- `jwt-decode` (^4) — if not already present

## Done = next steps

When this is merged and published:
1. CLI prompt at `../gc2-cli/.claude/prompts/auth-refactor.md` migrates
   `centiaClient.ts` to use `createTokenProvider`.
2. MCP prompt at `../mcp-server/.claude/prompts/auth-refactor.md` replaces
   env-only auth with `createTokenProvider` + env fallback.

Bump SDK minor version. CLI and MCP will pin to the new version.
