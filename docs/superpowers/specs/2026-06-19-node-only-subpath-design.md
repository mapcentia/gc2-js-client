# Node-only Subpath for `createConfigstoreTokenStore` — Design

> Date: 2026-06-19
> Status: Approved
> Repos: `gc2-js-client` (SDK), `gc2-cli` (consumer)

## Goal

Move the SDK's only Node-only function, `createConfigstoreTokenStore`, behind a
`@centia-io/sdk/node` subpath export so the main entry (`@centia-io/sdk`) is
fully browser-safe. After this, the main bundle no longer contains the guarded
`await import('configstore')`, so browser consumers (e.g. centia-app) no longer
need to externalize `configstore`/`proper-lockfile` in their bundler.

## Context

- The SDK builds with tsdown (`platform: "browser"`, single entry
  `src/index.ts` → `dist/centia-io-sdk.{js,cjs,umd.js,d.ts,d.cts}`). Its config
  already lists `external: ['configstore', 'proper-lockfile', 'node:fs',
  'node:os', 'node:path']`.
- Only `src/auth/configstoreTokenStore.ts` is Node-only: it loads `configstore`,
  `proper-lockfile`, and `node:*` via guarded **dynamic** `await import(...)`
  that never runs in the browser. `createTokenProvider`
  (`src/auth/tokenProvider.ts`), the errors, and all types are browser-safe.
- The main entry (`src/index.ts`) re-exports `createConfigstoreTokenStore` from
  `./auth`. Because the function lives in the main bundle, the dynamic
  `import('configstore')` is in `dist/centia-io-sdk.js`. A consuming browser
  bundler (Rollup/Vite) re-traverses that dynamic import and fails on
  `stubborn-fs`'s static `import { promisify } from 'node:util'`
  (configstore → atomically → stubborn-fs).
- Consumers:
  - **gc2-cli** imports `createConfigstoreTokenStore` from `@centia-io/sdk`
    (`src/centiaClient.ts`), alongside `CodeFlow`, `createCentiaAdminClient`,
    `createTokenProvider`, `isCentiaApiError`, `NotLoggedInError`,
    `SessionExpiredError`, `CentiaAdminClient`. Its SDK dependency is a local
    link: `"@centia-io/sdk": "file:../gc2-js-client"`.
  - **centia-app** (browser) never uses it; it currently works around the build
    failure with `external: ['configstore','proper-lockfile']` in vite.config.

## Approach (chosen)

A dedicated Node-only entry + `./node` subpath export; remove
`createConfigstoreTokenStore` from the main entry. Rejected alternatives:
dual-export (keeps the code in the main bundle — does not fix the browser
build) and conditional browser/node `exports` for `.` (same import resolving to
different availability — confusing, more build machinery).

## Changes — `gc2-js-client`

1. **New `src/node.ts`** — Node-only entry:
   ```ts
   export { createConfigstoreTokenStore } from './auth/configstoreTokenStore'
   ```
2. **`src/index.ts`** — remove `createConfigstoreTokenStore` from the runtime
   export block. Keep `createTokenProvider`, `NotLoggedInError`,
   `SessionExpiredError`, and every type export unchanged.
3. **`src/auth/index.ts`** — remove the `createConfigstoreTokenStore`
   re-export. The source file `src/auth/configstoreTokenStore.ts` stays in
   place (tests import it by relative path and are unaffected).
4. **`tsdown.config.ts`** — add a second entry:
   ```ts
   entry: {
     'centia-io-sdk': './src/index.ts',
     'centia-io-sdk-node': './src/node.ts',
   }
   ```
   (Same config; `external` already covers configstore/proper-lockfile/node:*.)
5. **`package.json`** — add the subpath export and bump the version:
   ```jsonc
   "exports": {
     ".": { "require": "./dist/centia-io-sdk.cjs", "import": "./dist/centia-io-sdk.js" },
     "./node": {
       "import": { "types": "./dist/centia-io-sdk-node.d.ts", "default": "./dist/centia-io-sdk-node.js" },
       "require": { "types": "./dist/centia-io-sdk-node.d.cts", "default": "./dist/centia-io-sdk-node.cjs" }
     },
     "./package.json": "./package.json"
   }
   ```
   The `./node` subpath uses per-condition `types` (the top-level `types` field
   only covers the root `.` import, not subpaths). Leave the working `.` export
   as-is. Version `0.1.3` → `0.2.0` (breaking change in 0.x).
6. **Tests** — update `src/__tests__/tokenProvider.test.ts` "public exports":
   drop the `sdk.createConfigstoreTokenStore` assertion from the main-barrel
   test (it is no longer on `../index`), and add a test that `../node` exports
   `createConfigstoreTokenStore` as a function.

## Changes — `gc2-cli`

7. **`src/centiaClient.ts`** — split the import so only
   `createConfigstoreTokenStore` comes from the subpath:
   ```ts
   import { CodeFlow, createCentiaAdminClient, createTokenProvider,
            isCentiaApiError, NotLoggedInError, SessionExpiredError,
            type CentiaAdminClient } from '@centia-io/sdk'
   import { createConfigstoreTokenStore } from '@centia-io/sdk/node'
   ```
   No package.json change (the dependency is a `file:` link; rebuilding the SDK
   makes `@centia-io/sdk/node` resolve).

## Verification

- **SDK:** `npx tsc --noEmit`, `npx vitest run`, `pnpm build`. Then:
  - `dist/centia-io-sdk.js` (main bundle) contains **no** `configstore`
    reference.
  - `dist/centia-io-sdk-node.js` exists and contains `createConfigstoreTokenStore`.
- **gc2-cli:** typecheck/build against the freshly built local SDK; confirm
  `@centia-io/sdk/node` resolves. If gc2-cli's `moduleResolution` does not honor
  `exports` subpaths, that is a risk to resolve during implementation (it uses
  oclif/TS; expected `bundler`/`node16`).

## Out of scope (follow-up)

- After `0.2.0` is published and installed in centia-app, remove
  `external: ['configstore','proper-lockfile']` from its `vite.config.ts`.
- Reclassifying `configstore`/`proper-lockfile` as optional/peer dependencies of
  the SDK (not required for this change).
