# Node-only Subpath Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move `createConfigstoreTokenStore` behind a `@centia-io/sdk/node` subpath so the main `@centia-io/sdk` entry is browser-safe, and migrate gc2-cli to the subpath.

**Architecture:** Add a dedicated Node-only entry (`src/node.ts`) exporting `createConfigstoreTokenStore`, remove it from the main entry/barrel, wire a second tsdown entry and a `./node` package export, and ship a root `node.d.ts` types shim so classic-resolution consumers (gc2-cli) resolve the subpath. Then split gc2-cli's import.

**Tech Stack:** TypeScript, tsdown (esm/cjs/umd, `platform: browser`), vitest, pnpm; oclif (gc2-cli).

## Global Constraints

- SDK version bump `0.1.3` → `0.2.0` (breaking change for Node consumers).
- Only `createConfigstoreTokenStore` moves. `createTokenProvider`, `NotLoggedInError`, `SessionExpiredError`, and all type exports stay on the main entry.
- The source file `src/auth/configstoreTokenStore.ts` stays in place (tests import it by relative path).
- The main bundle `dist/centia-io-sdk.js` must contain no `configstore` reference after the change.
- gc2-cli uses classic TS module resolution (`module: commonjs`, no `moduleResolution`), which ignores `package.json` `exports` for type resolution — so the SDK must also ship a root `node.d.ts` shim. gc2-cli's tsconfig must NOT be changed.
- gc2-cli's SDK dependency is a local link (`"@centia-io/sdk": "file:../gc2-js-client"`); rebuilding the SDK makes the subpath resolve. No gc2-cli package.json change.

---

### Task 1: SDK — move `createConfigstoreTokenStore` to `@centia-io/sdk/node`

**Repo:** `/home/mh/Source/gc2-js-client` (branch `feat/node-only-subpath`)

**Files:**
- Create: `src/node.ts`
- Create: `node.d.ts` (repo root)
- Modify: `src/index.ts` (export block at lines 128-133)
- Modify: `src/auth/index.ts`
- Modify: `tsdown.config.ts`
- Modify: `package.json` (`exports`, `version`, `files`)
- Modify (test): `src/__tests__/tokenProvider.test.ts`

**Interfaces:**
- Produces: subpath module `@centia-io/sdk/node` exporting `createConfigstoreTokenStore(name?: string): TokenStore` (used by Task 2). Source entry is `src/node.ts`.

- [ ] **Step 1: Update the test to express the new contract**

In `src/__tests__/tokenProvider.test.ts`, replace the `describe('public exports', ...)` block (currently asserting the main barrel exports `createConfigstoreTokenStore`) with:

```ts
describe('public exports', () => {
    it('re-exports browser-safe auth surface from the package barrel', async () => {
        const sdk = await import('../index')
        expect(typeof sdk.createTokenProvider).toBe('function')
        expect(sdk.NotLoggedInError).toBeDefined()
        expect(sdk.SessionExpiredError).toBeDefined()
    })

    it('does not expose the Node-only token store on the main entry', async () => {
        const sdk = await import('../index')
        expect((sdk as Record<string, unknown>).createConfigstoreTokenStore).toBeUndefined()
    })

    it('exposes createConfigstoreTokenStore from the node entry', async () => {
        const node = await import('../node')
        expect(typeof node.createConfigstoreTokenStore).toBe('function')
    })
})
```

- [ ] **Step 2: Run the test — verify it fails**

Run: `cd /home/mh/Source/gc2-js-client && npx vitest run src/__tests__/tokenProvider.test.ts`
Expected: FAIL — `../node` cannot be resolved (file does not exist yet) and/or the main entry still exposes `createConfigstoreTokenStore`.

- [ ] **Step 3: Create the Node-only entry**

Create `src/node.ts`:

```ts
/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 * Node-only entry point. Importing `@centia-io/sdk/node` pulls in the
 * configstore-backed token store, which uses Node-only APIs and must not be
 * bundled for the browser. Browser consumers use the main `@centia-io/sdk`
 * entry, which never references this module.
 */

export { createConfigstoreTokenStore } from './auth/configstoreTokenStore'
```

- [ ] **Step 4: Remove the export from the main entry**

In `src/index.ts`, change the auth re-export block (lines 128-133) from:

```ts
export {
    createTokenProvider,
    createConfigstoreTokenStore,
    NotLoggedInError,
    SessionExpiredError,
} from './auth'
```

to:

```ts
export {
    createTokenProvider,
    NotLoggedInError,
    SessionExpiredError,
} from './auth'
```

- [ ] **Step 5: Remove the re-export from the auth barrel**

In `src/auth/index.ts`, delete this line:

```ts
export { createConfigstoreTokenStore } from './configstoreTokenStore'
```

Leave the rest of `src/auth/index.ts` (createTokenProvider, errors, types) unchanged. The file `src/auth/configstoreTokenStore.ts` is NOT moved.

- [ ] **Step 6: Run the test — verify it passes**

Run: `cd /home/mh/Source/gc2-js-client && npx vitest run src/__tests__/tokenProvider.test.ts`
Expected: PASS (3 tests in the `public exports` block).

- [ ] **Step 7: Add the second tsdown entry**

In `tsdown.config.ts`, change the `entry` field from:

```ts
    entry: {
        'centia-io-sdk': './src/index.ts'
    },
```

to:

```ts
    entry: {
        'centia-io-sdk': './src/index.ts',
        'centia-io-sdk-node': './src/node.ts'
    },
```

Leave `external`, `platform`, `format`, etc. unchanged.

- [ ] **Step 8: Create the root types shim for classic resolution**

Create `node.d.ts` at the repo root (so classic-resolution consumers find `@centia-io/sdk/node` types on disk; `exports` is ignored by classic resolution):

```ts
export * from './dist/centia-io-sdk-node'
```

- [ ] **Step 9: Update package.json exports, version, and files**

In `package.json`:

Change `"version": "0.1.3"` to `"version": "0.2.0"`.

Replace the `exports` block with:

```jsonc
"exports": {
    ".": {
        "require": "./dist/centia-io-sdk.cjs",
        "import": "./dist/centia-io-sdk.js"
    },
    "./node": {
        "import": { "types": "./dist/centia-io-sdk-node.d.ts", "default": "./dist/centia-io-sdk-node.js" },
        "require": { "types": "./dist/centia-io-sdk-node.d.cts", "default": "./dist/centia-io-sdk-node.cjs" }
    },
    "./package.json": "./package.json"
},
```

Change the `files` array from `["dist"]` to:

```jsonc
"files": [
    "dist",
    "node.d.ts"
],
```

- [ ] **Step 10: Build**

Run: `cd /home/mh/Source/gc2-js-client && pnpm build`
Expected: build succeeds; `dist/` now contains `centia-io-sdk-node.js`, `centia-io-sdk-node.cjs`, `centia-io-sdk-node.d.ts`, `centia-io-sdk-node.d.cts` (plus maps/umd) alongside the existing `centia-io-sdk.*`.

- [ ] **Step 11: Verify the split**

Run:
```bash
cd /home/mh/Source/gc2-js-client
echo "main bundle references configstore? (expect none):"
grep -c "configstore" dist/centia-io-sdk.js || true
echo "node bundle has the function? (expect >=1):"
grep -c "createConfigstoreTokenStore" dist/centia-io-sdk-node.js || true
ls node.d.ts dist/centia-io-sdk-node.d.ts
```
Expected: `dist/centia-io-sdk.js` → `0` configstore references; `dist/centia-io-sdk-node.js` → `≥1`; both `node.d.ts` and `dist/centia-io-sdk-node.d.ts` exist.

- [ ] **Step 12: Typecheck + full test suite**

Run: `cd /home/mh/Source/gc2-js-client && npx tsc --noEmit && npx vitest run`
Expected: `tsc` shows only the 2 pre-existing errors (`src/SqlBuilder.ts:1062`, `src/util/utils.ts:73`) and nothing referencing `node.ts`/`index.ts`/`auth`; all vitest tests pass.

- [ ] **Step 13: Commit**

```bash
cd /home/mh/Source/gc2-js-client
git add src/node.ts node.d.ts src/index.ts src/auth/index.ts tsdown.config.ts package.json src/__tests__/tokenProvider.test.ts
git commit -m "feat(node): move createConfigstoreTokenStore to @centia-io/sdk/node

The main entry is now browser-safe (no configstore in dist/centia-io-sdk.js).
Node consumers import createConfigstoreTokenStore from @centia-io/sdk/node.
Ship a root node.d.ts shim so classic-resolution consumers resolve the
subpath. BREAKING: bump to 0.2.0.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: gc2-cli — migrate to the `@centia-io/sdk/node` subpath

**Repo:** `/home/mh/Source/gc2-cli`

**Files:**
- Modify: `src/centiaClient.ts` (import block at lines 8-18)

**Interfaces:**
- Consumes: `@centia-io/sdk/node` exporting `createConfigstoreTokenStore` (from Task 1). Requires Task 1 to be built first (the SDK is a `file:` link, so the built `dist/` + root `node.d.ts` are visible immediately).

- [ ] **Step 1: Split the import**

In `src/centiaClient.ts`, change the import block from:

```ts
import {
  CodeFlow,
  createCentiaAdminClient,
  createConfigstoreTokenStore,
  createTokenProvider,
  isCentiaApiError,
  NotLoggedInError,
  SessionExpiredError,
  type CentiaAdminClient,
} from '@centia-io/sdk'
```

to:

```ts
import {
  CodeFlow,
  createCentiaAdminClient,
  createTokenProvider,
  isCentiaApiError,
  NotLoggedInError,
  SessionExpiredError,
  type CentiaAdminClient,
} from '@centia-io/sdk'
import {createConfigstoreTokenStore} from '@centia-io/sdk/node'
```

Leave the rest of the file (including `export const tokenStore = createConfigstoreTokenStore('gc2-env')`) unchanged.

- [ ] **Step 2: Typecheck against the freshly built SDK**

Run: `cd /home/mh/Source/gc2-cli && npx tsc --noEmit`
Expected: no error about `Cannot find module '@centia-io/sdk/node'` and no new error on the `createConfigstoreTokenStore` usage. (Pre-existing errors elsewhere in gc2-cli, if any, are out of scope — report them but do not fix.)

If `@centia-io/sdk/node` does not resolve, first run `cd /home/mh/Source/gc2-cli && pnpm install` to refresh the link, then re-run the typecheck. The root `node.d.ts` shim from Task 1 is what makes classic resolution find the subpath types.

- [ ] **Step 3: Build**

Run: `cd /home/mh/Source/gc2-cli && npx tsc -b`
Expected: build succeeds (emits to `lib/`).

- [ ] **Step 4: Commit**

```bash
cd /home/mh/Source/gc2-cli
git add src/centiaClient.ts
git commit -m "refactor: import createConfigstoreTokenStore from @centia-io/sdk/node

@centia-io/sdk 0.2.0 moved the Node-only configstore token store to a
/node subpath. Import it from there; the rest stays on the main entry.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

- **Spec coverage:**
  - New `src/node.ts` → Task 1 Step 3. ✓
  - Remove from `src/index.ts` → Task 1 Step 4. ✓
  - Remove from `src/auth/index.ts` → Task 1 Step 5. ✓
  - tsdown second entry → Task 1 Step 7. ✓
  - package.json `./node` export (per-condition types) + version 0.2.0 + files → Task 1 Steps 8-9. ✓
  - Root `node.d.ts` shim for classic resolution (constraint) → Task 1 Step 8, files in Step 9. ✓
  - Update `tokenProvider.test.ts` public-exports + add node-entry test → Task 1 Step 1. ✓
  - gc2-cli import split → Task 2 Step 1. ✓
  - Verification: main bundle has no configstore; node bundle has the function → Task 1 Step 11. ✓
  - gc2-cli typecheck resolves subpath → Task 2 Step 2. ✓
- **Placeholder scan:** No TBD/TODO; all code blocks complete. ✓
- **Type consistency:** `createConfigstoreTokenStore` named identically across `src/node.ts`, the test, and gc2-cli's import; subpath `@centia-io/sdk/node` identical in package.json exports, root `node.d.ts` target, and gc2-cli import. ✓
- **Note:** `node.d.ts` re-exports `./dist/centia-io-sdk-node`, which only exists after Task 1 Step 10 (build). The SDK's own `tsc --noEmit` (Step 12) does NOT check it — the SDK tsconfig is `include: ["src"]` and `node.d.ts` sits at the repo root, outside `src`. It is consumed only by downstream classic-resolution typechecks (gc2-cli, Task 2) after the build exists.
