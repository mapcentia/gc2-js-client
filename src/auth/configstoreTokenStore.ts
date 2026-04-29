/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { StoredCredentials, TokenStore } from './types'

const LOCK_RETRIES = 5
const LOCK_RETRY_MIN_MS = 100
const LOCK_RETRY_MAX_MS = 500
const LOCK_STALE_MS = 10_000

/**
 * File-backed TokenStore using `configstore` (~/.config/configstore/<name>.json)
 * with cross-process advisory locking via `proper-lockfile`.
 *
 * In-process correctness: a serial promise chain on `set()` ensures concurrent
 * same-process calls do not race on the shared configstore cache.
 *
 * Cross-process correctness: `proper-lockfile` serializes the read-merge-write
 * critical section across processes.
 *
 * Node-only. The dynamic imports keep `configstore` and `proper-lockfile` out
 * of browser bundles even when this module is imported through the SDK barrel.
 */
export function createConfigstoreTokenStore(name = 'gc2-env'): TokenStore {
    let configstoreInstance: any | null = null
    let setChain: Promise<void> = Promise.resolve()

    async function getConfigstore(): Promise<any> {
        if (configstoreInstance) return configstoreInstance
        const mod = await import('configstore')
        const Configstore: any = (mod as any).default ?? mod
        const { homedir } = await import('node:os')
        const { join } = await import('node:path')
        // Resolve XDG_CONFIG_HOME at call time (not at module-load time) so
        // that test fixtures setting process.env.XDG_CONFIG_HOME are respected.
        const xdgConfig = process.env.XDG_CONFIG_HOME || join(homedir(), '.config')
        const configPath = join(xdgConfig, 'configstore', `${name}.json`)
        configstoreInstance = new Configstore(name, undefined, { configPath })
        return configstoreInstance
    }

    async function getLockfile(): Promise<typeof import('proper-lockfile')> {
        const mod = await import('proper-lockfile')
        return ((mod as any).default ?? mod) as typeof import('proper-lockfile')
    }

    function readAll(cs: any): StoredCredentials {
        const result: StoredCredentials = {}
        const token = cs.get('token')
        const refresh_token = cs.get('refresh_token')
        const host = cs.get('host')
        if (token !== undefined) result.token = token
        if (refresh_token !== undefined) result.refresh_token = refresh_token
        if (host !== undefined) result.host = host
        return result
    }

    async function doLockedSet(patch: Partial<StoredCredentials>): Promise<void> {
        const cs = await getConfigstore()
        const lockfile = await getLockfile()
        const filePath: string = cs.path

        // Ensure the file (and its directory) exist so proper-lockfile has
        // something to anchor on. `wx` is atomic create-if-not-exists, so this
        // is safe even if another process is racing to create the same file.
        const { mkdirSync, writeFileSync } = await import('node:fs')
        const { dirname } = await import('node:path')
        try {
            mkdirSync(dirname(filePath), { recursive: true })
            writeFileSync(filePath, '{}', { flag: 'wx' })
        } catch (e: any) {
            if (e?.code !== 'EEXIST') throw e
        }

        // realpath:false skips symlink resolution. configstore returns an
        // already-absolute path, and resolving symlinks would force an extra
        // stat (and breaks on macOS test tmpdirs which are symlinks).
        const release = await lockfile.lock(filePath, {
            retries: {
                retries: LOCK_RETRIES,
                minTimeout: LOCK_RETRY_MIN_MS,
                maxTimeout: LOCK_RETRY_MAX_MS,
                factor: 2,
            },
            stale: LOCK_STALE_MS,
            realpath: false,
        })

        try {
            // Force configstore to re-read the on-disk state so we merge
            // against the latest cross-process value, not a stale cache.
            configstoreInstance = null
            const fresh = await getConfigstore()
            const merged: StoredCredentials = { ...readAll(fresh), ...patch }
            ;(fresh as any).all = merged
        } finally {
            await release()
        }
    }

    return {
        async get(): Promise<StoredCredentials> {
            const cs = await getConfigstore()
            return readAll(cs)
        },

        async set(patch: Partial<StoredCredentials>): Promise<void> {
            const next = setChain.then(() => doLockedSet(patch))
            // Don't poison the chain on a rejection; the original error still
            // propagates via `next` to the caller.
            setChain = next.catch(() => {})
            return next
        },
    }
}
