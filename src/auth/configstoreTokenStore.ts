/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import { homedir } from 'node:os'
import { join } from 'node:path'
import type { StoredCredentials, TokenStore } from './types'

/**
 * File-backed TokenStore using `configstore` (~/.config/configstore/<name>.json)
 * with cross-process advisory locking via `proper-lockfile`.
 *
 * Node-only. The dynamic imports keep `configstore` and `proper-lockfile` out
 * of browser bundles even when this module is imported through the SDK barrel.
 */
export function createConfigstoreTokenStore(name = 'gc2-env'): TokenStore {
    let configstoreInstance: any | null = null

    async function getConfigstore(): Promise<any> {
        if (configstoreInstance) return configstoreInstance
        const mod = await import('configstore')
        const Configstore: any = (mod as any).default ?? mod
        // Resolve XDG_CONFIG_HOME at call time (not at module-load time) so
        // that test fixtures setting process.env.XDG_CONFIG_HOME are respected.
        const xdgConfig = process.env.XDG_CONFIG_HOME || join(homedir(), '.config')
        const configPath = join(xdgConfig, 'configstore', `${name}.json`)
        configstoreInstance = new Configstore(name, undefined, { configPath })
        return configstoreInstance
    }

    return {
        async get(): Promise<StoredCredentials> {
            const cs = await getConfigstore()
            const result: StoredCredentials = {}
            const token = cs.get('token')
            const refresh_token = cs.get('refresh_token')
            const host = cs.get('host')
            if (token !== undefined) result.token = token
            if (refresh_token !== undefined) result.refresh_token = refresh_token
            if (host !== undefined) result.host = host
            return result
        },
        async set(_patch: Partial<StoredCredentials>): Promise<void> {
            throw new Error('not implemented')
        },
    }
}
