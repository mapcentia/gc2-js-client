/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { GetTokenResponse } from '../util/utils'

export interface StoredCredentials {
    token?: string
    refresh_token?: string
    host?: string
    user?: string
    database?: string
    superUser?: boolean
}

export interface TokenStore {
    get(): Promise<StoredCredentials>
    set(patch: Partial<StoredCredentials>): Promise<void>
}

export interface TokenProvider {
    getAccessToken(): Promise<string>
}

/**
 * Minimal structural type for the auth service. The existing `Gc2Service`
 * (returned by `CodeFlow#service` and `PasswordFlow#service`) satisfies this.
 */
export interface AuthService {
    getRefreshToken(refreshToken: string): Promise<GetTokenResponse>
}
