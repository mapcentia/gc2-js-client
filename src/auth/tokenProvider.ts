/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import { jwtDecode } from '../util/jwt-decode'
import type { JwtPayload } from '../util/jwt-decode'
import type { AuthService, TokenProvider, TokenStore } from './types'
import { NotLoggedInError, SessionExpiredError } from './errors'

const DEFAULT_SKEW_SECONDS = 30

export interface CreateTokenProviderOptions {
    store: TokenStore
    authService: AuthService
    expirySkewSeconds?: number
}

export function createTokenProvider(opts: CreateTokenProviderOptions): TokenProvider {
    const skew = opts.expirySkewSeconds ?? DEFAULT_SKEW_SECONDS

    return {
        async getAccessToken(): Promise<string> {
            const { token } = await opts.store.get()
            if (!token) throw new NotLoggedInError()
            if (!isExpired(token, skew)) return token
            // Refresh path implemented in later tasks.
            throw new SessionExpiredError()
        },
    }
}

function isExpired(jwt: string, skewSeconds: number): boolean {
    const { exp } = jwtDecode<JwtPayload>(jwt)
    if (!exp) return false
    const nowSec = Math.floor(Date.now() / 1000)
    return nowSec + skewSeconds >= exp
}
