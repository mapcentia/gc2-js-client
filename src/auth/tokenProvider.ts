/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import { jwtDecode } from '../util/jwt-decode'
import type { JwtPayload } from '../util/jwt-decode'
import type { AuthService, StoredCredentials, TokenProvider, TokenStore } from './types'
import { NotLoggedInError, SessionExpiredError } from './errors'

const DEFAULT_SKEW_SECONDS = 30

export interface CreateTokenProviderOptions {
    store: TokenStore
    authService: AuthService
    expirySkewSeconds?: number
}

export function createTokenProvider(opts: CreateTokenProviderOptions): TokenProvider {
    const skew = opts.expirySkewSeconds ?? DEFAULT_SKEW_SECONDS
    let inFlight: Promise<string> | null = null

    async function refresh(refreshToken: string): Promise<string> {
        const refreshed = await opts.authService.getRefreshToken(refreshToken)
        const patch: Partial<StoredCredentials> = { token: refreshed.access_token }
        if (refreshed.refresh_token) patch.refresh_token = refreshed.refresh_token
        await opts.store.set(patch)
        return refreshed.access_token
    }

    return {
        async getAccessToken(): Promise<string> {
            const creds = await opts.store.get()
            if (!creds.token) throw new NotLoggedInError()
            if (!isExpired(creds.token, skew)) return creds.token

            if (!creds.refresh_token || isExpired(creds.refresh_token, skew)) {
                throw new SessionExpiredError()
            }

            if (!inFlight) {
                inFlight = refresh(creds.refresh_token).finally(() => { inFlight = null })
            }
            return inFlight
        },
    }
}

function isExpired(jwt: string, skewSeconds: number): boolean {
    const { exp } = jwtDecode<JwtPayload>(jwt)
    if (!exp) return false
    const nowSec = Math.floor(Date.now() / 1000)
    return nowSec + skewSeconds >= exp
}
