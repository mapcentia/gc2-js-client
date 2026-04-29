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

/**
 * Build a {@link TokenProvider} that returns a fresh access token, refreshing
 * via `opts.authService` and persisting the result to `opts.store` whenever
 * the cached token is within `expirySkewSeconds` of expiry.
 *
 * **Behaviour:**
 * - If the store has no access token, throws {@link NotLoggedInError}.
 * - If the access token is fresh, returns it immediately.
 * - If expired and the refresh token is missing or expired, throws
 *   {@link SessionExpiredError}.
 * - Otherwise calls `opts.authService.getRefreshToken(refresh_token)`,
 *   persists `{ token, refresh_token? }` via `opts.store.set()`, and
 *   returns the new access token.
 *
 * **In-process concurrency.** Multiple concurrent `getAccessToken()` calls
 * during a refresh share a single in-flight promise; the auth service is
 * called exactly once per refresh cycle. On failure the in-flight slot
 * clears so the next call retries.
 *
 * **Cross-process concurrency — known limitation.** This function does NOT
 * coordinate refresh across processes. Two processes that share a
 * configstore-backed {@link TokenStore} can each independently observe an
 * expired access token, both call `getRefreshToken` against the same
 * refresh token, and the OAuth provider will reject the second call with
 * `invalid_grant` once the refresh token rotates. Callers that run
 * multiple processes concurrently against the same store should treat
 * `invalid_grant` as a transient failure and re-read the store before
 * retrying. Closing this gap requires holding the file lock across the
 * network refresh, which the current implementation does not do.
 *
 * @param opts - Provider configuration.
 * @param opts.store - Where credentials are read from and written to.
 * @param opts.authService - Object exposing
 *                           `getRefreshToken(refreshToken)`. The existing
 *                           `Gc2Service` (returned by `CodeFlow#service`)
 *                           satisfies this structurally.
 * @param opts.expirySkewSeconds - How many seconds before `exp` to treat a
 *                                 JWT as expired. Default `30`.
 * @returns A {@link TokenProvider} whose `getAccessToken()` resolves to a
 *          non-expired access token, refreshing if necessary.
 */
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
