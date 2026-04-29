import { describe, it, expect, vi } from 'vitest'
import { createTokenProvider } from '../auth/tokenProvider'
import { NotLoggedInError, SessionExpiredError } from '../auth/errors'
import type { TokenStore, AuthService, StoredCredentials } from '../auth/types'

/**
 * Build a JWT with the given expiry (seconds since epoch). Signature is bogus —
 * we only ever decode the payload for `exp`.
 */
function makeJwt(expSeconds: number): string {
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ exp: expSeconds })).toString('base64url')
    return `${header}.${payload}.sig`
}

function memoryStore(initial: StoredCredentials = {}): TokenStore & { _data: StoredCredentials, _writes: Array<Partial<StoredCredentials>> } {
    const data: StoredCredentials = { ...initial }
    const writes: Array<Partial<StoredCredentials>> = []
    return {
        _data: data,
        _writes: writes,
        async get() { return { ...data } },
        async set(patch) {
            writes.push(patch)
            Object.assign(data, patch)
        },
    }
}

describe('createTokenProvider', () => {
    it('returns the cached access token when it is not expired', async () => {
        const future = Math.floor(Date.now() / 1000) + 3600
        const token = makeJwt(future)
        const store = memoryStore({ token, refresh_token: 'r1' })
        const authService: AuthService = {
            getRefreshToken: vi.fn(),
        }

        const provider = createTokenProvider({ store, authService })
        const got = await provider.getAccessToken()

        expect(got).toBe(token)
        expect(authService.getRefreshToken).not.toHaveBeenCalled()
        expect(store._writes).toHaveLength(0)
    })

    it('throws NotLoggedInError when the store has no access token', async () => {
        const store = memoryStore({})
        const authService: AuthService = { getRefreshToken: vi.fn() }
        const provider = createTokenProvider({ store, authService })

        await expect(provider.getAccessToken()).rejects.toBeInstanceOf(NotLoggedInError)
        expect(authService.getRefreshToken).not.toHaveBeenCalled()
    })

    it('refreshes and persists new access + refresh tokens when access token is expired', async () => {
        const past = Math.floor(Date.now() / 1000) - 60
        const future = Math.floor(Date.now() / 1000) + 3600
        const oldAccess = makeJwt(past)
        const oldRefresh = makeJwt(future) // not expired
        const newAccess = makeJwt(future)
        const newRefresh = makeJwt(future + 86400)

        const store = memoryStore({ token: oldAccess, refresh_token: oldRefresh })
        const authService: AuthService = {
            getRefreshToken: vi.fn(async () => ({
                access_token: newAccess,
                refresh_token: newRefresh,
                expires_in: 3600,
                refresh_expires_in: 86400,
                token_type: 'Bearer',
                'not-before-policy': 0,
                session_state: 's',
                scope: '',
            })),
        }

        const provider = createTokenProvider({ store, authService })
        const got = await provider.getAccessToken()

        expect(got).toBe(newAccess)
        expect(authService.getRefreshToken).toHaveBeenCalledWith(oldRefresh)
        expect(store._data.token).toBe(newAccess)
        expect(store._data.refresh_token).toBe(newRefresh)
        expect(store._writes).toHaveLength(1)
    })

    it('throws SessionExpiredError when access token is expired and refresh token is missing', async () => {
        const past = Math.floor(Date.now() / 1000) - 60
        const store = memoryStore({ token: makeJwt(past) })
        const authService: AuthService = { getRefreshToken: vi.fn() }
        const provider = createTokenProvider({ store, authService })

        await expect(provider.getAccessToken()).rejects.toBeInstanceOf(SessionExpiredError)
        expect(authService.getRefreshToken).not.toHaveBeenCalled()
    })

    it('throws SessionExpiredError when refresh token is also expired', async () => {
        const past = Math.floor(Date.now() / 1000) - 60
        const store = memoryStore({ token: makeJwt(past), refresh_token: makeJwt(past) })
        const authService: AuthService = { getRefreshToken: vi.fn() }
        const provider = createTokenProvider({ store, authService })

        await expect(provider.getAccessToken()).rejects.toBeInstanceOf(SessionExpiredError)
        expect(authService.getRefreshToken).not.toHaveBeenCalled()
    })

    it('deduplicates concurrent getAccessToken calls during refresh', async () => {
        const past = Math.floor(Date.now() / 1000) - 60
        const future = Math.floor(Date.now() / 1000) + 3600
        const oldAccess = makeJwt(past)
        const oldRefresh = makeJwt(future)
        const newAccess = makeJwt(future)

        const store = memoryStore({ token: oldAccess, refresh_token: oldRefresh })
        const refreshFn = vi.fn(async () => {
            await new Promise(r => setTimeout(r, 20))
            return {
                access_token: newAccess,
                refresh_token: oldRefresh,
                expires_in: 3600,
                refresh_expires_in: 86400,
                token_type: 'Bearer',
                'not-before-policy': 0,
                session_state: 's',
                scope: '',
            }
        })
        const authService: AuthService = { getRefreshToken: refreshFn }

        const provider = createTokenProvider({ store, authService })
        const [a, b, c] = await Promise.all([
            provider.getAccessToken(),
            provider.getAccessToken(),
            provider.getAccessToken(),
        ])

        expect(a).toBe(newAccess)
        expect(b).toBe(newAccess)
        expect(c).toBe(newAccess)
        expect(refreshFn).toHaveBeenCalledTimes(1)
        expect(store._writes).toHaveLength(1)
    })

    it('clears the in-flight slot on refresh failure so the next call retries', async () => {
        const past = Math.floor(Date.now() / 1000) - 60
        const future = Math.floor(Date.now() / 1000) + 3600
        const store = memoryStore({ token: makeJwt(past), refresh_token: makeJwt(future) })
        const newAccess = makeJwt(future)
        const refreshFn = vi.fn()
            .mockRejectedValueOnce(new Error('network'))
            .mockResolvedValueOnce({
                access_token: newAccess,
                refresh_token: makeJwt(future),
                expires_in: 3600,
                refresh_expires_in: 86400,
                token_type: 'Bearer',
                'not-before-policy': 0,
                session_state: 's',
                scope: '',
            })
        const provider = createTokenProvider({ store, authService: { getRefreshToken: refreshFn } })

        await expect(provider.getAccessToken()).rejects.toThrow('network')
        await expect(provider.getAccessToken()).resolves.toBe(newAccess)
        expect(refreshFn).toHaveBeenCalledTimes(2)
    })
})
