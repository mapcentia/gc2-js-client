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
})
