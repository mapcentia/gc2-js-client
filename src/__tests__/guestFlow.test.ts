import {describe, it, expect, vi, afterEach} from 'vitest'
import GuestFlow from '../GuestFlow'
import {getTokens, getOptions, clearTokens, clearOptions} from '../util/utils'

const tokenResponse = {
    access_token: 'guest-access',
    refresh_token: 'guest-refresh',
    token_type: 'bearer',
    expires_in: 3600,
    scope: '',
}

function stubFetch(status: number, body: unknown) {
    const fetchFn = vi.fn().mockResolvedValue({
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
        text: async () => JSON.stringify(body),
    } as unknown as Response)
    vi.stubGlobal('fetch', fetchFn)
    return fetchFn
}

afterEach(() => {
    vi.unstubAllGlobals()
    clearTokens()
    clearOptions()
})

describe('GuestFlow', () => {
    it('signIn posts database and client_id to the guest endpoint and stores tokens', async () => {
        const fetchFn = stubFetch(201, tokenResponse)
        const flow = new GuestFlow({
            host: 'https://api.example.com',
            clientId: 'my-client',
            database: 'my_database',
        })

        await flow.signIn()

        const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
        expect(url).toBe('https://api.example.com/api/v4/oauth/guest')
        expect(init.method).toBe('POST')
        expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json')
        expect(JSON.parse(init.body as string)).toEqual({
            database: 'my_database',
            client_id: 'my-client',
        })
        expect(getTokens()).toMatchObject({accessToken: 'guest-access', refreshToken: 'guest-refresh'})
        expect(getOptions().host).toBe('https://api.example.com')
        expect(getOptions().clientId).toBe('my-client')
    })

    it('signIn sends client_secret for confidential clients', async () => {
        const fetchFn = stubFetch(201, tokenResponse)
        const flow = new GuestFlow({
            host: 'https://api.example.com',
            clientId: 'my-client',
            clientSecret: 'shh',
            database: 'my_database',
        })

        await flow.signIn()

        const [, init] = fetchFn.mock.calls[0] as [string, RequestInit]
        expect(JSON.parse(init.body as string)).toEqual({
            database: 'my_database',
            client_id: 'my-client',
            client_secret: 'shh',
        })
    })

    it('signIn throws on error responses', async () => {
        stubFetch(404, {error: 'NO_DEFAULT_USER_FOUND'})
        const flow = new GuestFlow({
            host: 'https://api.example.com',
            clientId: 'my-client',
            database: 'my_database',
        })

        await expect(flow.signIn()).rejects.toThrow(/404/)
    })

    it('signOut clears stored tokens', async () => {
        stubFetch(201, tokenResponse)
        const flow = new GuestFlow({
            host: 'https://api.example.com',
            clientId: 'my-client',
            database: 'my_database',
        })
        await flow.signIn()

        flow.signOut()

        expect(getTokens().accessToken).toBeFalsy()
    })
})
