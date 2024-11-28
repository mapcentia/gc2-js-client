import {Gc2Service,} from './services/gc2.services'
import {generatePkceChallenge, isLogin, setTokens, setOptions} from './util/utils'
import querystring from "querystring";
import {Options} from "./util/utils";


export default class CodeFlow {
    options: Options
    service: Gc2Service

    constructor(options: Options) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async redirectHandle(): Promise<boolean | string> {
        const url = window.location.search.substring(1)
        const queryString = querystring.parse(url)

        if (queryString.error) {
            return Promise.reject(new Error(`Failed to redirect: ${url}`))
        }

        if (queryString.code) {
            if (queryString.state !== localStorage.getItem('state')) {
                return Promise.reject('Possible CSRF attack. Aborting login???')
            }
            try {
                const {
                    access_token,
                    refresh_token
                } = await this.service.getAuthorizationCodeToken(queryString.code, localStorage.getItem('codeVerifier'))
                setTokens({accessToken: access_token, refreshToken: refresh_token})
                setOptions({
                    clientId: this.options.clientId,
                    host: this.options.host,
                    redirectUri: this.options.redirectUri
                })
                localStorage.removeItem('state')
                localStorage.removeItem('codeVerifier')

                // Remove state and code from the redirect url
                const params = new URLSearchParams(window.location.search);
                params.delete('code')
                params.delete('state')
                const loc = window.location
                const newUrl = loc.origin + loc.pathname + (params.size > 1 ? '?' + params.toString() : '')
                history.pushState(null, '', newUrl);

                return Promise.resolve(true)

            } catch (e: any) {
                return Promise.reject(`Failed to redirect: ${url}`)
            }
        }
        if (await isLogin(this.service)) {

            return Promise.resolve(true)
        }

        return Promise.resolve(false)
    }

    public async signIn(): Promise<void> {
        const {state, codeVerifier, codeChallenge} = await generatePkceChallenge()
        localStorage.setItem("state", state)
        localStorage.setItem("codeVerifier", codeVerifier);
        // @ts-ignore
        window.location = this.service.getAuthorizationCodeURL(
            codeChallenge,
            state,
        );
    }

    public signOut(): void {
        this.service.clearTokens()
        this.service.clearOptions()
    }
}
