import {Gc2Service} from './services/gc2.services'
import {generatePkceChallenge, isLogin, setTokens, setOptions} from './util/utils'
import querystring from "querystring";
import {CodeFlowOptions, clearTokens, clearOptions} from "./util/utils";


export default class CodeFlow {
    options: CodeFlowOptions
    service: Gc2Service

    constructor(options: CodeFlowOptions) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async redirectHandle(): Promise<boolean> {
        const url = window.location.search.substring(1)
        const queryString = querystring.parse(url)

        if (queryString.error) {
            throw new Error(`Failed to redirect: ${url}`)
        }

        if (queryString.code) {
            if (queryString.state !== localStorage.getItem('state')) {
                throw new Error('Possible CSRF attack. Aborting login!')
            }
            try {
                const {
                    access_token,
                    refresh_token,
                    id_token,
                } = await this.service.getAuthorizationCodeToken(queryString.code, localStorage.getItem('codeVerifier'))
                setTokens({accessToken: access_token, refreshToken: refresh_token, idToken: id_token})
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
                throw new Error(e.message)
            }
        }
        return await isLogin(this.service);
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
        clearTokens()
        clearOptions()
        // @ts-ignore
        window.location = this.service.getSignOutURL();
    }
}
