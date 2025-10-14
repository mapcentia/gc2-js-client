import {Gc2Service} from './services/gc2.services'
import {generatePkceChallenge, isLogin, setTokens, setOptions, clearNonce} from './util/utils'
import {CodeFlowOptions, clearTokens, clearOptions} from "./util/utils";
import {getStorage} from './util/storage'

export default class CodeFlow {
    options: CodeFlowOptions
    service: Gc2Service

    constructor(options: CodeFlowOptions) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async redirectHandle(): Promise<boolean> {
        const url: string = window.location.search
        const queryParams = new URLSearchParams(url)

        const error = queryParams.get('error')
        if (error) {
            throw new Error(`Failed to redirect: ${url}`)
        }

        const code = queryParams.get('code')
        if (code) {
            const state = queryParams.get('state')
            if (state !== getStorage().getItem('state')) {
                throw new Error('Possible CSRF attack. Aborting login!')
            }
            try {
                const {
                    access_token,
                    refresh_token,
                    id_token,
                } = await this.service.getAuthorizationCodeToken(code, getStorage().getItem('codeVerifier'))
                setTokens({accessToken: access_token, refreshToken: refresh_token, idToken: id_token})
                setOptions({
                    clientId: this.options.clientId,
                    host: this.options.host,
                    redirectUri: this.options.redirectUri
                })
                getStorage().removeItem('state')
                getStorage().removeItem('codeVerifier')

                // Remove state and code from the redirect url
                const params = new URLSearchParams(window.location.search);
                params.delete('code')
                params.delete('state')
                const loc = window.location
                const newUrl = loc.origin + loc.pathname + (params.size > 0 ? '?' + params.toString() : '')
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
        getStorage().setItem("state", state)
        getStorage().setItem("codeVerifier", codeVerifier);
        // @ts-ignore
        window.location = this.service.getAuthorizationCodeURL(
            codeChallenge,
            state,
        );
    }

    public signOut(): void {
        this.clear()
        // @ts-ignore
        window.location = this.service.getSignOutURL();
    }

    public clear(): void {
        clearTokens()
        clearOptions()
        clearNonce()
    }
}
