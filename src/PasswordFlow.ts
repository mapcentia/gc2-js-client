import {Gc2Service,} from './services/gc2.services'
import {isLogin, setTokens, setOptions, PasswordFlowOptions, clearTokens, clearOptions, clearNonce} from './util/utils'

export default class PasswordFlow {
    options: PasswordFlowOptions
    service: Gc2Service

    constructor(options: PasswordFlowOptions) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async signIn(): Promise<void> {
        const {access_token, refresh_token} = await this.service.getPasswordToken()
        setTokens({accessToken: access_token, refreshToken: refresh_token})
        setOptions({
            clientId: this.options.clientId,
            host: this.options.host,
            redirectUri: '',
            clientSecret: this.options.clientSecret,
        })
    }

    public signOut(): void {
        this.clear()
    }

    public clear(): void {
        clearTokens()
        clearOptions()
        clearNonce()
    }
}
