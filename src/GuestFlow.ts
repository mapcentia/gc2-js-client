/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import {Gc2Service} from './services/gc2.services'
import {setTokens, setOptions, GuestFlowOptions, clearTokens, clearOptions, clearNonce} from './util/utils'

/**
 * Guest token flow. Issues access/refresh tokens for the database's default
 * user (the sub-user used for anonymous access) without any user credentials.
 * `clientSecret` is only required when the OAuth client is not public.
 */
export default class GuestFlow {
    options: GuestFlowOptions
    service: Gc2Service

    constructor(options: GuestFlowOptions) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async signIn(): Promise<void> {
        const {access_token, refresh_token} = await this.service.getGuestToken()
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
