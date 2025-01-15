import {Gc2Service,} from './services/gc2.services'
import { isLogin, setTokens, setOptions, Options} from './util/utils'

export default class PasswordFlow {
    // service: Gc2Service
    //
    // constructor(options: Options) {
    //     this.service = new Gc2Service(options)
    // }
    //
    // public async signIn(user: string, password: string, database: string): Promise<void> {
    //     const {access_token, refresh_token} = await this.service.getPasswordToken(user, password, database)
    //     setTokens({accessToken: access_token, refreshToken: refresh_token})
    // }
    //
    // public signOut(): void {
    //     this.service.clearTokens()
    // }
}
