import {Gc2Service} from './services/gc2.services'
import {SignUpOptions} from './util/utils'

export default class SignUp {
    options: SignUpOptions
    service: Gc2Service

    constructor(options: SignUpOptions) {
        this.options = options
        this.service = new Gc2Service(options)
    }

    public async signUp(): Promise<void> {
        // @ts-ignore
        window.location = this.service.getSignUpURL();
    }
}
