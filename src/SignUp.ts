/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

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
        window.location.assign(this.service.getSignUpURL())
    }
}
