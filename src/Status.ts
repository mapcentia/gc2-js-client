/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import {getTokens} from "./util/utils";

export default class Status {
    isAuth() {
        const tokens = getTokens()
        return !(!tokens.accessToken && !tokens.refreshToken);
    }

    getTokens() {
        return getTokens()
    }
}
