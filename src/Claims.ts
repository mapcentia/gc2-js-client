/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import {claims, getTokens} from "./util/utils";

export default class Claims {
    get() {
        const tokens = getTokens().accessToken
        return claims(tokens);
    }
}
