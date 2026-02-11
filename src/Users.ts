/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";

export default class Users {
    async get(user: string): Promise<any> {
        const response = await make('4', `users/${user}`, 'GET', null)
        return await get(response, 200)
    }
}
