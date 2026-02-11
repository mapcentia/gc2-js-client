/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";

export default class Stats {
    async get(): Promise<any> {
        const response = await make('4', `stats`, 'GET', null)
        return await get(response, 200)
    }
}
