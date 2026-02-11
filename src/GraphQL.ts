/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";
import {GqlRequest, GqlResponse} from "./types/pgTypes";

export default class GraphQL {
    async request(request: GqlRequest): Promise<GqlResponse> {
        const response = await make(null, `graphql/schema/public`, 'POST', request)
        return await get(response, 200)
    }
}
