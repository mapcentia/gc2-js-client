/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";
import {GraphqlRequest, GraphqlResponse} from "./types/pgTypes";

export default class GraphQL {
    async request(request: GraphqlRequest): Promise<GraphqlResponse> {
        const response = await make(null, `graphql/schema/public`, 'POST', request)
        return await get(response, 200)
    }
}
