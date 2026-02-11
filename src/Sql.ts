/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import make from "./util/make-request";
import get from "./util/get-response";
import {SqlRequest, SqlResponse, DataRow, TypedSqlRequest} from "./types/pgTypes";

export default class Sql {
    // Overload for typed request: preserves row typing
    async exec<R extends DataRow>(request: TypedSqlRequest<R>): Promise<SqlResponse<R>>;
    // Fallback overload: plain SqlRequest returns generic DataRow
    async exec(request: SqlRequest): Promise<SqlResponse<DataRow>>;
    // Implementation
    async exec(request: SqlRequest): Promise<SqlResponse<any>> {
        const response = await make('4', `sql`, 'POST', request)
        return await get(response, 200)
    }
}
