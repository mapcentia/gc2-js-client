import make from "./util/make-request";
import get from "./util/get-response";
import {SqlRequest, SQLResponse, DataRow, TypedSqlRequest} from "./types/pgTypes";

export default class Sql {
    // Overload for typed request: preserves row typing
    async exec<R extends DataRow>(request: TypedSqlRequest<R>): Promise<SQLResponse<R>>;
    // Fallback overload: plain SqlRequest returns generic DataRow
    async exec(request: SqlRequest): Promise<SQLResponse<DataRow>>;
    // Implementation
    async exec(request: SqlRequest): Promise<SQLResponse<any>> {
        const response = await make('4', `sql`, 'POST', request)
        return await get(response, 200)
    }
}
