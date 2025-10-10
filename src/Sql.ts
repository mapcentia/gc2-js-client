import make from "./util/make-request";
import get from "./util/get-response";
import {SqlRequest, SQLResponse} from "./types/pgTypes";

export default class Sql {
    async exec(request: SqlRequest): Promise<SQLResponse> {
        const response = await make('4', `sql`, 'POST', request)
        return await get(response, 200)
    }
}
