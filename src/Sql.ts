/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";
import {SqlRequest, SqlResponse, DataRow, TypedSqlRequest} from "./types/pgTypes";

export default class Sql {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    // Overload for typed request: preserves row typing
    async exec<R extends DataRow>(request: TypedSqlRequest<R>): Promise<SqlResponse<R>>;
    // Fallback overload: plain SqlRequest returns generic DataRow
    async exec(request: SqlRequest): Promise<SqlResponse<DataRow>>;
    // Implementation
    async exec(request: SqlRequest): Promise<SqlResponse<any>> {
        return this.client.request({
            path: 'api/v4/sql',
            method: 'POST',
            body: request,
        });
    }
}
