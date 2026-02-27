/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import type { CentiaHttpClient } from "./http/client";
import { getLegacyClient } from "./http/legacy";

export default class Tables {
    private client: CentiaHttpClient;

    constructor(client?: CentiaHttpClient) {
        this.client = client ?? getLegacyClient();
    }

    async get(schema: string, table: string): Promise<any> {
        return this.client.request({
            path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`,
            method: 'GET',
        });
    }

    async create(schema: string, table: string, payload: any): Promise<any> {
        return this.client.request({
            path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`,
            method: 'POST',
            body: payload,
        });
    }

    async patch(schema: string, table: string, payload: any): Promise<any> {
        return this.client.request({
            path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`,
            method: 'PATCH',
            body: payload,
        });
    }

    async delete(schema: string, table: string): Promise<any> {
        return this.client.request({
            path: `api/v4/schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`,
            method: 'DELETE',
            expectedStatus: 204,
        });
    }
}
