import make from "./util/make-request";
import get from "./util/get-response";

export default class Tables {
    async get(schema: string, table: string): Promise<any> {
        const response = await make('4', `schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`, 'GET', null)
        return await get(response, 200)
    }

    async create(schema: string, table: string, payload: any): Promise<any> {
        const response = await make('4', `schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`, 'POST', payload)
        return await get(response, 200)
    }

    async patch(schema: string, table: string, payload: any): Promise<any> {
        const response = await make('4', `schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`, 'PATCH', payload)
        return await get(response, 200)
    }

    async delete(schema: string, table: string): Promise<any> {
        const response = await make('4', `schemas/${encodeURIComponent(schema)}/tables/${encodeURIComponent(table)}`, 'DELETE', null)
        return await get(response, 204)
    }
}
