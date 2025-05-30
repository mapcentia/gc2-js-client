import make from "./util/make-request";
import get from "./util/get-response";
import {base64UrlEncodeString} from "./util/utils";

type SqlRequest = {
    q: string;
    base64?: boolean;
    srs?: number;
    format?: string;
}

export default class Sql {
    async select(query: string): Promise<any> {
        const body: SqlRequest = {
            q: base64UrlEncodeString(query),
            base64: true,
            srs: 4326,
            format: 'json',
        }
        const response = await make('4', `sql`, 'POST', body)
        return await get(response, 200)
    }
}
