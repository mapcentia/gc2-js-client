import make from "./util/make-request";
import get from "./util/get-response";

export default class Meta {
    async query(rel: string): Promise<any> {
        const response = await make('4', `meta/${rel}`, 'GET', null)
        return await get(response, 200)
    }
}
