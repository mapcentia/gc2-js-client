import make from "./util/make-request";
import get from "./util/get-response";

export default class Stats {
    async get(): Promise<any> {
        const response = await make('4', `stats`, 'GET', null)
        return await get(response, 200)
    }
}
