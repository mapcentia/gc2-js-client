import make from "./util/make-request";
import get from "./util/get-response";

export default class Sql {

    constructor() {

    }

    async select(query: string): Promise<any> {
        const body = {q: query}
        const response = await make('4', `sql`, 'POST', body)
        return await get(response, 200)
    }
}
