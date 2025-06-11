import make from "./util/make-request";
import get from "./util/get-response";

export default class Users {
    async get(user: string): Promise<any> {
        const response = await make('4', `users/${user}`, 'GET', null)
        return await get(response, 200)
    }
}
