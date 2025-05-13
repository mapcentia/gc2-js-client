import {getTokens} from "./util/utils";

export default class Status {
    isAuth() {
        const tokens = getTokens()
        return !(!tokens.accessToken && !tokens.refreshToken);
    }
}
