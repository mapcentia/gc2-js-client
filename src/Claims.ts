import {claims, getTokens} from "./util/utils";

export default class Claims {
    get() {
        const tokens = getTokens().accessToken
        return claims(tokens);
    }
}
