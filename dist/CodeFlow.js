"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const gc2_services_1 = require("./services/gc2.services");
const utils_1 = require("./util/utils");
const querystring_1 = __importDefault(require("querystring"));
class CodeFlow {
    constructor(options) {
        this.options = options;
        this.service = new gc2_services_1.Gc2Service(options);
    }
    redirectHandle() {
        return __awaiter(this, void 0, void 0, function* () {
            const url = window.location.search.substring(1);
            const q = querystring_1.default.parse(url);
            if (q.error) {
                return Promise.reject(new Error(`Failed to redirect: ${url}`));
            }
            if (q.code) {
                if (q.state !== localStorage.getItem('state')) {
                    return Promise.resolve('Possible CSRF attack. Aborting login???');
                }
                try {
                    const { access_token, refresh_token } = yield this.service.getAuthorizationCodeToken(q.code, localStorage.getItem('codeVerifier'));
                    (0, utils_1.setTokens)({ accessToken: access_token, refreshToken: refresh_token });
                    (0, utils_1.setOptions)({ clientId: this.options.clientId, host: this.options.host, redirectUri: this.options.redirectUri });
                    localStorage.removeItem('state');
                    localStorage.removeItem('codeVerifier');
                    return Promise.resolve(true);
                }
                catch (e) {
                    return Promise.reject(new Error(`Failed to redirect: ${url}`));
                }
            }
            if (yield (0, utils_1.isLogin)(this.service)) {
                console.log("Logged in");
            }
            return Promise.resolve(false);
        });
    }
    getAuthorizationCodeURL() {
        return __awaiter(this, void 0, void 0, function* () {
            const { state, codeVerifier, codeChallenge } = yield (0, utils_1.generatePkceChallenge)();
            localStorage.setItem("state", state);
            localStorage.setItem("codeVerifier", codeVerifier);
            // @ts-ignore
            window.location = this.service.getAuthorizationCodeURL(codeChallenge, state);
        });
    }
}
exports.default = CodeFlow;
