"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Gc2Service = void 0;
const axios_1 = __importStar(require("axios"));
const querystring = __importStar(require("querystring"));
class Gc2Service {
    constructor(options) {
        this.options = options;
        this.http = axios_1.default.create({
            baseURL: this.options.host
        });
    }
    getDeviceCode() {
        return __awaiter(this, void 0, void 0, function* () {
            const { data } = yield this.http.post(`/api/v4/oauth/device`, {
                client_id: this.options.clientId,
            }, {
                headers: {
                    'Content-Type': 'application/json',
                },
            });
            return data;
        });
    }
    poolToken(deviceCode, interval) {
        return __awaiter(this, void 0, void 0, function* () {
            const getToken = () => this.http
                .post('/api/v4/oauth', {
                client_id: this.options.clientId,
                device_code: deviceCode,
                grant_type: 'device_code',
            }, {
                headers: {
                    'Content-Type': 'application/json',
                },
            })
                .then(({ data }) => data)
                .catch(error => {
                var _a;
                if (error instanceof axios_1.AxiosError) {
                    const err = (_a = error.response) === null || _a === void 0 ? void 0 : _a.data;
                    if (err.error === 'authorization_pending') {
                        return null;
                    }
                    else {
                        return err.error_description;
                    }
                }
            });
            let response = yield getToken();
            while (response === null) {
                response = yield new Promise(resolve => {
                    setTimeout(() => __awaiter(this, void 0, void 0, function* () {
                        resolve(yield getToken());
                    }), interval * 1100); // interval equal to 1 is equivalent to 1.1 seconds between one request and another
                });
            }
            return response;
        });
    }
    getAuthorizationCodeURL(codeChallenge, state) {
        const queryParams = querystring.stringify({
            response_type: 'code',
            client_id: this.options.clientId,
            redirect_uri: this.options.redirectUri,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: 'S256',
        });
        return `${this.options.host}/auth/?${queryParams}`;
    }
    getAuthorizationCodeToken(code, codeVerifier) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.http
                .post(`/api/v4/oauth`, {
                client_id: this.options.clientId,
                redirect_uri: this.options.redirectUri,
                grant_type: 'authorization_code',
                code,
                code_verifier: codeVerifier,
            }, {
                headers: {
                    'Content-Type': 'application/json',
                },
            })
                .then(({ data }) => data).catch(err => {
                throw new Error(err.message);
            });
        });
    }
    // TODO use v4 when all has updated GC2
    getPasswordToken(username, password, database) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.http
                .post(`/api/v3/oauth/token`, {
                client_id: this.options.clientId,
                grant_type: 'password',
                username,
                password,
                database,
            }, {
                headers: {
                    'Content-Type': 'application/json',
                },
            })
                .then(({ data }) => data);
        });
    }
    getRefreshToken(token) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.http
                .post(`/api/v4/oauth`, {
                client_id: this.options.clientId,
                grant_type: 'refresh_token',
                refresh_token: token
            }, {
                headers: {
                    'Content-Type': 'application/json',
                },
            }).then(({ data }) => data).catch(err => {
            });
        });
    }
}
exports.Gc2Service = Gc2Service;
