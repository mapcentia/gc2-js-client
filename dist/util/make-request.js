"use strict";
/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */
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
const request_headers_1 = __importDefault(require("./request-headers"));
const utils_1 = require("./utils");
const gc2_services_1 = require("../services/gc2.services");
const utils_2 = require("./utils");
const make = (version_1, resource_1, method_1, payload_1, ...args_1) => __awaiter(void 0, [version_1, resource_1, method_1, payload_1, ...args_1], void 0, function* (version, resource, method, payload, checkConnection = true, contentType = 'application/json') {
    const headers = (0, request_headers_1.default)(contentType);
    if (!headers.Authorization && checkConnection) {
        (0, utils_1.noLogin)();
    }
    const { accessToken, refreshToken } = (0, utils_2.getTokens)();
    const { host } = (0, utils_1.getOptions)();
    // We check is token needs refreshing
    if (checkConnection && (0, utils_1.isTokenExpired)(accessToken)) {
        if ((0, utils_1.isTokenExpired)(refreshToken)) {
            throw new Error('Refresh token has expired. Please login again');
        }
        const keycloakService = new gc2_services_1.Gc2Service((0, utils_1.getOptions)());
        try {
            const data = yield keycloakService.getRefreshToken(refreshToken);
            (0, utils_1.setTokens)({ accessToken: data.access_token, refreshToken: data.refresh_token });
            headers.Authorization = 'Bearer ' + data.access_token;
        }
        catch (e) {
            throw new Error('Could not get refresh token');
        }
    }
    let request = {
        method: method,
        headers: headers,
        redirect: 'manual'
    };
    if (payload) {
        request.body = contentType === 'application/json' ? JSON.stringify(payload) : payload;
    }
    return yield fetch(host + `/api/v${version}/${resource}`, request);
});
exports.default = make;
