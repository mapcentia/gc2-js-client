"use strict";
/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2023 MapCentia ApS
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
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Asynchronously sends a GET request and returns the response body if the
 * request is successful.
 *
 * @param {Response} response - The response object containing the response from the GET request.
 * @param expectedCode
 * @param doNotExit
 * @returns {Promise<any>} - A promise that resolves with the response body.
 */
const get = (response_1, expectedCode_1, ...args_1) => __awaiter(void 0, [response_1, expectedCode_1, ...args_1], void 0, function* (response, expectedCode, doNotExit = false) {
    let res = null;
    // Handle case of No Content
    if (![204, 303].includes(expectedCode)) {
        res = yield response.json();
    }
    if (response.status !== expectedCode) {
        if (res === null) {
            res = yield response.json();
        }
        // ux.log('⚠️ ' + chalk.red(res.message || res.error))
        // if (!doNotExit) {
        //   exit(1)
        // }
    }
    return res;
});
exports.default = get;
