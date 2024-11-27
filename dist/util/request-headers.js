"use strict";
/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */
Object.defineProperty(exports, "__esModule", { value: true });
const utils_1 = require("./utils");
const getHeaders = (contentType = 'application/json') => {
    const { accessToken } = (0, utils_1.getTokens)();
    const headers = {
        Accept: 'application/json',
        Cookie: 'XDEBUG_SESSION=XDEBUG_ECLIPSE',
        Authorization: accessToken ? 'Bearer ' + accessToken : null,
    };
    if (contentType) {
        headers['Content-Type'] = contentType;
    }
    return headers;
};
exports.default = getHeaders;
