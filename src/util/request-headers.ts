/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */

import {getOptions, getTokens, isLogin} from "./utils";
import {Gc2Service} from "../services/gc2.services";

const getHeaders = async (contentType: string|null = 'application/json'): Promise<any>=> {
  type headers = {
    Accept: string,
    Cookie: string,
    Authorization: string|null,
    'Content-Type'?: string
  }

  const options = getOptions()
  const service = new Gc2Service(options)

  // We check is token needs refreshing
  if (!await isLogin(service)) {
    return Promise.reject('Is not logged in')
  }

  const {accessToken} = getTokens()

  const headers: headers = {
    Accept: 'application/json',
    Cookie: 'XDEBUG_SESSION=XDEBUG_ECLIPSE',
    Authorization: accessToken ? 'Bearer ' + accessToken : null,
  }
  if (contentType) {
    headers['Content-Type'] = contentType
  }
  return headers
}
export default getHeaders

