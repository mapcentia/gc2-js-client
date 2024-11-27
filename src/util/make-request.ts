/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */

import getHeaders from './request-headers'
import Method from '../common/http-verbs'
import {getOptions} from './utils'

export const make = async (version: string, resource: string, method: Method, payload?: any, contentType: string | null = 'application/json'): Promise<any> => {
  const options = getOptions()
  const headers = await getHeaders(contentType)

  let request: RequestInit = {
    method: method,
    headers: headers,
    redirect: 'manual'
  }
  if (payload) {
    request.body = contentType === 'application/json' ? JSON.stringify(payload) : payload
  }
  return await fetch(options.host + `/api/v${version}/${resource}`, request)
}
export default make
