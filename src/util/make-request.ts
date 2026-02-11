/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

import getHeaders from './request-headers'
import Method from '../common/http-verbs'
import {getOptions} from './utils'

export const make = async (version: string | null, resource: string, method: Method, payload?: any, contentType: string | null = 'application/json'): Promise<any> => {
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
  if (version !== null) {
    return await fetch(options.host + `/api/v${version}/${resource}`, request)
  } else {
    return await fetch(options.host + `/api/${resource}`, request)
  }
}
export default make
