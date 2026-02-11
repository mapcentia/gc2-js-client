/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

const get = async (response: Response, expectedCode: number): Promise<any> => {
  let res: any = null
    let bodyText = ''

    // Read the body only once as text. This avoids "body used already" with node-fetch.
    try {
        // Even for 204/303, text() is safe and will return '' for empty bodies
        bodyText = await response.text()
    } catch (e) {
        // Ignore body read errors; we'll proceed with null/empty body
    }

    // Try to parse JSON if there is a body
    if (bodyText) {
        try {
            res = JSON.parse(bodyText)
        } catch (e) {
            // Not JSON; keep res as null and use bodyText for error messages
        }
    }

    if (response.status !== expectedCode) {
        const msg = (res && (res.message || res.error)) || bodyText || `Unexpected status ${response.status}`
        throw new Error(msg)
    }

    // For 204/303, res will be null (no body), which is fine for callers expecting no content
    return res
}

export default get
