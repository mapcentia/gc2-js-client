/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

export class NotLoggedInError extends Error {
    constructor(message = 'Not logged in: no access token in store') {
        super(message)
        this.name = 'NotLoggedInError'
    }
}

export class SessionExpiredError extends Error {
    constructor(message = 'Session expired: refresh token is missing or expired') {
        super(message)
        this.name = 'SessionExpiredError'
    }
}
