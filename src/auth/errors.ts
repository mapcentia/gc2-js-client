/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

/**
 * Thrown by {@link createTokenProvider} when the {@link TokenStore} has no
 * access token. Indicates the user has never logged in (or has logged out)
 * and a fresh interactive login is required. Distinct from
 * {@link SessionExpiredError}, which means the user *did* log in but the
 * refresh token has since expired.
 */
export class NotLoggedInError extends Error {
    constructor(message = 'Not logged in: no access token in store') {
        super(message)
        this.name = 'NotLoggedInError'
    }
}

/**
 * Thrown by {@link createTokenProvider} when the access token is expired and
 * the refresh token is either missing or also expired. Indicates the
 * stored credentials cannot be silently revived; the user must run an
 * interactive login again.
 */
export class SessionExpiredError extends Error {
    constructor(message = 'Session expired: refresh token is missing or expired') {
        super(message)
        this.name = 'SessionExpiredError'
    }
}
