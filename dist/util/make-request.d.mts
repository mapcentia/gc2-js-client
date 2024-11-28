import Method from '../common/http-verbs.mjs';

/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2024 MapCentia ApS
 * @license    http://www.gnu.org/licenses/#AGPL  GNU AFFERO GENERAL PUBLIC LICENSE 3
 *
 */

declare const make: (version: string, resource: string, method: Method, payload?: any, contentType?: string | null) => Promise<any>;

export { make as default, make };
