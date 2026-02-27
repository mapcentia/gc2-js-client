/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 * Legacy bridge: creates a CentiaHttpClient from storage-based options/tokens.
 * Used by existing SDK modules when no explicit client is provided.
 */

import { CentiaHttpClient } from './client';
import { getOptions, getTokens, isLogin } from '../util/utils';
import { Gc2Service } from '../services/gc2.services';

/**
 * Create a CentiaHttpClient backed by the legacy storage-based auth.
 * The auth callback reads fresh tokens from storage on each request
 * and auto-refreshes expired access tokens via the refresh token.
 */
export function getLegacyClient(): CentiaHttpClient {
  const options = getOptions();
  return new CentiaHttpClient({
    baseUrl: options.host,
    auth: {
      getAccessToken: async () => {
        const currentOptions = getOptions();
        const service = new Gc2Service(currentOptions);
        if (!await isLogin(service)) {
          return undefined;
        }
        return getTokens().accessToken || undefined;
      },
    },
  });
}
