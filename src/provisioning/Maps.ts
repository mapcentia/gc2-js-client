/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse, MapConfig } from './types';

export default class Maps {
  constructor(private readonly client: CentiaHttpClient) {}

  /** Get the map view configuration (center, zoom, extent) for a schema. */
  async getMap(schema: string): Promise<MapConfig> {
    return this.client.request<MapConfig>({
      path: `api/v4/map/schema/${encodeURIComponent(schema)}`,
      method: 'GET',
    });
  }

  /** Set the map view configuration for a schema. Only the provided properties are updated; `null` clears a value. */
  async patchMap(schema: string, body: MapConfig): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/map/schema/${encodeURIComponent(schema)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }
}
