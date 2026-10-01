/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { LocationResponse, SchemaTileSettingsInfo, SchemaTileSettingsInput } from './types';

/**
 * Tile settings for a schema's merged tileset — `<schema>` and
 * `<schema>.mvt`, drawn from all the schema's layers at once. Super-user only.
 *
 * Changing `cache` or `format` does not clear the existing cache: tiles
 * already rendered stay in the old backend or format, where they are
 * neither served nor cleaned up. Delete the tileset's cache yourself if
 * you want the space back.
 */
export default class SchemaTileSettings {
  constructor(private readonly client: CentiaHttpClient) {}

  private path(schema: string): string {
    return `api/v4/schemas/${encodeURIComponent(schema)}/tile`;
  }

  /**
   * The effective settings (stored values over the defaults). `_stored`
   * holds only what is actually stored. Answers even when the schema has
   * been dropped — `schema_exists` is then false, and the settings wait for
   * the schema to come back.
   */
  async getSchemaTileSettings(schema: string): Promise<SchemaTileSettingsInfo> {
    return this.client.request<SchemaTileSettingsInfo>({
      path: this.path(schema),
      method: 'GET',
    });
  }

  /**
   * Merge settings into the stored ones (303). Send only the fields you
   * change; an explicit `null` returns a setting to its default. Unlike GET
   * and DELETE, the schema must exist: throws 404 `SCHEMA_NOT_FOUND`, so a
   * typo cannot become a row that silently takes effect later. Throws 400
   * `INPUT_VALIDATION_ERROR` for a disallowed value or unknown field.
   */
  async patchSchemaTileSettings(schema: string, body: SchemaTileSettingsInput): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.path(schema),
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Remove all stored settings, returning the schema to the defaults (204). Idempotent, and works when the schema is gone. */
  async deleteSchemaTileSettings(schema: string): Promise<void> {
    await this.client.request({
      path: this.path(schema),
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
