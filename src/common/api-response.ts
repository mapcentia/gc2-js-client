/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 *
 */

export interface ApiResponse {
  readonly success: boolean;
  readonly data?: any;
  readonly message: string;
  readonly _execution_time: number;
}
