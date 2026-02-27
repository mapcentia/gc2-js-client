/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

export interface CentiaApiErrorOptions {
  message: string;
  status?: number;
  code?: string;
  details?: unknown;
  requestId?: string;
  method: string;
  url: string;
  cause?: unknown;
}

/**
 * Normalized error thrown by all SDK HTTP operations.
 * CLI and Web should catch this type for consistent error handling.
 */
export class CentiaApiError extends Error {
  override readonly name = 'CentiaApiError';
  readonly status: number | undefined;
  readonly code: string | undefined;
  readonly details: unknown;
  readonly requestId: string | undefined;
  readonly method: string;
  readonly url: string;

  constructor(opts: CentiaApiErrorOptions) {
    super(opts.message);
    if (opts.cause !== undefined) {
      (this as any).cause = opts.cause;
    }
    this.status = opts.status;
    this.code = opts.code;
    this.details = opts.details;
    this.requestId = opts.requestId;
    this.method = opts.method;
    this.url = opts.url;
  }
}

/** Type guard for CentiaApiError. */
export function isCentiaApiError(e: unknown): e is CentiaApiError {
  return e instanceof CentiaApiError;
}
