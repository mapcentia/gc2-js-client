/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  CreateFunctionRequest,
  PatchFunctionRequest,
  FunctionInfo,
  FunctionInvocationResult,
  FunctionInvocationRecord,
  AsyncInvocationAccepted,
  DryRunResult,
  LocationResponse,
} from './types';

/**
 * Lambda-like functions: manage (CRUD), invoke (sync/async/dry-run) and read
 * the generated TypeScript interface.
 */
export default class Functions {
  constructor(private readonly client: CentiaHttpClient) {}

  /** List all functions, or get one by name. */
  async getFunctions(): Promise<FunctionInfo[]>;
  async getFunctions(name: string): Promise<FunctionInfo>;
  async getFunctions(name?: string): Promise<FunctionInfo | FunctionInfo[]> {
    const path = name
      ? `api/v4/functions/${encodeURIComponent(name)}`
      : 'api/v4/functions';
    return this.client.request<FunctionInfo | FunctionInfo[]>({ path, method: 'GET' });
  }

  /** Create one or more functions. Returns the Location of the created resource. */
  async postFunction(
    body: CreateFunctionRequest | CreateFunctionRequest[],
  ): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/functions',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Update a function. Changing the code bumps its version. */
  async patchFunction(name: string, body: PatchFunctionRequest): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `api/v4/functions/${encodeURIComponent(name)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Delete a function. */
  async deleteFunction(name: string): Promise<void> {
    await this.client.request({
      path: `api/v4/functions/${encodeURIComponent(name)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }

  /** Invoke a function synchronously and return its result. */
  async invoke(name: string, event: unknown = {}): Promise<FunctionInvocationResult> {
    return this.client.request<FunctionInvocationResult>({
      path: `api/v4/functions/${encodeURIComponent(name)}/invocations`,
      method: 'POST',
      body: event,
    });
  }

  /** Queue a function invocation; returns immediately with 202 and an id to poll. */
  async invokeAsync(name: string, event: unknown = {}): Promise<AsyncInvocationAccepted> {
    return this.client.request<AsyncInvocationAccepted>({
      path: `api/v4/functions/${encodeURIComponent(name)}/invocations`,
      method: 'POST',
      body: event,
      query: { async: 'true' },
      expectedStatus: 202,
    });
  }

  /** Run once to infer and store input/output type schemas (for TypeScript generation). */
  async dryRun(name: string, event: unknown = {}): Promise<DryRunResult> {
    return this.client.request<DryRunResult>({
      path: `api/v4/functions/${encodeURIComponent(name)}/invocations`,
      method: 'POST',
      body: event,
      query: { dry: 'true' },
    });
  }

  /** Get a stored invocation record (e.g. to poll an async invocation). */
  async getInvocation(name: string, id: string): Promise<FunctionInvocationRecord> {
    return this.client.request<FunctionInvocationRecord>({
      path: `api/v4/functions/${encodeURIComponent(name)}/invocations/${encodeURIComponent(id)}`,
      method: 'GET',
    });
  }

  /** Get the generated TypeScript `Functions` interface (from dry-run schemas). */
  async getInterfaces(): Promise<string> {
    return this.client.request<string>({
      path: 'api/v4/function-interfaces',
      method: 'GET',
      accept: 'text/plain',
    });
  }
}
