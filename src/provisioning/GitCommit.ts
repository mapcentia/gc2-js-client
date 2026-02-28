/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { CommitRequest, CommitResult } from './types';

export default class GitCommit {
  constructor(private readonly client: CentiaHttpClient) {}

  async postCommit(body: CommitRequest): Promise<CommitResult> {
    return this.client.request<CommitResult>({
      path: 'api/v4/commit',
      method: 'POST',
      body,
    });
  }
}
