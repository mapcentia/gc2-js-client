/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { FileProcessRequest, FileProcessResponse } from './types';

export default class FileImport {
  constructor(private readonly client: CentiaHttpClient) {}

  /**
   * Upload a file via multipart/form-data.
   * In Node.js, pass a FormData instance. In browsers, pass a native FormData.
   */
  async postFileUpload(formData: FormData): Promise<{ filename: string }> {
    return this.client.request<{ filename: string }>({
      path: 'api/v4/file/upload',
      method: 'POST',
      body: formData,
      contentType: null, // Let the browser/runtime set multipart boundary
      expectedStatus: 201,
    });
  }

  async postFileProcess(body: FileProcessRequest): Promise<FileProcessResponse[]> {
    return this.client.request<FileProcessResponse[]>({
      path: 'api/v4/file/process',
      method: 'POST',
      body,
      expectedStatus: 200,
    });
  }
}
