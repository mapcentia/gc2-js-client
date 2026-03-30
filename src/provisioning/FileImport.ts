/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type { FileProcessRequest, FileProcessResponse, FileUploadOptions } from './types';

export default class FileImport {
  constructor(private readonly client: CentiaHttpClient) {}

  /**
   * Upload a file via multipart/form-data.
   * When `options.chunkSize` is set, the file is split into chunks and uploaded
   * sequentially. The server reassembles the file from the chunks.
   */
  async postFileUpload(
    formData: FormData,
    options?: FileUploadOptions,
  ): Promise<{ filename: string }> {
    if (!options?.chunkSize) {
      return this.client.request<{ filename: string }>({
        path: 'api/v4/file/upload',
        method: 'POST',
        body: formData,
        contentType: null,
        expectedStatus: 201,
      });
    }

    const file = formData.get('filename') as File | Blob | null;
    if (!file) {
      throw new Error('FormData must contain a "filename" entry for chunked upload.');
    }

    const fileName = file instanceof File ? file.name : 'upload';
    const totalChunks = Math.ceil(file.size / options.chunkSize);
    let result: { filename: string } = { filename: '' };

    for (let i = 0; i < totalChunks; i++) {
      const start = i * options.chunkSize;
      const end = Math.min(start + options.chunkSize, file.size);
      const chunk = file.slice(start, end);

      const chunkForm = new FormData();
      chunkForm.append('filename', chunk, fileName);

      result = await this.client.request<{ filename: string }>({
        path: 'api/v4/file/upload',
        method: 'POST',
        body: chunkForm,
        contentType: null,
        query: {
          chunk: String(i),
          chunks: String(totalChunks),
        },
        expectedStatus: 201,
      });
    }

    return result;
  }

  async postFileProcess(body: FileProcessRequest): Promise<FileProcessResponse[]> {
    return this.client.request<FileProcessResponse[]>({
      path: 'api/v4/file/process',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
  }
}
