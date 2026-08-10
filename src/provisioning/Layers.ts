/**
 * @author     Martin Høgh <mh@mapcentia.com>
 * @copyright  2013-2026 MapCentia ApS
 * @license    https://opensource.org/license/mit  The MIT License
 */

import type { CentiaHttpClient } from '../http/client';
import type {
  GetLayerOptions,
  Label,
  Layer,
  LayerClass,
  LocationResponse,
  Style,
} from './types';

export default class Layers {
  constructor(private readonly client: CentiaHttpClient) {}

  private layerPath(layer: string): string {
    return `api/v4/layers/${encodeURIComponent(layer)}`;
  }

  private classPath(layer: string, classId: string): string {
    return `${this.layerPath(layer)}/classes/${encodeURIComponent(classId)}`;
  }

  // ===== Layers =====

  async getLayer(layer?: undefined, opts?: GetLayerOptions): Promise<Layer[]>;
  async getLayer(layer: string, opts?: GetLayerOptions): Promise<Layer>;
  async getLayer(layer?: string, opts?: GetLayerOptions): Promise<Layer | Layer[]> {
    const path = layer ? this.layerPath(layer) : 'api/v4/layers';
    const query: Record<string, string> = {};
    if (opts?.namesOnly) {
      query.namesOnly = 'true';
    }
    return this.client.request<Layer | Layer[]>({
      path,
      method: 'GET',
      query: Object.keys(query).length > 0 ? query : undefined,
    });
  }

  /** Configure existing layer(s): set properties and replace classes. */
  async postLayer(body: Layer | Layer[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: 'api/v4/layers',
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Update layer properties (key-merge on the def JSON). */
  async patchLayer(layer: string, body: Layer): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.layerPath(layer),
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  // ===== Classes =====

  async getLayerClass(layer: string): Promise<LayerClass[]>;
  async getLayerClass(layer: string, classId: string): Promise<LayerClass>;
  async getLayerClass(layer: string, classId?: string): Promise<LayerClass | LayerClass[]> {
    const path = classId != null
      ? this.classPath(layer, classId)
      : `${this.layerPath(layer)}/classes`;
    return this.client.request<LayerClass | LayerClass[]>({
      path,
      method: 'GET',
    });
  }

  async postLayerClass(layer: string, body: LayerClass | LayerClass[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.layerPath(layer)}/classes`,
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Update a class (key-merge). Styles/labels are managed via their own methods. */
  async patchLayerClass(layer: string, classId: string, body: LayerClass): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: this.classPath(layer, classId),
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Delete class(es). `classId` may be a comma-separated list of ids. */
  async deleteLayerClass(layer: string, classId: string): Promise<void> {
    await this.client.request({
      path: this.classPath(layer, classId),
      method: 'DELETE',
      expectedStatus: 204,
    });
  }

  // ===== Styles =====

  async getStyle(layer: string, classId: string): Promise<Style[]>;
  async getStyle(layer: string, classId: string, styleId: string): Promise<Style>;
  async getStyle(layer: string, classId: string, styleId?: string): Promise<Style | Style[]> {
    const base = `${this.classPath(layer, classId)}/styles`;
    const path = styleId != null ? `${base}/${encodeURIComponent(styleId)}` : base;
    return this.client.request<Style | Style[]>({
      path,
      method: 'GET',
    });
  }

  async postStyle(layer: string, classId: string, body: Style | Style[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.classPath(layer, classId)}/styles`,
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Update a style (key-merge). */
  async patchStyle(layer: string, classId: string, styleId: string, body: Style): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.classPath(layer, classId)}/styles/${encodeURIComponent(styleId)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Delete style(s). `styleId` may be a comma-separated list of ids. */
  async deleteStyle(layer: string, classId: string, styleId: string): Promise<void> {
    await this.client.request({
      path: `${this.classPath(layer, classId)}/styles/${encodeURIComponent(styleId)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }

  // ===== Labels =====

  async getLabel(layer: string, classId: string): Promise<Label[]>;
  async getLabel(layer: string, classId: string, labelId: string): Promise<Label>;
  async getLabel(layer: string, classId: string, labelId?: string): Promise<Label | Label[]> {
    const base = `${this.classPath(layer, classId)}/labels`;
    const path = labelId != null ? `${base}/${encodeURIComponent(labelId)}` : base;
    return this.client.request<Label | Label[]>({
      path,
      method: 'GET',
    });
  }

  async postLabel(layer: string, classId: string, body: Label | Label[]): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.classPath(layer, classId)}/labels`,
      method: 'POST',
      body,
      expectedStatus: 201,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Update a label (key-merge). */
  async patchLabel(layer: string, classId: string, labelId: string, body: Label): Promise<LocationResponse> {
    const res = await this.client.requestFull({
      path: `${this.classPath(layer, classId)}/labels/${encodeURIComponent(labelId)}`,
      method: 'PATCH',
      body,
      expectedStatus: 303,
    });
    return { location: res.getHeader('Location') ?? '' };
  }

  /** Delete label(s). `labelId` may be a comma-separated list of ids. */
  async deleteLabel(layer: string, classId: string, labelId: string): Promise<void> {
    await this.client.request({
      path: `${this.classPath(layer, classId)}/labels/${encodeURIComponent(labelId)}`,
      method: 'DELETE',
      expectedStatus: 204,
    });
  }
}
