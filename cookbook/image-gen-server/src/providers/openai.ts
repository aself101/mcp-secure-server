/**
 * OpenAI provider adapter (openai-image-api 3.x)
 * Supports the GPT Image models. DALL-E 2 and 3 are not offered by
 * openai-image-api 3.x, and neither is the variations endpoint.
 */

import { OpenAIImageAPI } from 'openai-image-api';
import type { ImageModel, ImageResponse } from 'openai-image-api';
import type { ImageProvider, GenerateOptions, GenerateResult, EditOptions, ProviderName } from './index.js';
import { withImageFile, withOptionalImageFile } from '../image-input.js';

const MODELS: ImageModel[] = [
  'gpt-image-2.5-flare',
  'gpt-image-2.5-sunburst',
  'gpt-image-2',
  'gpt-image-1.5',
  'gpt-image-1',
  'gpt-image-1-mini'
];

const DEFAULT_MODEL: ImageModel = 'gpt-image-2.5-flare';

export class OpenAIProvider implements ImageProvider {
  name: ProviderName = 'openai';
  private api: OpenAIImageAPI | null = null;

  private getApi(): OpenAIImageAPI {
    if (!this.api) {
      if (!process.env.OPENAI_API_KEY) {
        throw new Error(
          'OpenAI API key required. Set OPENAI_API_KEY environment variable. ' +
          'Get your API key at https://platform.openai.com/api-keys'
        );
      }
      this.api = new OpenAIImageAPI();
    }
    return this.api;
  }

  private resolveModel(requested?: string): ImageModel {
    if (!requested) return DEFAULT_MODEL;
    if ((MODELS as string[]).includes(requested)) return requested as ImageModel;
    throw new Error(`Unsupported OpenAI model "${requested}". Use one of: ${MODELS.join(', ')}`);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const model = this.resolveModel(options.model);
    const result = await this.getApi().generateImage({
      prompt: options.prompt,
      model,
      n: options.count || 1,
      size: this.getSize(options.width, options.height, model)
    });

    return { images: this.toDataUris(result), model, provider: this.name };
  }

  /**
   * Edits the given image (the pre-3.x adapter ignored it and generated a new
   * one). openai-image-api takes file paths, so a data URI or URL input is
   * written to a temporary file for the call (withImageFile).
   */
  async edit(options: EditOptions): Promise<GenerateResult> {
    const model = DEFAULT_MODEL;
    const api = this.getApi();
    const result = await withImageFile(options.image, image =>
      withOptionalImageFile(options.mask, mask => api.generateImageEdit({ image, prompt: options.prompt, mask, model }))
    );

    return { images: this.toDataUris(result), model, provider: this.name };
  }

  /**
   * gpt-image-1.x accepts three fixed sizes; gpt-image-2 and 2.5 accept any
   * size whose edges are multiples of 16. Without dimensions the server picks.
   */
  private getSize(width: number | undefined, height: number | undefined, model: ImageModel): string | undefined {
    if (!width || !height) return undefined;
    if (model.startsWith('gpt-image-1')) {
      if (width > height) return '1536x1024';
      if (height > width) return '1024x1536';
      return '1024x1024';
    }
    const edge = (n: number) => Math.max(16, Math.round(n / 16) * 16);
    return `${edge(width)}x${edge(height)}`;
  }

  /** GPT Image models return base64 only; the format is on the response. */
  private toDataUris(result: ImageResponse): string[] {
    const format = result.output_format || 'png';
    return result.data
      .map(img => (img.b64_json ? `data:image/${format};base64,${img.b64_json}` : ''))
      .filter(Boolean);
  }

  listModels(): string[] {
    return MODELS;
  }
}
