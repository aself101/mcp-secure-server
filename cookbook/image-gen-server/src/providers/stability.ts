/**
 * Stability AI provider adapter (stability-ai-api 1.x)
 * Supports Stable Image Ultra/Core, Stable Diffusion 3.5, and editing operations
 */

import { StabilityAPI, isImageResult } from 'stability-ai-api';
import { detectImageMime } from 'stability-ai-api/utils';
import type { ImageProvider, GenerateOptions, GenerateResult, EditOptions, UpscaleOptions, ProviderName } from './index.js';

const SD3_MODELS = ['sd3.5-large', 'sd3.5-large-turbo', 'sd3.5-medium', 'sd3.5-flash'];

const MODELS = ['stable-image-ultra', 'stable-image-core', ...SD3_MODELS];

/**
 * Model names this server accepted before stability-ai-api 1.0. Since
 * 2025-04-17 Stability re-routes `sd3-large` to `sd3.5-large` server-side at
 * the same price (spec, and a keyless probe on 2026-09-22 answered 401, i.e.
 * accepted — a bogus name answers 400). Mapping it here sends what the server
 * would use anyway and reports the model actually used, not a retired name.
 */
const MODEL_ALIASES: Record<string, string> = { 'sd3-large': 'sd3.5-large' };

export class StabilityProvider implements ImageProvider {
  name: ProviderName = 'stability';
  private api: StabilityAPI;

  constructor() {
    const apiKey = process.env.STABILITY_API_KEY;
    if (!apiKey) {
      throw new Error('API key is required. Please provide STABILITY_API_KEY.');
    }
    this.api = new StabilityAPI(apiKey);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const requested = options.model || 'stable-image-ultra';
    const model = MODEL_ALIASES[requested] ?? requested;

    const params = {
      prompt: options.prompt,
      negative_prompt: options.negativePrompt,
      aspect_ratio: options.aspectRatio
    };

    let result: unknown;
    if (model === 'stable-image-core') {
      result = await this.api.generateCore(params);
    } else if (SD3_MODELS.includes(model)) {
      result = await this.api.generateSD3({ ...params, model });
    } else {
      result = await this.api.generateUltra(params);
    }

    return {
      images: this.extractImages(result),
      model,
      provider: this.name
    };
  }

  async edit(options: EditOptions): Promise<GenerateResult> {
    const result = await this.api.inpaint(options.image, options.prompt, { mask: options.mask });

    return {
      images: this.extractImages(result),
      model: 'inpaint',
      provider: this.name
    };
  }

  async upscale(options: UpscaleOptions): Promise<GenerateResult> {
    const result = await this.api.upscaleFast(options.image);

    return {
      images: this.extractImages(result),
      model: 'upscale-fast',
      provider: this.name
    };
  }

  async removeBackground(image: string): Promise<GenerateResult> {
    const result = await this.api.removeBackground(image);

    return {
      images: this.extractImages(result),
      model: 'remove-background',
      provider: this.name
    };
  }

  async replaceBackground(image: string, prompt: string): Promise<GenerateResult> {
    // Asynchronous on Stability's side; the library polls until the image is
    // ready unless told not to wait, so a task result here means it did not.
    const result = await this.api.replaceBackgroundAndRelight(image, { background_prompt: prompt });

    return {
      images: this.extractImages(result),
      model: 'replace-background',
      provider: this.name
    };
  }

  /** A data URI whose MIME type comes from the image bytes, not an assumed PNG. */
  private extractImages(result: unknown): string[] {
    if (!isImageResult(result)) return [];
    const mime = detectImageMime(result.image) || 'image/png';
    return [`data:${mime};base64,${result.image.toString('base64')}`];
  }

  listModels(): string[] {
    return MODELS;
  }
}
