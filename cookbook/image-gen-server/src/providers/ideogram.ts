/**
 * Ideogram provider adapter
 * Supports style presets and various editing operations
 */

import { IdeogramAPI } from 'ideogram-api';
import { withImageFile, withOptionalImageFile } from '../image-input.js';
import type { ImageProvider, GenerateOptions, GenerateResult, EditOptions, UpscaleOptions, ProviderName } from './index.js';

const MODELS = ['ideogram-v3'];

const STYLE_PRESETS = [
  'AUTO', 'GENERAL', 'REALISTIC', 'DESIGN', 'RENDER_3D', 'ANIME'
];

export class IdeogramProvider implements ImageProvider {
  name: ProviderName = 'ideogram';
  private api: any;

  constructor() {
    const apiKey = process.env.IDEOGRAM_API_KEY;
    if (!apiKey) {
      throw new Error('API key is required. Please provide IDEOGRAM_API_KEY.');
    }
    this.api = new (IdeogramAPI as any)(apiKey);
  }

  async generate(options: GenerateOptions): Promise<GenerateResult> {
    const result = await this.api.generate({
      prompt: options.prompt,
      negativePrompt: options.negativePrompt,
      aspectRatio: options.aspectRatio,
      styleType: options.style?.toUpperCase() || 'AUTO',
      numImages: options.count || 1
    } as any);

    const images = result?.data?.map((img: any) => img?.url || '').filter(Boolean) || [];

    return {
      images,
      model: 'ideogram-v3',
      provider: this.name
    };
  }

  async edit(options: EditOptions): Promise<GenerateResult> {
    const result: any = await withImageFile(options.image, image =>
      withOptionalImageFile(options.mask, mask => this.api.edit({ image, prompt: options.prompt, mask } as any))
    );

    const images = result?.data?.map((img: any) => img?.url || '').filter(Boolean) || [];

    return {
      images,
      model: 'ideogram-v3',
      provider: this.name
    };
  }

  async upscale(options: UpscaleOptions): Promise<GenerateResult> {
    const result: any = await withImageFile(options.image, image => this.api.upscale({ image } as any));

    const images = result?.data?.map((img: any) => img?.url || '').filter(Boolean) || [];

    return {
      images,
      model: 'ideogram-v3',
      provider: this.name
    };
  }

  async replaceBackground(image: string, prompt: string): Promise<GenerateResult> {
    const result: any = await withImageFile(image, file => this.api.replaceBackground({ image: file, prompt } as any));

    const images = result?.data?.map((img: any) => img?.url || '').filter(Boolean) || [];

    return {
      images,
      model: 'ideogram-v3',
      provider: this.name
    };
  }

  async describe(image: string): Promise<string> {
    const result: any = await withImageFile(image, file => this.api.describe({ image: file } as any));
    return result?.descriptions?.[0]?.text || '';
  }

  listModels(): string[] {
    return [...MODELS, ...STYLE_PRESETS.map(s => `ideogram-v3 (style: ${s})`)];
  }
}
