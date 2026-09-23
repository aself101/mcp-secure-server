/**
 * Provider factory for unified image generation interface
 */

import { BflProvider } from './bfl.js';
import { GoogleProvider } from './google.js';
import { IdeogramProvider } from './ideogram.js';
import { OpenAIProvider } from './openai.js';
import { StabilityProvider } from './stability.js';

export type ProviderName = 'bfl' | 'google' | 'ideogram' | 'openai' | 'stability';

export interface GenerateOptions {
  prompt: string;
  model?: string;
  negativePrompt?: string;
  width?: number;
  height?: number;
  aspectRatio?: string;
  style?: string;
  count?: number;
}

export interface EditOptions {
  image: string;
  prompt: string;
  mask?: string;
}

export interface UpscaleOptions {
  image: string;
  scale?: number;
}

export interface GenerateResult {
  images: string[];
  model: string;
  provider: ProviderName;
}

export interface ImageProvider {
  name: ProviderName;
  generate(options: GenerateOptions): Promise<GenerateResult>;
  edit?(options: EditOptions): Promise<GenerateResult>;
  upscale?(options: UpscaleOptions): Promise<GenerateResult>;
  removeBackground?(image: string): Promise<GenerateResult>;
  replaceBackground?(image: string, prompt: string): Promise<GenerateResult>;
  describe?(image: string): Promise<string>;
  listModels(): string[];
}

const providers: Map<ProviderName, ImageProvider> = new Map();

export function getProvider(name: ProviderName): ImageProvider {
  let provider = providers.get(name);
  if (!provider) {
    switch (name) {
      case 'bfl':
        provider = new BflProvider();
        break;
      case 'google':
        provider = new GoogleProvider();
        break;
      case 'ideogram':
        provider = new IdeogramProvider();
        break;
      case 'openai':
        provider = new OpenAIProvider();
        break;
      case 'stability':
        provider = new StabilityProvider();
        break;
      default:
        throw new Error(
          `Unknown provider: ${name}. ` +
          `Valid providers: bfl, google, ideogram, openai, stability`
        );
    }
    providers.set(name, provider);
  }
  return provider;
}

export function getAllProviders(): ImageProvider[] {
  const names: ProviderName[] = ['bfl', 'google', 'ideogram', 'openai', 'stability'];
  return names.map(name => getProvider(name));
}

export function listAllModels(): Record<ProviderName, string[]> {
  const result: Record<string, string[]> = {};
  const names: ProviderName[] = ['bfl', 'google', 'ideogram', 'openai', 'stability'];
  for (const name of names) {
    result[name] = getProvider(name).listModels();
  }
  return result as Record<ProviderName, string[]>;
}
