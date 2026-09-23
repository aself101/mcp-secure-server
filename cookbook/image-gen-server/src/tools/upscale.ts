/**
 * Image upscaling and variation tools
 */

import { z } from 'zod';
import { getProvider, type ProviderName, type GenerateResult } from '../providers/index.js';
import { resolveImageOutput } from '../image-input.js';

type ContentBlock = { type: 'text'; text: string } | { type: 'image'; data: string; mimeType: string };

async function buildImageResponse(result: GenerateResult): Promise<{ content: ContentBlock[] }> {
  const content: ContentBlock[] = [
    {
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        provider: result.provider,
        model: result.model,
        imageCount: result.images.length
      }, null, 2)
    }
  ];

  for (const img of result.images) {
    const { base64, mimeType } = await resolveImageOutput(img);
    content.push({ type: 'image' as const, data: base64, mimeType });
  }

  return { content };
}

export const upscaleImageSchema = z.object({
  provider: z.enum(['ideogram', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  scale: z.number().optional().describe('Upscale factor (provider-specific)')
});

export type UpscaleImageArgs = z.infer<typeof upscaleImageSchema>;

export async function upscaleImage(args: UpscaleImageArgs) {
  try {
    const provider = getProvider(args.provider as ProviderName);

    if (!provider.upscale) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Provider "${args.provider}" does not support upscaling. ` +
              `Try: ideogram or stability instead.`
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.upscale({
      image: args.image,
      scale: args.scale
    });

    return await buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to upscale image'
        }, null, 2)
      }],
      isError: true
    };
  }
}
