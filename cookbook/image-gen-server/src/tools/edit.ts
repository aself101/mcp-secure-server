/**
 * Image editing tools - edit, replace background
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

export const editImageSchema = z.object({
  provider: z.enum(['ideogram', 'openai', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  prompt: z.string().max(2000).describe('Description of the edit to make'),
  mask: z.string().optional().describe('Mask image URL or base64 (white = edit area)')
});

export type EditImageArgs = z.infer<typeof editImageSchema>;

export async function editImage(args: EditImageArgs) {
  try {
    const provider = getProvider(args.provider as ProviderName);

    if (!provider.edit) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Provider "${args.provider}" does not support image editing. ` +
              `Try: ideogram, openai, or stability instead.`
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.edit({
      image: args.image,
      prompt: args.prompt,
      mask: args.mask
    });

    return await buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to edit image'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const removeBackgroundSchema = z.object({
  image: z.string().describe('Image URL or base64 data')
});

export type RemoveBackgroundArgs = z.infer<typeof removeBackgroundSchema>;

export async function removeBackground(args: RemoveBackgroundArgs) {
  try {
    const provider = getProvider('stability');

    if (!provider.removeBackground) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: 'Remove background is only supported by Stability AI.'
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.removeBackground(args.image);
    return await buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to remove background'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const replaceBackgroundSchema = z.object({
  provider: z.enum(['ideogram', 'stability']),
  image: z.string().describe('Image URL or base64 data'),
  prompt: z.string().max(2000).describe('Description of the new background')
});

export type ReplaceBackgroundArgs = z.infer<typeof replaceBackgroundSchema>;

export async function replaceBackground(args: ReplaceBackgroundArgs) {
  try {
    const provider = getProvider(args.provider as ProviderName);

    if (!provider.replaceBackground) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: false,
            error: `Provider "${args.provider}" does not support background replacement. ` +
              `Try: ideogram or stability instead.`
          }, null, 2)
        }],
        isError: true
      };
    }

    const result = await provider.replaceBackground(args.image, args.prompt);
    return await buildImageResponse(result);
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to replace background'
        }, null, 2)
      }],
      isError: true
    };
  }
}
