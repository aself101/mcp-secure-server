/**
 * Generate image tool - unified interface for all providers
 */

import { z } from 'zod';
import path from 'path';
import { resolveImageOutput } from '../image-input.js';
import { getProvider, type ProviderName } from '../providers/index.js';
import {
  saveBase64Image,
  saveMetadata,
  getImageOutputPath,
  getOutputDir
} from '../utils.js';


export const generateImageSchema = z.object({
  provider: z.enum(['bfl', 'google', 'ideogram', 'openai', 'stability']),
  prompt: z.string().max(2000).describe('Text description of the image to generate'),
  model: z.string().optional().describe('Provider-specific model name'),
  negativePrompt: z.string().optional().describe('What to avoid in the image'),
  width: z.number().optional().describe('Image width in pixels'),
  height: z.number().optional().describe('Image height in pixels'),
  aspectRatio: z.string().optional().describe('Aspect ratio (e.g., "16:9", "1:1")'),
  style: z.string().optional().describe('Style preset (provider-specific)'),
  count: z.number().min(1).max(4).optional().describe('Number of images to generate')
});

export type GenerateImageArgs = z.infer<typeof generateImageSchema>;

export async function generateImage(args: GenerateImageArgs) {
  try {
    const provider = getProvider(args.provider as ProviderName);

    const result = await provider.generate({
      prompt: args.prompt,
      model: args.model,
      negativePrompt: args.negativePrompt,
      width: args.width,
      height: args.height,
      aspectRatio: args.aspectRatio,
      style: args.style,
      count: args.count
    });

  const savedImages: Array<{ imagePath: string; metadataPath: string }> = [];
  const imageDataList: { data: string; mimeType: string }[] = [];

  // Process and save each image
  for (let i = 0; i < result.images.length; i++) {
    // Data URI, bare base64, or a result URL (downloaded SSRF-guarded); the
    // type and extension come from the bytes rather than an assumed PNG.
    const { base64: base64Data, mimeType, extension } = await resolveImageOutput(result.images[i]);
    imageDataList.push({ data: base64Data, mimeType });

    // Generate output paths (append index if multiple images)
    const promptSuffix = result.images.length > 1 ? `_${i + 1}` : '';
    const { imagePath, metadataPath } = getImageOutputPath(
      args.provider,
      result.model,
      args.prompt + promptSuffix,
      extension
    );

    // Convert to absolute path
    const absoluteImagePath = path.resolve(imagePath);
    const absoluteMetadataPath = path.resolve(metadataPath);

    // Save image to disk
    await saveBase64Image(base64Data, absoluteImagePath);

    // Save metadata
    const metadata = {
      provider: args.provider,
      model: result.model,
      prompt: args.prompt,
      timestamp: new Date().toISOString(),
      parameters: {
        negativePrompt: args.negativePrompt,
        width: args.width,
        height: args.height,
        aspectRatio: args.aspectRatio,
        style: args.style,
        count: args.count,
      },
      imagePath: absoluteImagePath,
      imageIndex: i + 1,
      totalImages: result.images.length,
    };
    await saveMetadata(metadata, absoluteMetadataPath);

    savedImages.push({
      imagePath: absoluteImagePath,
      metadataPath: absoluteMetadataPath,
    });
  }

  // Return images as proper MCP image content blocks
  const content: Array<{ type: 'text'; text: string } | { type: 'image'; data: string; mimeType: string }> = [
    {
      type: 'text' as const,
      text: JSON.stringify({
        success: true,
        provider: result.provider,
        model: result.model,
        imageCount: result.images.length,
        outputDirectory: path.resolve(getOutputDir()),
        savedImages: savedImages.map(s => s.imagePath),
      }, null, 2)
    }
  ];

  // Add images as MCP image content blocks
  for (const { data, mimeType } of imageDataList) {
    content.push({ type: 'image' as const, data, mimeType });
  }

    return { content };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to generate image'
        }, null, 2)
      }],
      isError: true
    };
  }
}
