/**
 * Image Resize Tool
 *
 * Safe wrapper for ImageMagick's convert command with:
 * - Input/output file validation
 * - Allowed extensions only (PNG, JPG, GIF, WebP)
 * - Dimension limits
 * - No dangerous ImageMagick features (MSL, label, etc.)
 */

import { z } from 'zod';
import { resolve, dirname } from 'path';
import { existsSync, mkdirSync } from 'fs';
import {
  executeCommand,
  validatePath,
  validateCommand,
  getAllowlist,
  isFile,
} from '../utils/index.js';

export const imageResizeSchema = z.object({
  inputPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the input image'),
  outputPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path for the output image'),
  width: z
    .number()
    .int()
    .min(1)
    .max(10000)
    .describe('Target width in pixels'),
  height: z
    .number()
    .int()
    .min(1)
    .max(10000)
    .describe('Target height in pixels'),
  quality: z
    .number()
    .int()
    .min(1)
    .max(100)
    .default(85)
    .describe('Output quality (1-100)'),
  maintainAspect: z
    .boolean()
    .default(true)
    .describe('Maintain aspect ratio'),
});

export type ImageResizeArgs = z.infer<typeof imageResizeSchema>;

export interface ImageResizeResult {
  content: Array<{ type: 'text'; text: string }>;
}

// Allowed directories for image operations
const ALLOWED_IMAGE_DIRS = [
  process.cwd(),
  '/home',
  '/Users',
  '/tmp',
];

// Allowed image extensions
const ALLOWED_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.tiff'];

export async function imageResize(args: ImageResizeArgs): Promise<ImageResizeResult> {
  const { inputPath, outputPath, width, height, quality, maintainAspect } = args;

  // Validate input path
  const inputValidation = validatePath(inputPath, {
    allowedDirs: ALLOWED_IMAGE_DIRS,
    allowedExtensions: ALLOWED_EXTENSIONS,
    mustExist: true,
    followSymlinks: true,
  });

  if (!inputValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid input path',
          message: inputValidation.error,
        }, null, 2),
      }],
    };
  }

  // Verify input is a file
  if (!isFile(inputValidation.normalizedPath)) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid input path',
          message: 'Input path is not a file',
        }, null, 2),
      }],
    };
  }

  // Validate output path (doesn't need to exist yet)
  const outputValidation = validatePath(outputPath, {
    allowedDirs: ALLOWED_IMAGE_DIRS,
    allowedExtensions: ALLOWED_EXTENSIONS,
    mustExist: false,
    followSymlinks: false,
  });

  if (!outputValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid output path',
          message: outputValidation.error,
        }, null, 2),
      }],
    };
  }

  // Ensure output directory exists
  const outputDir = dirname(outputValidation.normalizedPath);
  if (!existsSync(outputDir)) {
    try {
      mkdirSync(outputDir, { recursive: true });
    } catch {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            error: 'Cannot create output directory',
            message: `Failed to create directory: ${outputDir}`,
          }, null, 2),
        }],
      };
    }
  }

  // Build ImageMagick arguments
  // Format: convert input -resize WxH -quality Q output
  const resizeSpec = maintainAspect ? `${width}x${height}` : `${width}x${height}!`;
  const convertArgs = [
    inputValidation.normalizedPath,
    '-resize', resizeSpec,
    '-quality', quality.toString(),
    '-strip', // Remove metadata (security)
    '-auto-orient', // Fix orientation
    outputValidation.normalizedPath,
  ];

  // Validate command against allowlist
  const convertAllowlist = getAllowlist('convert');
  if (!convertAllowlist) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Configuration error',
          message: 'Convert allowlist not found',
        }, null, 2),
      }],
    };
  }

  const commandValidation = validateCommand('convert', convertArgs, convertAllowlist);
  if (!commandValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Command validation failed',
          message: commandValidation.error,
        }, null, 2),
      }],
    };
  }

  // Execute ImageMagick convert
  const result = await executeCommand('convert', convertArgs, {
    timeout: 30000, // 30 second timeout for large images
    maxOutput: 10 * 1024, // 10KB max output (should be minimal)
  });

  if (result.timedOut) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Command timed out',
          message: 'Image resize exceeded 30 second timeout',
        }, null, 2),
      }],
    };
  }

  if (result.exitCode !== 0) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Image resize failed',
          message: result.stderr || 'Unknown error',
          exitCode: result.exitCode,
        }, null, 2),
      }],
    };
  }

  // Verify output was created
  if (!existsSync(outputValidation.normalizedPath)) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Output not created',
          message: 'ImageMagick completed but output file was not created',
        }, null, 2),
      }],
    };
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        inputPath: inputValidation.normalizedPath,
        outputPath: outputValidation.normalizedPath,
        dimensions: { width, height, maintainAspect },
        quality,
        durationMs: result.durationMs,
      }, null, 2),
    }],
  };
}
