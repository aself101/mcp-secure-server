/**
 * Image Generation MCP Server - Utility Functions
 *
 * Utility functions for image handling, file I/O, and filename generation.
 * Based on patterns from bfl-api, stability-ai-api, etc.
 */

import fs from 'fs/promises';
import path from 'path';

/**
 * Ensure a directory exists, creating it if necessary.
 */
export async function ensureDirectory(dirPath: string): Promise<void> {
  await fs.mkdir(dirPath, { recursive: true });
}

/**
 * Generate a safe filename from a prompt string.
 */
export function promptToFilename(prompt: string, maxLength = 50): string {
  let filename = prompt
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '_')
    .replace(/-+/g, '_')
    .replace(/^_+|_+$/g, '');

  if (filename.length > maxLength) {
    filename = filename.substring(0, maxLength);
  }

  if (!filename) {
    filename = 'image';
  }

  return filename;
}

/**
 * Generate a timestamped filename.
 */
export function generateTimestampedFilename(prefix: string, extension: string): string {
  const timestamp = new Date()
    .toISOString()
    .replace(/[:.]/g, '-')
    .replace('T', '_')
    .split('Z')[0];
  return `${timestamp}_${prefix}.${extension}`;
}

/**
 * Save base64 image data to file.
 */
export async function saveBase64Image(
  base64Data: string,
  filepath: string
): Promise<void> {
  const dir = path.dirname(filepath);
  await ensureDirectory(dir);

  const buffer = Buffer.from(base64Data, 'base64');
  await fs.writeFile(filepath, buffer);
}

/**
 * Save metadata JSON alongside image.
 */
export async function saveMetadata(
  metadata: Record<string, unknown>,
  filepath: string
): Promise<void> {
  const dir = path.dirname(filepath);
  await ensureDirectory(dir);

  await fs.writeFile(filepath, JSON.stringify(metadata, null, 2));
}


/**
 * Get the output directory for generated images.
 * Priority: IMAGE_GEN_OUTPUT_DIR env var > default
 */
export function getOutputDir(): string {
  return process.env.IMAGE_GEN_OUTPUT_DIR || 'generated-images';
}

/**
 * Generate full output path for an image.
 */
export function getImageOutputPath(
  provider: string,
  model: string,
  prompt: string,
  extension = 'png'
): { imagePath: string; metadataPath: string } {
  const outputDir = getOutputDir();
  const modelDir = path.join(outputDir, provider, model);

  const safePrompt = promptToFilename(prompt);
  const imageFilename = generateTimestampedFilename(safePrompt, extension);
  const metadataFilename = imageFilename.replace(/\.(png|jpg|jpeg|webp)$/, '_metadata.json');

  return {
    imagePath: path.join(modelDir, imageFilename),
    metadataPath: path.join(modelDir, metadataFilename),
  };
}
