/**
 * Video Encoding Tool
 *
 * Safe wrapper for FFmpeg with:
 * - Input/output file validation
 * - Codec and preset allowlist
 * - Timeout enforcement (long-running operations)
 * - No dangerous FFmpeg features (concat, lavfi, URLs)
 */

import { z } from 'zod';
import { resolve, dirname } from 'path';
import { existsSync, mkdirSync } from 'fs';
import {
  executeCommand,
  commandExists,
  validatePath,
  validateCommand,
  getAllowlist,
  isFile,
} from '../utils/index.js';

export const encodeVideoSchema = z.object({
  inputPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the input video file'),
  outputPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path for the output video file'),
  format: z
    .enum(['mp4', 'webm', 'mkv', 'mov'])
    .default('mp4')
    .describe('Output format'),
  codec: z
    .enum(['libx264', 'libx265', 'libvpx', 'copy'])
    .default('libx264')
    .describe('Video codec'),
  preset: z
    .enum(['ultrafast', 'superfast', 'veryfast', 'faster', 'fast', 'medium', 'slow', 'slower', 'veryslow'])
    .default('medium')
    .describe('Encoding preset (speed vs quality)'),
  crf: z
    .number()
    .int()
    .min(0)
    .max(51)
    .default(23)
    .describe('Constant Rate Factor (0-51, lower is better quality)'),
  maxDuration: z
    .number()
    .int()
    .min(1)
    .max(3600)
    .optional()
    .describe('Maximum duration in seconds (optional)'),
  resolution: z
    .string()
    .regex(/^\d{1,4}x\d{1,4}$/)
    .optional()
    .describe('Output resolution (e.g., "1920x1080")'),
});

export type EncodeVideoArgs = z.infer<typeof encodeVideoSchema>;

export interface EncodeVideoResult {
  content: Array<{ type: 'text'; text: string }>;
}

// Allowed directories for video operations
const ALLOWED_VIDEO_DIRS = [
  process.cwd(),
  '/home',
  '/Users',
  '/tmp',
];

// Allowed video extensions
const ALLOWED_INPUT_EXTENSIONS = ['.mp4', '.mkv', '.avi', '.mov', '.webm', '.m4v', '.flv', '.wmv'];
const ALLOWED_OUTPUT_EXTENSIONS = ['.mp4', '.mkv', '.webm', '.mov'];

// Timeout for video encoding (5 minutes max for demo purposes)
const ENCODE_TIMEOUT = 5 * 60 * 1000;

export async function encodeVideo(args: EncodeVideoArgs): Promise<EncodeVideoResult> {
  const { inputPath, outputPath, format, codec, preset, crf, maxDuration, resolution } = args;

  // Check if FFmpeg is installed
  if (!(await commandExists('ffmpeg'))) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'FFmpeg not installed',
          message: 'The "ffmpeg" command was not found. Please install FFmpeg:\n' +
            '  - macOS: brew install ffmpeg\n' +
            '  - Ubuntu/Debian: sudo apt install ffmpeg\n' +
            '  - Windows: https://ffmpeg.org/download.html',
        }, null, 2),
      }],
    };
  }

  // Validate input path
  const inputValidation = validatePath(inputPath, {
    allowedDirs: ALLOWED_VIDEO_DIRS,
    allowedExtensions: ALLOWED_INPUT_EXTENSIONS,
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

  // Validate output path
  const outputValidation = validatePath(outputPath, {
    allowedDirs: ALLOWED_VIDEO_DIRS,
    allowedExtensions: ALLOWED_OUTPUT_EXTENSIONS,
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

  // Build FFmpeg arguments
  const ffmpegArgs: string[] = [
    '-i', inputValidation.normalizedPath,
    '-y', // Overwrite output
    '-c:v', codec,
  ];

  // Add preset for non-copy codecs
  if (codec !== 'copy') {
    ffmpegArgs.push('-preset', preset);
    ffmpegArgs.push('-crf', crf.toString());
  }

  // Add resolution if specified
  if (resolution) {
    ffmpegArgs.push('-vf', `scale=${resolution.replace('x', ':')}`);
  }

  // Add duration limit if specified
  if (maxDuration) {
    ffmpegArgs.push('-t', maxDuration.toString());
  }

  // Add output file
  ffmpegArgs.push(outputValidation.normalizedPath);

  // Validate command against allowlist
  const ffmpegAllowlist = getAllowlist('ffmpeg');
  if (!ffmpegAllowlist) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Configuration error',
          message: 'FFmpeg allowlist not found',
        }, null, 2),
      }],
    };
  }

  const commandValidation = validateCommand('ffmpeg', ffmpegArgs, ffmpegAllowlist);
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

  // Execute FFmpeg
  const result = await executeCommand('ffmpeg', ffmpegArgs, {
    timeout: ENCODE_TIMEOUT,
    maxOutput: 100 * 1024, // 100KB max output (FFmpeg outputs to stderr)
  });

  if (result.timedOut) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Encoding timed out',
          message: `Video encoding exceeded ${ENCODE_TIMEOUT / 1000} second timeout`,
        }, null, 2),
      }],
    };
  }

  // FFmpeg outputs progress to stderr, so check both exit code and file existence
  if (result.exitCode !== 0) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Video encoding failed',
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
          message: 'FFmpeg completed but output file was not created',
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
        settings: {
          format,
          codec,
          preset,
          crf,
          resolution: resolution || 'original',
          maxDuration: maxDuration || 'full',
        },
        durationMs: result.durationMs,
      }, null, 2),
    }],
  };
}
