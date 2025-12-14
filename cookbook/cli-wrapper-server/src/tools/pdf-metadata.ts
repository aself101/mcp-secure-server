/**
 * PDF Metadata Tool
 *
 * Safe wrapper for pdfinfo command with:
 * - Input file validation (PDF only)
 * - No shell execution
 * - Output parsing and sanitization
 */

import { z } from 'zod';
import {
  executeCommand,
  validatePath,
  validateCommand,
  getAllowlist,
  isFile,
} from '../utils/index.js';

export const pdfMetadataSchema = z.object({
  pdfPath: z
    .string()
    .min(1)
    .max(500)
    .describe('Path to the PDF file'),
});

export type PdfMetadataArgs = z.infer<typeof pdfMetadataSchema>;

export interface PdfMetadataResult {
  content: Array<{ type: 'text'; text: string }>;
}

export interface PdfMetadata {
  title?: string;
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: string;
  modificationDate?: string;
  pages?: number;
  pageSize?: string;
  fileSize?: string;
  pdfVersion?: string;
  encrypted?: boolean;
}

// Allowed directories for PDF operations
const ALLOWED_PDF_DIRS = [
  process.cwd(),
  '/home',
  '/Users',
  '/tmp',
];

/**
 * Parse pdfinfo output into structured metadata
 */
function parsePdfInfo(output: string): PdfMetadata {
  const metadata: PdfMetadata = {};
  const lines = output.split('\n');

  for (const line of lines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex === -1) continue;

    const key = line.slice(0, colonIndex).trim().toLowerCase();
    const value = line.slice(colonIndex + 1).trim();

    switch (key) {
      case 'title':
        metadata.title = value;
        break;
      case 'author':
        metadata.author = value;
        break;
      case 'creator':
        metadata.creator = value;
        break;
      case 'producer':
        metadata.producer = value;
        break;
      case 'creationdate':
        metadata.creationDate = value;
        break;
      case 'moddate':
        metadata.modificationDate = value;
        break;
      case 'pages':
        metadata.pages = parseInt(value, 10) || undefined;
        break;
      case 'page size':
        metadata.pageSize = value;
        break;
      case 'file size':
        metadata.fileSize = value;
        break;
      case 'pdf version':
        metadata.pdfVersion = value;
        break;
      case 'encrypted':
        metadata.encrypted = value.toLowerCase() === 'yes';
        break;
    }
  }

  return metadata;
}

export async function pdfMetadata(args: PdfMetadataArgs): Promise<PdfMetadataResult> {
  const { pdfPath } = args;

  // Validate PDF path
  const pathValidation = validatePath(pdfPath, {
    allowedDirs: ALLOWED_PDF_DIRS,
    allowedExtensions: ['.pdf'],
    mustExist: true,
    followSymlinks: true,
  });

  if (!pathValidation.valid) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid PDF path',
          message: pathValidation.error,
        }, null, 2),
      }],
    };
  }

  // Verify it's a file
  if (!isFile(pathValidation.normalizedPath)) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Invalid PDF path',
          message: 'Path is not a file',
        }, null, 2),
      }],
    };
  }

  // Build pdfinfo arguments
  const pdfArgs = ['-enc', 'UTF-8', pathValidation.normalizedPath];

  // Validate command against allowlist
  const pdfAllowlist = getAllowlist('pdfinfo');
  if (!pdfAllowlist) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Configuration error',
          message: 'pdfinfo allowlist not found',
        }, null, 2),
      }],
    };
  }

  const commandValidation = validateCommand('pdfinfo', pdfArgs, pdfAllowlist);
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

  // Execute pdfinfo
  const result = await executeCommand('pdfinfo', pdfArgs, {
    timeout: 10000, // 10 second timeout
    maxOutput: 50 * 1024, // 50KB max output
  });

  if (result.timedOut) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'Command timed out',
          message: 'pdfinfo exceeded 10 second timeout',
        }, null, 2),
      }],
    };
  }

  if (result.exitCode !== 0) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          error: 'PDF metadata extraction failed',
          message: result.stderr || 'Unknown error',
          exitCode: result.exitCode,
        }, null, 2),
      }],
    };
  }

  // Parse the output
  const metadata = parsePdfInfo(result.stdout);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        pdfPath: pathValidation.normalizedPath,
        metadata,
        durationMs: result.durationMs,
      }, null, 2),
    }],
  };
}
