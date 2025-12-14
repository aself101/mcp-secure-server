/**
 * CLI Wrapper MCP Server
 *
 * Demonstrates safe wrapping of command-line tools with:
 * - Layer 2: Command injection detection (pipes, backticks, $(), etc.)
 * - Layer 5: Command allowlist validation
 * - Layer 5: Argument sanitization
 * - Layer 4: Timeout enforcement
 * - Layer 4: Working directory restrictions
 *
 * Tools:
 * - git-status: Git repository status (status, branch, log, diff, show)
 * - image-resize: ImageMagick image resizing
 * - pdf-metadata: PDF info extraction
 * - encode-video: FFmpeg video encoding
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  gitStatusSchema,
  gitStatus,
  type GitStatusArgs,
  imageResizeSchema,
  imageResize,
  type ImageResizeArgs,
  pdfMetadataSchema,
  pdfMetadata,
  type PdfMetadataArgs,
  encodeVideoSchema,
  encodeVideo,
  type EncodeVideoArgs,
} from './tools/index.js';

// ============================================================================
// Configuration
// ============================================================================

const GIT_TIMEOUT = parseInt(process.env.GIT_TIMEOUT || '10000', 10);
const IMAGE_TIMEOUT = parseInt(process.env.IMAGE_TIMEOUT || '30000', 10);
const PDF_TIMEOUT = parseInt(process.env.PDF_TIMEOUT || '10000', 10);
const VIDEO_TIMEOUT = parseInt(process.env.VIDEO_TIMEOUT || '300000', 10); // 5 minutes

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'cli-wrapper-server',
    version: '1.0.0',
  },
  {
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'git-status',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 100 * 1024, // 100KB for git output
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'image-resize',
        sideEffects: 'write',
        maxArgsSize: 2048,
        maxEgressBytes: 10 * 1024, // 10KB response (metadata only)
        quotaPerMinute: 20,
        quotaPerHour: 200,
      },
      {
        name: 'pdf-metadata',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 50 * 1024, // 50KB for PDF metadata
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'encode-video',
        sideEffects: 'write',
        maxArgsSize: 2048,
        maxEgressBytes: 10 * 1024, // 10KB response (metadata only)
        quotaPerMinute: 5, // Expensive operation
        quotaPerHour: 50,
      },
    ],

    // Command injection patterns are detected by Layer 2:
    // - Pipes (|)
    // - Command substitution ($(), ``)
    // - Semicolons (;)
    // - AND/OR (&&, ||)
    // - Redirects (>, <, >>)
    // - Background (&)

    // Default policy
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: true, // CLI tools may create output files
    },

    // Global rate limits
    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 2000,
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

/**
 * Tool 1: git-status
 * Safe git command execution
 * - Allowlisted subcommands only (status, branch, log, diff, show)
 * - Working directory validation
 * - Timeout enforcement
 * - Side effect: 'read'
 */
server.tool(
  'git-status',
  'Execute safe git commands (status, branch, log, diff, show) on a repository.',
  gitStatusSchema.shape,
  async (args: GitStatusArgs) => gitStatus(args)
);

/**
 * Tool 2: image-resize
 * ImageMagick wrapper for image resizing
 * - Input/output path validation
 * - Allowed extensions only (PNG, JPG, GIF, WebP)
 * - No dangerous ImageMagick features
 * - Side effect: 'write' (creates output file)
 */
server.tool(
  'image-resize',
  'Resize images using ImageMagick. Supports PNG, JPG, GIF, WebP.',
  imageResizeSchema.shape,
  async (args: ImageResizeArgs) => imageResize(args)
);

/**
 * Tool 3: pdf-metadata
 * PDF info extraction
 * - Input file validation (PDF only)
 * - No shell execution
 * - Output parsing and sanitization
 * - Side effect: 'read'
 */
server.tool(
  'pdf-metadata',
  'Extract metadata from PDF files (title, author, pages, etc.).',
  pdfMetadataSchema.shape,
  async (args: PdfMetadataArgs) => pdfMetadata(args)
);

/**
 * Tool 4: encode-video
 * FFmpeg video encoding
 * - Input/output path validation
 * - Codec and preset allowlist
 * - Long timeout (5 minutes)
 * - No dangerous FFmpeg features
 * - Side effect: 'write' (creates output file)
 * - Rate limited: 5/minute (expensive operation)
 */
server.tool(
  'encode-video',
  'Encode videos using FFmpeg with safe codec and preset options.',
  encodeVideoSchema.shape,
  async (args: EncodeVideoArgs) => encodeVideo(args)
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.error('CLI Wrapper MCP Server starting...');
  console.error('Security features enabled:');
  console.error('  - Layer 2: Command injection detection');
  console.error('  - Layer 4: Per-tool rate limits and timeouts');
  console.error('  - Layer 4: Side effect enforcement');
  console.error('  - Layer 5: Command allowlist validation');
  console.error('  - App level: Path validation and sanitization');

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('CLI Wrapper MCP Server running on stdio');
  console.error('Tools available: git-status, image-resize, pdf-metadata, encode-video');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
