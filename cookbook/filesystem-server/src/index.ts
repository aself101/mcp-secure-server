/**
 * Filesystem MCP Server
 *
 * Demonstrates safe file system operations with:
 * - Layer 4: Resource policies (rootDirs, denyGlobs)
 * - Layer 4: maxReadBytes enforcement
 * - Layer 4: Side effect declarations (read vs write)
 * - Layer 2: Path traversal prevention
 *
 * Tools:
 * - read-file: Safe file reading within allowed directories
 * - list-directory: Directory listing with entry limits
 * - search-files: Text search with scan limits
 * - write-log: Append-only logging to restricted directory
 */

import 'dotenv/config';
import * as path from 'path';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  readFileSchema,
  readFile,
  listDirectorySchema,
  listDirectory,
  searchFilesSchema,
  searchFiles,
  writeLogSchema,
  writeLog,
} from './tools/index.js';

import { createPathPolicy } from './utils/index.js';

// ============================================================================
// Configuration
// ============================================================================

const BASE_DIR = process.env.BASE_DIR || process.cwd();
const MAX_FILE_SIZE = parseInt(process.env.MAX_FILE_SIZE || '2097152', 10); // 2MB
const MAX_DIR_ENTRIES = parseInt(process.env.MAX_DIR_ENTRIES || '1000', 10);
const MAX_SEARCH_FILES = parseInt(process.env.MAX_SEARCH_FILES || '100', 10);

// Define allowed directories (relative to BASE_DIR)
const DATA_DIR = path.resolve(BASE_DIR, 'data');
const DOCUMENTS_DIR = path.resolve(BASE_DIR, 'documents');
const LOGS_DIR = path.resolve(BASE_DIR, 'logs');

// Create path policy for read operations
const readPolicy = createPathPolicy(
  [DATA_DIR, DOCUMENTS_DIR],
  [
    '**/*.key',
    '**/*.pem',
    '**/.env',
    '**/.env.*',
    '**/credentials*',
    '**/secrets*',
    '/etc/**',
  ]
);

// Create path policy for write operations (logs only)
const writePolicy = createPathPolicy([LOGS_DIR], []);

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'filesystem-server',
    version: '1.0.0',
  },
  {
    // Security preset - standard for filesystem operations (path traversal protection)
    securityLevel: 'standard',
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'read-file',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: MAX_FILE_SIZE,
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'list-directory',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 100 * 1024, // 100KB for directory listings
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'search-files',
        sideEffects: 'read',
        maxArgsSize: 1024,
        maxEgressBytes: 500 * 1024, // 500KB for search results
        quotaPerMinute: 10,
        quotaPerHour: 100,
      },
      {
        name: 'write-log',
        sideEffects: 'write',
        maxArgsSize: 11 * 1024, // Slightly more than max message size
        maxEgressBytes: 1024, // Small response
        quotaPerMinute: 100,
        quotaPerHour: 2000,
      },
    ],

    // Resource policy for filesystem access
    resourcePolicy: {
      allowedSchemes: ['file'],
      rootDirs: [DATA_DIR, DOCUMENTS_DIR, LOGS_DIR],
      denyGlobs: [
        '**/*.key',
        '**/*.pem',
        '**/.env',
        '**/.env.*',
        '**/credentials*',
        '**/secrets*',
        '/etc/**',
        '/proc/**',
        '/sys/**',
      ],
      maxReadBytes: MAX_FILE_SIZE,
    },

    // Default policy
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: false,
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
 * Tool 1: read-file
 * Safe file reading within allowed directories
 * - Restricted to ./data/ and ./documents/
 * - Blocks sensitive files (.key, .env, etc.)
 * - Max file size: 2MB
 */
server.tool(
  'read-file',
  'Read a file from the allowed directories (data/, documents/). Blocks sensitive files and enforces size limits.',
  readFileSchema.shape,
  async (args) =>
    readFile(args as Parameters<typeof readFile>[0], {
      baseDir: BASE_DIR,
      policy: readPolicy,
      maxFileSize: MAX_FILE_SIZE,
    })
);

/**
 * Tool 2: list-directory
 * Directory listing with entry limits
 * - Same restrictions as read-file
 * - Max 1000 entries
 */
server.tool(
  'list-directory',
  'List contents of a directory within allowed directories. Returns file names, types, sizes, and modification times.',
  listDirectorySchema.shape,
  async (args) =>
    listDirectory(args as Parameters<typeof listDirectory>[0], {
      baseDir: BASE_DIR,
      policy: readPolicy,
      maxEntries: MAX_DIR_ENTRIES,
    })
);

/**
 * Tool 3: search-files
 * Text search in files with scan limits
 * - Same restrictions as read-file
 * - Max 100 files scanned
 */
server.tool(
  'search-files',
  'Search for text patterns within files in the allowed directories. Case-insensitive search with file scan limits.',
  searchFilesSchema.shape,
  async (args) =>
    searchFiles(args as Parameters<typeof searchFiles>[0], {
      baseDir: BASE_DIR,
      policy: readPolicy,
      maxFiles: MAX_SEARCH_FILES,
    })
);

/**
 * Tool 4: write-log
 * Append-only log writing
 * - Restricted to ./logs/ only
 * - Max message: 10KB
 * - Side effect: 'write'
 */
server.tool(
  'write-log',
  'Append a log message to the application log file. Only writes to the logs/ directory.',
  writeLogSchema.shape,
  async (args) =>
    writeLog(args as Parameters<typeof writeLog>[0], {
      baseDir: BASE_DIR,
      logsDir: LOGS_DIR,
    })
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  // Log the configuration
  console.error('Filesystem MCP Server starting...');
  console.error(`Base directory: ${BASE_DIR}`);
  console.error(`Allowed read directories: ${DATA_DIR}, ${DOCUMENTS_DIR}`);
  console.error(`Logs directory: ${LOGS_DIR}`);
  console.error(`Max file size: ${MAX_FILE_SIZE} bytes`);

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('Filesystem MCP Server running on stdio');
  console.error('Tools available: read-file, list-directory, search-files, write-log');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
