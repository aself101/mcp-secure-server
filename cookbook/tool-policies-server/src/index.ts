/**
 * Tool Policies MCP Server
 *
 * Demonstrates config-driven tool policies for context-aware security validation.
 * Tool policies are loaded from tool-policies.json, enabling different security
 * levels per tool to reduce false positives while maintaining protection.
 *
 * Security Levels:
 * - EXECUTION: Full validation (command injection, all patterns)
 * - QUERY: Standard validation (SQL/NoSQL patterns added)
 * - STORAGE: Relaxed validation (skips command injection patterns)
 * - DISPLAY: Minimal validation (XSS/deserialization only)
 *
 * Tools:
 * - save-note: STORAGE level - stores documentation that may contain code examples
 * - search-notes: DISPLAY level - read-only search
 * - execute-command: EXECUTION level - full validation (demo only, doesn't execute)
 * - query-data: QUERY level - database-like queries
 *
 * Configuration:
 * Tool policies are defined in tool-policies.json using the v2.0 schema.
 * Supports patterns, base policies, inheritance, and relaxed fields.
 */

import 'dotenv/config';
import { readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  SecureMcpServer,
  initializeToolPolicies,
  getToolPolicy,
  getToolsByLevel,
  isRelaxedField,
  getToolPoliciesConfig,
  type ToolSecurityLevel,
  type ToolPoliciesConfig
} from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// Get the directory of this file for relative path resolution
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ============================================================================
// In-Memory Storage
// ============================================================================

interface Note {
  id: number;
  title: string;
  content: string;
  category: string;
  createdAt: string;
}

const notes: Note[] = [];
let nextId = 1;

// ============================================================================
// Load Tool Policies from Config File
// ============================================================================

async function loadPolicies(): Promise<void> {
  const configPath = join(__dirname, '..', 'tool-policies.json');

  try {
    const content = await readFile(configPath, 'utf-8');
    const config: ToolPoliciesConfig = JSON.parse(content);
    initializeToolPolicies(config);
    console.error(`Loaded tool policies from ${configPath}`);
  } catch (error) {
    console.error(`Warning: Could not load tool-policies.json: ${error}`);
    console.error('Using default EXECUTION level for all tools');
  }
}

// ============================================================================
// Server Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'tool-policies-server',
    version: '1.0.0',
  },
  {
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    toolRegistry: [
      {
        name: 'save-note',
        sideEffects: 'write',
        maxArgsSize: 50 * 1024, // 50KB for documentation
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'search-notes',
        sideEffects: 'read',
        maxArgsSize: 512,
        quotaPerMinute: 120,
        quotaPerHour: 3600,
      },
      {
        name: 'execute-command',
        sideEffects: 'write',
        maxArgsSize: 1024,
        quotaPerMinute: 5, // Restricted
        quotaPerHour: 50,
      },
      {
        name: 'query-data',
        sideEffects: 'read',
        maxArgsSize: 2048,
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
    ],

    defaultPolicy: {
      allowNetwork: false,
      allowWrites: true,
    },

    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 2000,
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

/**
 * Tool 1: save-note (STORAGE level)
 *
 * This tool uses STORAGE security level, which means content can include:
 * - Shell command examples: `ls -la | grep foo`
 * - Event handler documentation: `onclick="handleClick()"`
 * - Code snippets with pipes and operators
 *
 * These would trigger false positives at EXECUTION level but are safe
 * when the content is just being stored as documentation.
 */
server.tool(
  'save-note',
  'Save a documentation note. Content can include code examples that would normally trigger security warnings.',
  {
    title: z.string().min(1).max(200).describe('Note title'),
    content: z.string().min(1).max(50000).describe('Note content - can include code examples'),
    category: z.string().min(1).max(50).default('general').describe('Note category'),
  },
  async (args: { title: string; content: string; category: string }) => {
    const note: Note = {
      id: nextId++,
      title: args.title,
      content: args.content,
      category: args.category,
      createdAt: new Date().toISOString(),
    };
    notes.push(note);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          noteId: note.id,
          message: `Note "${note.title}" saved successfully`,
          securityLevel: getToolPolicy('save-note').level,
        }, null, 2),
      }],
    };
  }
);

/**
 * Tool 2: search-notes (DISPLAY level)
 *
 * Read-only search with minimal validation.
 * Only checks for critical XSS and deserialization patterns.
 */
server.tool(
  'search-notes',
  'Search saved notes by title or content.',
  {
    query: z.string().min(1).max(100).describe('Search query'),
    category: z.string().optional().describe('Filter by category'),
  },
  async (args: { query: string; category?: string }) => {
    let results = notes.filter(note =>
      note.title.toLowerCase().includes(args.query.toLowerCase()) ||
      note.content.toLowerCase().includes(args.query.toLowerCase())
    );

    if (args.category) {
      results = results.filter(note => note.category === args.category);
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          query: args.query,
          category: args.category || 'all',
          count: results.length,
          notes: results.map(n => ({
            id: n.id,
            title: n.title,
            category: n.category,
            preview: n.content.substring(0, 100) + (n.content.length > 100 ? '...' : ''),
          })),
          securityLevel: getToolPolicy('search-notes').level,
        }, null, 2),
      }],
    };
  }
);

/**
 * Tool 3: execute-command (EXECUTION level)
 *
 * This tool has full security validation enabled.
 * Any command injection patterns will be blocked.
 *
 * NOTE: This is a demo tool - it doesn't actually execute commands.
 * It just shows what would be validated.
 */
server.tool(
  'execute-command',
  'Demo command tool with full security validation. Does not actually execute commands.',
  {
    command: z.string().min(1).max(500).describe('Command to validate'),
    args: z.array(z.string()).optional().describe('Command arguments'),
  },
  async (args: { command: string; args?: string[] }) => {
    // In a real implementation, you would execute the command here
    // This demo just shows the validation passed
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: true,
          message: 'Command passed EXECUTION-level security validation',
          command: args.command,
          args: args.args || [],
          securityLevel: getToolPolicy('execute-command').level,
          note: 'This is a demo - no actual command was executed',
        }, null, 2),
      }],
    };
  }
);

/**
 * Tool 4: query-data (QUERY level)
 *
 * Database query tool with SQL/NoSQL injection checks.
 * Blocks SQL patterns like ' OR 1=1 or UNION SELECT.
 */
server.tool(
  'query-data',
  'Query data with SQL/NoSQL injection protection.',
  {
    table: z.enum(['users', 'orders', 'products']).describe('Table to query'),
    filter: z.string().optional().describe('Filter expression'),
    limit: z.number().min(1).max(100).default(10).describe('Max results'),
  },
  async (args: { table: string; filter?: string; limit: number }) => {
    // Demo data
    const demoData: Record<string, Array<Record<string, unknown>>> = {
      users: [
        { id: 1, name: 'Alice', email: 'alice@example.com' },
        { id: 2, name: 'Bob', email: 'bob@example.com' },
      ],
      orders: [
        { id: 1, userId: 1, total: 99.99, status: 'completed' },
        { id: 2, userId: 2, total: 149.99, status: 'pending' },
      ],
      products: [
        { id: 1, name: 'Widget', price: 29.99 },
        { id: 2, name: 'Gadget', price: 49.99 },
      ],
    };

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          table: args.table,
          filter: args.filter || 'none',
          limit: args.limit,
          data: demoData[args.table]?.slice(0, args.limit) || [],
          securityLevel: getToolPolicy('query-data').level,
        }, null, 2),
      }],
    };
  }
);

/**
 * Tool 5: get-policy-info
 *
 * Utility tool to inspect the current tool policy configuration.
 * Shows both the loaded config and resolved policies.
 */
server.tool(
  'get-policy-info',
  'Get information about tool security policies.',
  {
    toolName: z.string().optional().describe('Specific tool to inspect'),
  },
  async (args: { toolName?: string }) => {
    const config = getToolPoliciesConfig();

    if (args.toolName) {
      const policy = getToolPolicy(args.toolName);
      const relaxedFieldChecks: Record<string, boolean> = {};

      // Check common field names
      for (const field of ['content', 'title', 'description', 'data', 'query']) {
        relaxedFieldChecks[field] = isRelaxedField(args.toolName, field);
      }

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            tool: args.toolName,
            resolvedPolicy: policy,
            relaxedFieldChecks,
            configSource: config ? 'tool-policies.json' : 'defaults',
          }, null, 2),
        }],
      };
    }

    // Return config overview and tools grouped by level
    const levels: ToolSecurityLevel[] = ['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY'];
    const byLevel: Record<string, string[]> = {};

    for (const level of levels) {
      byLevel[level] = getToolsByLevel(level);
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          configLoaded: !!config,
          configVersion: config?.version,
          basePolicies: config?.basePolicies ? Object.keys(config.basePolicies) : [],
          patterns: config?.patterns?.map(p => p.match) || [],
          explicitTools: config?.tools ? Object.keys(config.tools) : [],
          defaultLevel: config?.defaultLevel || 'EXECUTION',
          registeredToolsByLevel: byLevel,
          levelDescriptions: {
            EXECUTION: 'Full validation - command injection, all patterns',
            QUERY: 'Standard - adds SQL/NoSQL injection checks',
            STORAGE: 'Relaxed - skips command injection patterns',
            DISPLAY: 'Minimal - XSS/deserialization only',
          },
        }, null, 2),
      }],
    };
  }
);

// ============================================================================
// Resource Definitions
// ============================================================================

server.resource(
  'security-levels',
  'policy://security-levels',
  {
    description: 'Documentation about tool security levels',
    mimeType: 'application/json',
  },
  async () => ({
    contents: [{
      uri: 'policy://security-levels',
      mimeType: 'application/json',
      text: JSON.stringify({
        overview: 'Tools are classified into security levels that determine which patterns are checked.',
        levels: {
          EXECUTION: {
            description: 'Full validation for tools that execute code or commands',
            patterns: ['Command injection', 'Path traversal', 'SQL injection', 'XSS', 'All patterns'],
            examples: ['execute-command', 'run-script', 'shell-access'],
          },
          QUERY: {
            description: 'Standard validation for database and API query tools',
            patterns: ['SQL injection', 'NoSQL injection', 'XSS', 'Deserialization'],
            examples: ['query-data', 'search-database', 'fetch-api'],
          },
          STORAGE: {
            description: 'Relaxed validation for documentation and note-taking tools',
            patterns: ['XSS', 'Deserialization'],
            skipped: ['Command injection', 'Pipe operators', 'Shell syntax'],
            examples: ['save-note', 'add-comment', 'update-documentation'],
          },
          DISPLAY: {
            description: 'Minimal validation for read-only display tools',
            patterns: ['XSS', 'Deserialization'],
            examples: ['search-notes', 'list-items', 'get-status'],
          },
        },
        whyThisMatters: 'Documentation often contains code examples with shell commands, ' +
          'SQL queries, or JavaScript event handlers. These would trigger false positives ' +
          'if validated at EXECUTION level. By classifying tools appropriately, we can ' +
          'maintain security while avoiding frustrating false positives.',
      }, null, 2),
    }],
  })
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.error('Tool Policies MCP Server starting...');
  console.error('');

  // Load tool policies from config file
  await loadPolicies();
  console.error('');

  // Display loaded policies
  const config = getToolPoliciesConfig();
  if (config) {
    console.error('Config-driven Tool Policies (v2.0):');
    console.error(`  Base policies: ${Object.keys(config.basePolicies || {}).join(', ') || 'none'}`);
    console.error(`  Patterns: ${config.patterns?.map(p => p.match).join(', ') || 'none'}`);
    console.error(`  Explicit tools: ${Object.keys(config.tools || {}).join(', ') || 'none'}`);
    console.error(`  Default level: ${config.defaultLevel || 'EXECUTION'}`);
  } else {
    console.error('No config loaded - using EXECUTION level for all tools');
  }
  console.error('');

  console.error('Resolved Security Levels:');
  console.error(`  - save-note:       ${getToolPolicy('save-note').level}`);
  console.error(`  - search-notes:    ${getToolPolicy('search-notes').level}`);
  console.error(`  - execute-command: ${getToolPolicy('execute-command').level}`);
  console.error(`  - query-data:      ${getToolPolicy('query-data').level}`);
  console.error(`  - get-policy-info: ${getToolPolicy('get-policy-info').level}`);
  console.error('');

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('Server running on stdio');
  console.error('Tools: save-note, search-notes, execute-command, query-data, get-policy-info');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
