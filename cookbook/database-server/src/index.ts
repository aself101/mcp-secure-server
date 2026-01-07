/**
 * Database MCP Server
 *
 * Demonstrates safe database operations with:
 * - Layer 2: SQL injection pattern detection
 * - Layer 4: Parameterized queries validation
 * - Layer 4: Different quotas for different operation costs
 * - Layer 4: Side effect enforcement
 * - Layer 4: Response size limits
 *
 * Tools:
 * - query-users: Safe user search with parameterized queries
 * - create-order: Insert orders with transaction support
 * - generate-report: Complex analytics queries
 * - health-check: Database connection status
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { z } from 'zod';
import {
  queryUsersSchema,
  queryUsers,
  type QueryUsersArgs,
  createOrderSchema,
  createOrder,
  type CreateOrderArgs,
  generateReportSchema,
  generateReport,
  type GenerateReportArgs,
  healthCheckSchema,
  healthCheck,
} from './tools/index.js';
import { getDatabase } from './utils/index.js';

// ============================================================================
// Configuration
// ============================================================================

const MAX_REPORT_SIZE = parseInt(process.env.MAX_REPORT_SIZE || '524288', 10); // 500KB

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'database-server',
    version: '1.0.0',
  },
  {
    // Security preset - standard for database operations (SQL injection protection)
    securityLevel: 'standard',
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'query-users',
        sideEffects: 'read',
        maxArgsSize: 512,
        maxEgressBytes: 50 * 1024, // 50KB for user list
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'create-order',
        sideEffects: 'write',
        maxArgsSize: 10 * 1024, // 10KB for order data
        maxEgressBytes: 2 * 1024, // 2KB for response
        quotaPerMinute: 10,
        quotaPerHour: 200,
      },
      {
        name: 'generate-report',
        sideEffects: 'read',
        maxArgsSize: 256,
        maxEgressBytes: MAX_REPORT_SIZE,
        quotaPerMinute: 2, // Expensive operation
        quotaPerHour: 20,
      },
      {
        name: 'health-check',
        sideEffects: 'none',
        maxArgsSize: 64,
        maxEgressBytes: 1024,
        quotaPerMinute: 120, // No limit effectively
        quotaPerHour: 3600,
      },
    ],

    // SQL injection patterns are already in Layer 2 content validation
    // The framework will automatically detect and block:
    // - ' OR 1=1 --
    // - '; DROP TABLE users; --
    // - UNION SELECT
    // - etc.

    // Default policy
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: true,
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
 * Tool 1: query-users
 * Safe user search using parameterized queries
 * - All inputs are safely escaped via prepared statements
 * - Limited to 100 results max
 * - Side effect: 'read'
 */
server.tool(
  'query-users',
  'Search for users by name or email. Uses parameterized queries for SQL injection protection.',
  queryUsersSchema.shape,
  async (args: QueryUsersArgs) => queryUsers(args)
);

/**
 * Tool 2: create-order
 * Insert new orders with transaction support
 * - Validates user exists
 * - Validates total matches calculated amount
 * - Uses transaction for atomicity
 * - Side effect: 'write'
 * - Rate limited: 10/minute
 */
server.tool(
  'create-order',
  'Create a new order for a user. Validates user and total amount. Transaction-safe.',
  createOrderSchema.shape,
  async (args: CreateOrderArgs) => createOrder(args)
);

/**
 * Tool 3: generate-report
 * Complex analytics queries (expensive)
 * - Read-only queries
 * - Multiple grouping options
 * - Large response possible (500KB max)
 * - Side effect: 'read'
 * - Rate limited: 2/minute (expensive operation)
 */
server.tool(
  'generate-report',
  'Generate sales analytics report. Supports grouping by day, week, month, department, or status.',
  generateReportSchema.shape,
  async (args: GenerateReportArgs) => generateReport(args)
);

/**
 * Tool 4: health-check
 * Database connection verification
 * - No parameters required
 * - Returns connection status and statistics
 * - Side effect: 'none'
 * - No rate limiting
 */
server.tool(
  'health-check',
  'Check database connection status and get basic statistics.',
  healthCheckSchema.shape,
  async () => healthCheck()
);

// ============================================================================
// Resource Definitions
// ============================================================================

/**
 * Resource 1: database-schema
 * Exposes the database schema for introspection
 * - Read-only access to table definitions
 * - Useful for understanding data structure
 */
server.resource(
  'database-schema',
  'db://schema',
  {
    description: 'Database schema definition showing all tables and columns',
    mimeType: 'application/json',
  },
  async () => {
    const db = getDatabase();
    const tables = db.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table' AND name NOT LIKE 'sqlite_%'
    `).all() as Array<{ name: string }>;

    const schema: Record<string, unknown> = {};
    for (const table of tables) {
      const columns = db.prepare(`PRAGMA table_info(${table.name})`).all();
      schema[table.name] = columns;
    }

    return {
      contents: [{
        uri: 'db://schema',
        mimeType: 'application/json',
        text: JSON.stringify({
          type: 'sqlite',
          mode: 'in-memory',
          tables: schema,
        }, null, 2),
      }],
    };
  }
);

/**
 * Resource 2: database-config
 * Exposes safe database configuration (no secrets)
 */
server.resource(
  'database-config',
  'db://config',
  {
    description: 'Database configuration (safe to expose, no secrets)',
    mimeType: 'application/json',
  },
  async () => {
    return {
      contents: [{
        uri: 'db://config',
        mimeType: 'application/json',
        text: JSON.stringify({
          type: 'sqlite',
          mode: 'in-memory',
          maxReportSize: MAX_REPORT_SIZE,
          securityFeatures: {
            layer2: 'SQL injection pattern detection',
            layer4: ['Per-tool quotas', 'Side effect enforcement', 'Response size limits'],
          },
        }, null, 2),
      }],
    };
  }
);

// ============================================================================
// Prompt Definitions
// ============================================================================

/**
 * Prompt 1: query-builder
 * Helps users construct safe database queries
 */
server.prompt(
  'query-builder',
  'Generate a safe database query for common operations',
  {
    operation: z.enum(['search', 'report', 'order']).describe('Type of operation'),
    details: z.string().optional().describe('Additional details about what you need'),
  },
  async (args: { operation: 'search' | 'report' | 'order'; details?: string }) => {
    const { operation, details } = args;

    const templates: Record<string, string> = {
      search: `To search for users, use the query-users tool:
{
  "search": "your search term",
  "department": "optional department filter",
  "limit": 20
}

The search term will match against both name and email fields.
${details ? `\nYour request: ${details}` : ''}`,

      report: `To generate a report, use the generate-report tool:
{
  "startDate": "YYYY-MM-DD",
  "endDate": "YYYY-MM-DD",
  "groupBy": "day" | "week" | "month" | "department" | "status"
}

This will aggregate sales data for the specified period.
${details ? `\nYour request: ${details}` : ''}`,

      order: `To create an order, use the create-order tool:
{
  "userId": 1,
  "items": [
    { "product": "Product Name", "quantity": 1, "price": 99.99 }
  ],
  "total": 99.99
}

Note: The total must match the sum of (quantity * price) for all items.
${details ? `\nYour request: ${details}` : ''}`,
    };

    return {
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: templates[operation] || 'Unknown operation type.',
        },
      }],
    };
  }
);

/**
 * Prompt 2: security-info
 * Provides information about the security features in use
 */
server.prompt(
  'security-info',
  'Learn about the security features protecting this database server',
  async () => {
    return {
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `This database server is protected by the MCP Security Framework with multiple layers of defense:

## Layer 2: Content Validation
- SQL injection pattern detection (OR 1=1, UNION SELECT, DROP TABLE, etc.)
- NoSQL injection pattern detection ($where, $regex, etc.)
- Blocks malicious payloads before they reach the database

## Layer 4: Semantic Validation
- **Per-tool quotas**: Different rate limits per operation cost
  - query-users: 60/min (cheap read)
  - create-order: 10/min (write operation)
  - generate-report: 2/min (expensive analytics)
- **Side effect enforcement**: Tools declare read/write/none
- **Response size limits**: Max egress bytes per tool

## Application Level
- **Parameterized queries**: All database queries use prepared statements
- **Input validation**: Zod schemas with type constraints
- **Transaction safety**: Atomic writes with rollback on failure

## What This Prevents
- SQL injection attacks
- Data exfiltration via oversized responses
- Resource exhaustion via expensive queries
- Unauthorized write operations`,
        },
      }],
    };
  }
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.error('Database MCP Server starting...');
  console.error('Security features enabled:');
  console.error('  - Layer 2: SQL injection detection');
  console.error('  - Layer 4: Per-tool quotas');
  console.error('  - Layer 4: Side effect enforcement');
  console.error('  - Layer 4: Response size limits');

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('Database MCP Server running on stdio');
  console.error('Tools available: query-users, create-order, generate-report, health-check');
  console.error('Resources available: database-schema, database-config');
  console.error('Prompts available: query-builder, security-info');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
