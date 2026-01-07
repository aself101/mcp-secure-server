/**
 * Transaction MCP Server
 *
 * Demonstrates Layer 4 method chaining security with a financial transaction workflow.
 * Shows how chaining prevents out-of-order operations and state confusion attacks.
 *
 * Transaction Flow:
 * connect-session -> list-accounts -> select-account -> prepare-transaction
 *                 -> confirm-transaction -> execute-transaction -> disconnect-session
 */

import { SecureMcpServer, ContextualValidationLayer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  connectSessionSchema,
  handleConnectSession,
  listAccountsSchema,
  handleListAccounts,
  selectAccountSchema,
  handleSelectAccount,
  prepareTransactionSchema,
  handlePrepareTransaction,
  confirmTransactionSchema,
  handleConfirmTransaction,
  executeTransactionSchema,
  handleExecuteTransaction,
  checkStatusSchema,
  handleCheckStatus,
  disconnectSessionSchema,
  handleDisconnectSession,
} from './tools/index.js';

import { createWorkflowStateValidator } from './validators/index.js';
import { initializeSessionStore } from './utils/index.js';

// Initialize session store
initializeSessionStore();

// Create secure server with chaining enabled
const server = new SecureMcpServer(
  {
    name: 'transaction-server',
    version: '1.0.0',
  },
  {
    // Security preset - paranoid for financial transactions (maximum security)
    securityLevel: 'paranoid',
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // CRITICAL: Enable Layer 4 method chaining enforcement
    enforceChaining: true,

    // Tool registry with financial operation policies
    toolRegistry: [
      {
        name: 'connect-session',
        sideEffects: 'none',
        maxArgsSize: 512,
        maxEgressBytes: 1024,
        quotaPerMinute: 60,
        quotaPerHour: 500,
      },
      {
        name: 'list-accounts',
        sideEffects: 'read',
        maxArgsSize: 256,
        maxEgressBytes: 10 * 1024,
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'select-account',
        sideEffects: 'none',
        maxArgsSize: 256,
        maxEgressBytes: 2 * 1024,
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'prepare-transaction',
        sideEffects: 'none',
        maxArgsSize: 2 * 1024,
        maxEgressBytes: 4 * 1024,
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'confirm-transaction',
        sideEffects: 'none',
        maxArgsSize: 512,
        maxEgressBytes: 2 * 1024,
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'execute-transaction',
        sideEffects: 'write',
        maxArgsSize: 512,
        maxEgressBytes: 2 * 1024,
        quotaPerMinute: 10,  // Most restricted - expensive operation
        quotaPerHour: 100,
      },
      {
        name: 'check-status',
        sideEffects: 'read',
        maxArgsSize: 256,
        maxEgressBytes: 8 * 1024,
        quotaPerMinute: 120,
        quotaPerHour: 2000,
      },
      {
        name: 'disconnect-session',
        sideEffects: 'none',
        maxArgsSize: 256,
        maxEgressBytes: 512,
        quotaPerMinute: 60,
        quotaPerHour: 500,
      },
    ],

    // Default policy - write enabled for execute-transaction
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: true,
    },

    // Global rate limits
    maxRequestsPerMinute: 100,
    maxRequestsPerHour: 2000,

    // Session configuration
    sessionTtlMs: 30 * 60 * 1000,  // 30 minute session TTL
    maxSessions: 1000,

    // Layer 5 contextual validation
    contextual: {
      enabled: true,
      rateLimiting: {
        enabled: true,
        limit: 100,
        windowMs: 60000,
      },
    },
  }
);

// Register Layer 5 workflow state validator
const layer5 = server.validationPipeline.layers[4] as ContextualValidationLayer;
layer5.addValidator(
  'workflow-state',
  createWorkflowStateValidator() as Parameters<typeof layer5.addValidator>[1],
  { priority: 10, enabled: true }
);

// Helper to create context from tool args
function createContext(args: { clientId?: string }): { sessionId: string; clientId: string } {
  const id = args.clientId ?? 'default';
  return { sessionId: id, clientId: id };
}

// Register tools
server.tool(
  'connect-session',
  'Initialize a secure financial session. Must be called first.',
  connectSessionSchema.shape,
  async (args) => handleConnectSession(
    args as Parameters<typeof handleConnectSession>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'list-accounts',
  'List available accounts. Requires: active session.',
  listAccountsSchema.shape,
  async (args) => handleListAccounts(
    args as Parameters<typeof handleListAccounts>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'select-account',
  'Select an account for transactions. Requires: accounts listed.',
  selectAccountSchema.shape,
  async (args) => handleSelectAccount(
    args as Parameters<typeof handleSelectAccount>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'prepare-transaction',
  'Prepare a transaction for review. Requires: account selected.',
  prepareTransactionSchema.shape,
  async (args) => handlePrepareTransaction(
    args as Parameters<typeof handlePrepareTransaction>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'confirm-transaction',
  'Confirm a prepared transaction. Requires: transaction prepared.',
  confirmTransactionSchema.shape,
  async (args) => handleConfirmTransaction(
    args as Parameters<typeof handleConfirmTransaction>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'execute-transaction',
  'Execute a confirmed transaction. Requires: transaction confirmed.',
  executeTransactionSchema.shape,
  async (args) => handleExecuteTransaction(
    args as Parameters<typeof handleExecuteTransaction>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'check-status',
  'Check session status, balances, and history. Allowed anytime when connected.',
  checkStatusSchema.shape,
  async (args) => handleCheckStatus(
    args as Parameters<typeof handleCheckStatus>[0],
    createContext(args as { clientId?: string })
  )
);

server.tool(
  'disconnect-session',
  'End the current session. Allowed anytime when connected.',
  disconnectSessionSchema.shape,
  async (args) => handleDisconnectSession(
    args as Parameters<typeof handleDisconnectSession>[0],
    createContext(args as { clientId?: string })
  )
);

// Start server
async function main() {
  console.error('Transaction MCP Server starting...');
  console.error('');
  console.error('Security features enabled:');
  console.error('  - Layer 4: Method chaining enforcement (enforceChaining: true)');
  console.error('  - Layer 5: Workflow state validation');
  console.error('');
  console.error('Transaction flow:');
  console.error('  connect-session -> list-accounts -> select-account');
  console.error('  -> prepare-transaction -> confirm-transaction -> execute-transaction');
  console.error('');

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error('Transaction MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
