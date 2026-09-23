/**
 * Prepare Transaction Tool
 *
 * Prepares a transaction with validation.
 * Requires: ACCOUNT_SELECTED state
 */

import { z } from 'zod';
import {
  getSession,
  updateSessionState,
  setPendingTransaction,
  getAllowedTools,
  getAccount,
  type PendingTransaction,
} from '../utils/index.js';

export const prepareTransactionSchema = z.object({
  toAccountId: z.string().min(1).max(50).describe('Destination account ID'),
  amount: z.number().positive().max(1000000).describe('Transaction amount'),
  currency: z.enum(['USD', 'EUR', 'GBP']).default('USD').describe('Currency'),
  description: z.string().max(200).optional().describe('Transaction description'),
});

export type PrepareTransactionArgs = z.infer<typeof prepareTransactionSchema>;

export type PrepareTransactionResult = {
  content: Array<{ type: 'text'; text: string }>;
};

// Generate simple transaction ID
function generateTransactionId(): string {
  return `txn-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

export async function handlePrepareTransaction(
  args: PrepareTransactionArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<PrepareTransactionResult> {
  const sessionId = context.sessionId ?? context.clientId ?? 'default';
  const session = getSession(sessionId);

  if (!session) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'No active session',
          message: 'Call connect-session first',
        }, null, 2),
      }],
    };
  }

  if (!session.selectedAccountId) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'No account selected',
          message: 'Call select-account first',
        }, null, 2),
      }],
    };
  }

  // Validate source account
  const sourceAccount = getAccount(session.selectedAccountId);
  if (!sourceAccount) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Selected account not found',
        }, null, 2),
      }],
    };
  }

  // Validate destination account
  const destAccount = getAccount(args.toAccountId);
  if (!destAccount) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Destination account not found',
          toAccountId: args.toAccountId,
        }, null, 2),
      }],
    };
  }

  // Prevent self-transfer
  if (sourceAccount.id === destAccount.id) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Cannot transfer to same account',
        }, null, 2),
      }],
    };
  }

  // Validate sufficient balance
  if (sourceAccount.balance < args.amount) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Insufficient funds',
          available: `${sourceAccount.balance.toLocaleString()} ${sourceAccount.currency}`,
          requested: `${args.amount.toLocaleString()} ${args.currency}`,
        }, null, 2),
      }],
    };
  }

  // Currency validation
  if (sourceAccount.currency !== args.currency) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Currency mismatch',
          accountCurrency: sourceAccount.currency,
          requestedCurrency: args.currency,
          message: 'Source account currency must match transaction currency',
        }, null, 2),
      }],
    };
  }

  // Create pending transaction
  const transaction: PendingTransaction = {
    id: generateTransactionId(),
    fromAccountId: session.selectedAccountId,
    toAccountId: args.toAccountId,
    amount: args.amount,
    currency: args.currency,
    description: args.description ?? 'Transfer',
    preparedAt: Date.now(),
  };

  setPendingTransaction(sessionId, transaction);
  updateSessionState(sessionId, 'TRANSACTION_PREPARED');

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        state: 'TRANSACTION_PREPARED',
        transactionId: transaction.id,
        details: {
          from: {
            id: sourceAccount.id,
            name: sourceAccount.name,
            balanceAfter: `${(sourceAccount.balance - args.amount).toLocaleString()} ${sourceAccount.currency}`,
          },
          to: {
            id: destAccount.id,
            name: destAccount.name,
          },
          amount: `${args.amount.toLocaleString()} ${args.currency}`,
          description: transaction.description,
        },
        message: 'Transaction prepared. Review details and call confirm-transaction to proceed.',
        warning: 'This transaction has not been executed yet.',
        allowedNextActions: getAllowedTools(sessionId),
      }, null, 2),
    }],
  };
}
