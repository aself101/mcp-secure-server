/**
 * Execute Transaction Tool
 *
 * Executes a confirmed transaction.
 * Requires: TRANSACTION_CONFIRMED state
 * Side effects: write (modifies account balances)
 */

import { z } from 'zod';
import {
  getSession,
  updateSessionState,
  clearPendingTransaction,
  getAllowedTools,
  getAccount,
  updateBalance,
  recordTransaction,
} from '../utils/index.js';

export const executeTransactionSchema = z.object({});

export type ExecuteTransactionArgs = z.infer<typeof executeTransactionSchema>;

export type ExecuteTransactionResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleExecuteTransaction(
  _args: ExecuteTransactionArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<ExecuteTransactionResult> {
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

  if (!session.pendingTransaction) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'No pending transaction',
          message: 'Call prepare-transaction first',
        }, null, 2),
      }],
    };
  }

  if (!session.pendingTransaction.confirmedAt) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Transaction not confirmed',
          message: 'Call confirm-transaction first',
        }, null, 2),
      }],
    };
  }

  const tx = session.pendingTransaction;
  const sourceAccount = getAccount(tx.fromAccountId);
  const destAccount = getAccount(tx.toAccountId);

  if (!sourceAccount || !destAccount) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Account not found',
          message: 'Source or destination account no longer exists',
        }, null, 2),
      }],
    };
  }

  // Final balance check
  if (sourceAccount.balance < tx.amount) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Insufficient funds',
          available: `${sourceAccount.balance.toLocaleString()} ${sourceAccount.currency}`,
          requested: `${tx.amount.toLocaleString()} ${tx.currency}`,
          message: 'Balance changed since transaction was prepared',
        }, null, 2),
      }],
    };
  }

  // Execute the transfer
  updateBalance(tx.fromAccountId, -tx.amount);
  updateBalance(tx.toAccountId, tx.amount);

  // Record the transaction
  const completedTx = recordTransaction({
    id: tx.id,
    fromAccountId: tx.fromAccountId,
    toAccountId: tx.toAccountId,
    amount: tx.amount,
    currency: tx.currency,
    status: 'completed',
    description: tx.description,
  });

  // Clear pending and update state
  clearPendingTransaction(sessionId);
  updateSessionState(sessionId, 'TRANSACTION_EXECUTED');

  // Get updated balances
  const updatedSource = getAccount(tx.fromAccountId);
  const updatedDest = getAccount(tx.toAccountId);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        state: 'TRANSACTION_EXECUTED',
        transactionId: completedTx.id,
        executed: {
          from: {
            id: tx.fromAccountId,
            name: sourceAccount.name,
            previousBalance: `${(sourceAccount.balance + tx.amount).toLocaleString()} ${sourceAccount.currency}`,
            newBalance: `${updatedSource?.balance.toLocaleString()} ${updatedSource?.currency}`,
          },
          to: {
            id: tx.toAccountId,
            name: destAccount.name,
            previousBalance: `${(destAccount.balance - tx.amount).toLocaleString()} ${destAccount.currency}`,
            newBalance: `${updatedDest?.balance.toLocaleString()} ${updatedDest?.currency}`,
          },
          amount: `${tx.amount.toLocaleString()} ${tx.currency}`,
          description: tx.description,
          completedAt: new Date(completedTx.completedAt!).toISOString(),
        },
        message: 'Transaction completed successfully!',
        allowedNextActions: getAllowedTools(sessionId),
      }, null, 2),
    }],
  };
}
