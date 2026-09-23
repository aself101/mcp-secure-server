/**
 * Confirm Transaction Tool
 *
 * Confirms a prepared transaction before execution.
 * Requires: TRANSACTION_PREPARED state
 */

import { z } from 'zod';
import {
  getSession,
  updateSessionState,
  confirmTransaction,
  getAllowedTools,
  getAccount,
} from '../utils/index.js';

export const confirmTransactionSchema = z.object({
  confirm: z.literal(true).describe('Must be true to confirm'),
});

export type ConfirmTransactionArgs = z.infer<typeof confirmTransactionSchema>;

export type ConfirmTransactionResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleConfirmTransaction(
  args: ConfirmTransactionArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<ConfirmTransactionResult> {
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

  if (!args.confirm) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Confirmation required',
          message: 'Set confirm: true to confirm the transaction',
        }, null, 2),
      }],
    };
  }

  const tx = session.pendingTransaction;
  const sourceAccount = getAccount(tx.fromAccountId);
  const destAccount = getAccount(tx.toAccountId);

  // Mark transaction as confirmed
  confirmTransaction(sessionId);
  updateSessionState(sessionId, 'TRANSACTION_CONFIRMED');

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        state: 'TRANSACTION_CONFIRMED',
        transactionId: tx.id,
        confirmed: {
          from: sourceAccount?.name ?? tx.fromAccountId,
          to: destAccount?.name ?? tx.toAccountId,
          amount: `${tx.amount.toLocaleString()} ${tx.currency}`,
          description: tx.description,
          confirmedAt: new Date().toISOString(),
        },
        message: 'Transaction confirmed. Call execute-transaction to complete the transfer.',
        warning: 'Once executed, this transaction cannot be reversed.',
        allowedNextActions: getAllowedTools(sessionId),
      }, null, 2),
    }],
  };
}
