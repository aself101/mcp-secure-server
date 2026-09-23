/**
 * Check Status Tool
 *
 * Check current session status, account balances, and transaction history.
 * Allowed from: any connected state (CONNECTED+)
 */

import { z } from 'zod';
import {
  getSession,
  getAllowedTools,
  getAccount,
  getTransactionHistory,
  getAllTransactions,
} from '../utils/index.js';
import { getStateDescription } from '../validators/index.js';

export const checkStatusSchema = z.object({
  includeHistory: z.boolean().default(false).describe('Include transaction history'),
});

export type CheckStatusArgs = z.infer<typeof checkStatusSchema>;

export type CheckStatusResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleCheckStatus(
  args: CheckStatusArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<CheckStatusResult> {
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

  const result: Record<string, unknown> = {
    success: true,
    session: {
      id: session.id,
      state: session.state,
      stateDescription: getStateDescription(session.state),
      createdAt: new Date(session.createdAt).toISOString(),
      updatedAt: new Date(session.updatedAt).toISOString(),
    },
    allowedNextActions: getAllowedTools(sessionId),
  };

  // Include selected account if any
  if (session.selectedAccountId) {
    const account = getAccount(session.selectedAccountId);
    if (account) {
      result.selectedAccount = {
        id: account.id,
        name: account.name,
        type: account.type,
        balance: `${account.balance.toLocaleString()} ${account.currency}`,
        currency: account.currency,
      };
    }
  }

  // Include pending transaction if any
  if (session.pendingTransaction) {
    const tx = session.pendingTransaction;
    const sourceAccount = getAccount(tx.fromAccountId);
    const destAccount = getAccount(tx.toAccountId);

    result.pendingTransaction = {
      id: tx.id,
      from: sourceAccount?.name ?? tx.fromAccountId,
      to: destAccount?.name ?? tx.toAccountId,
      amount: `${tx.amount.toLocaleString()} ${tx.currency}`,
      description: tx.description,
      preparedAt: new Date(tx.preparedAt).toISOString(),
      confirmed: !!tx.confirmedAt,
      confirmedAt: tx.confirmedAt ? new Date(tx.confirmedAt).toISOString() : null,
    };
  }

  // Include transaction history if requested
  if (args.includeHistory) {
    const allTx = getAllTransactions();
    result.transactionHistory = allTx.map(tx => {
      const from = getAccount(tx.fromAccountId);
      const to = getAccount(tx.toAccountId);
      return {
        id: tx.id,
        from: from?.name ?? tx.fromAccountId,
        to: to?.name ?? tx.toAccountId,
        amount: `${tx.amount.toLocaleString()} ${tx.currency}`,
        status: tx.status,
        description: tx.description,
        completedAt: tx.completedAt ? new Date(tx.completedAt).toISOString() : null,
      };
    });
    result.totalTransactions = allTx.length;
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2),
    }],
  };
}
