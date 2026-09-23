/**
 * Select Account Tool
 *
 * Selects an account for transaction operations.
 * Requires: ACCOUNTS_LISTED state
 */

import { z } from 'zod';
import {
  getSession,
  updateSessionState,
  setSelectedAccount,
  getAllowedTools,
  getAccount,
} from '../utils/index.js';

export const selectAccountSchema = z.object({
  accountId: z.string().min(1).max(50).describe('Account ID to select'),
});

export type SelectAccountArgs = z.infer<typeof selectAccountSchema>;

export type SelectAccountResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleSelectAccount(
  args: SelectAccountArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<SelectAccountResult> {
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

  // Validate account exists
  const account = getAccount(args.accountId);
  if (!account) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Account not found',
          accountId: args.accountId,
          message: 'Call list-accounts to see available accounts',
        }, null, 2),
      }],
    };
  }

  // Set selected account and update state
  setSelectedAccount(sessionId, args.accountId);
  updateSessionState(sessionId, 'ACCOUNT_SELECTED');

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        state: 'ACCOUNT_SELECTED',
        selectedAccount: {
          id: account.id,
          name: account.name,
          type: account.type,
          balance: `${account.balance.toLocaleString()} ${account.currency}`,
          currency: account.currency,
        },
        message: 'Account selected. Next step: call prepare-transaction',
        allowedNextActions: getAllowedTools(sessionId),
      }, null, 2),
    }],
  };
}
