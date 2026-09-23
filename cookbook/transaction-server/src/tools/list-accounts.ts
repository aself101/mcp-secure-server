/**
 * List Accounts Tool
 *
 * Lists all available accounts for the session.
 * Requires: CONNECTED state
 */

import { z } from 'zod';
import {
  getSession,
  updateSessionState,
  getAllowedTools,
  getAllAccounts,
} from '../utils/index.js';

export const listAccountsSchema = z.object({});

export type ListAccountsArgs = z.infer<typeof listAccountsSchema>;

export type ListAccountsResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleListAccounts(
  _args: ListAccountsArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<ListAccountsResult> {
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

  // Get all accounts
  const accounts = getAllAccounts();

  // Update state
  updateSessionState(sessionId, 'ACCOUNTS_LISTED');

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        state: 'ACCOUNTS_LISTED',
        accounts: accounts.map(a => ({
          id: a.id,
          name: a.name,
          type: a.type,
          balance: `${a.balance.toLocaleString()} ${a.currency}`,
          currency: a.currency,
        })),
        totalAccounts: accounts.length,
        message: 'Accounts listed. Next step: call select-account with an account ID',
        allowedNextActions: getAllowedTools(sessionId),
      }, null, 2),
    }],
  };
}
