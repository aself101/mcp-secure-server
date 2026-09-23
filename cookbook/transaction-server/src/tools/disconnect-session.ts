/**
 * Disconnect Session Tool
 *
 * Ends the current session and cleans up state.
 * Allowed from: any connected state (CONNECTED+)
 */

import { z } from 'zod';
import {
  getSession,
  deleteSession,
} from '../utils/index.js';

export const disconnectSessionSchema = z.object({});

export type DisconnectSessionArgs = z.infer<typeof disconnectSessionSchema>;

export type DisconnectSessionResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleDisconnectSession(
  _args: DisconnectSessionArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<DisconnectSessionResult> {
  const sessionId = context.sessionId ?? context.clientId ?? 'default';
  const session = getSession(sessionId);

  if (!session) {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'No active session',
          message: 'No session to disconnect',
        }, null, 2),
      }],
    };
  }

  const previousState = session.state;
  const hadPendingTransaction = !!session.pendingTransaction;

  // Delete session
  deleteSession(sessionId);

  const result: Record<string, unknown> = {
    success: true,
    message: 'Session disconnected successfully',
    previousState,
    sessionDuration: `${((Date.now() - session.createdAt) / 1000).toFixed(1)} seconds`,
  };

  if (hadPendingTransaction) {
    result.warning = 'Pending transaction was discarded';
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2),
    }],
  };
}
