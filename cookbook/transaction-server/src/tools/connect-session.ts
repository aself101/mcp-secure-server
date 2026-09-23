/**
 * Connect Session Tool
 *
 * Initializes a secure financial session. This must be the first tool called.
 */

import { z } from 'zod';
import {
  createSession,
  getSession,
  getAllowedTools,
} from '../utils/index.js';

export const connectSessionSchema = z.object({
  clientId: z.string().min(1).max(100).describe('Unique client identifier'),
});

export type ConnectSessionArgs = z.infer<typeof connectSessionSchema>;

export type ConnectSessionResult = {
  content: Array<{ type: 'text'; text: string }>;
};

export async function handleConnectSession(
  args: ConnectSessionArgs,
  context: { sessionId?: string; clientId?: string }
): Promise<ConnectSessionResult> {
  const sessionId = context.sessionId ?? context.clientId ?? args.clientId;

  // Check if session already exists and is active
  const existingSession = getSession(sessionId);
  if (existingSession && existingSession.state !== 'DISCONNECTED') {
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          success: false,
          error: 'Session already active',
          currentState: existingSession.state,
          message: 'Call disconnect-session before creating a new session',
        }, null, 2),
      }],
    };
  }

  // Create new session
  const session = createSession(sessionId);

  return {
    content: [{
      type: 'text',
      text: JSON.stringify({
        success: true,
        sessionId: session.id,
        state: session.state,
        message: 'Session connected successfully. Next step: call list-accounts',
        allowedNextActions: getAllowedTools(sessionId),
        createdAt: new Date(session.createdAt).toISOString(),
      }, null, 2),
    }],
  };
}
