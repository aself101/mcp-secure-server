/**
 * Response validation helper for SecureMcpServer.
 * Provides wrapper functions for validating tool responses through Layer 5.
 */

import type ContextualValidationLayer from "../layers/layer5-contextual.js";
import type { SecurityLogger } from "./security-logger.js";

/** Response validation context */
interface ResponseValidationContext {
  tool: string;
  arguments: unknown;
}

/** Blocked response structure */
interface BlockedResponse {
  content: Array<{ type: string; text: string }>;
  isError: boolean;
}

/**
 * Creates a response wrapper that validates tool responses through Layer 5.
 *
 * The wrapped handler receives every argument the SDK passes: `(args, extra)` for a
 * tool with an input schema, `(extra)` for one without (SDK `mcp.js`, the tool call
 * path). Until 0.1.0 it passed only the first, so schema-less tools never saw `extra`
 * and Layer 5 received `extra` — request headers included — as `arguments`. Layer 5's
 * `arguments` is now `args` for the first form and `{}` for the second.
 *
 * @param layer5 - The contextual validation layer (may be undefined)
 * @param logger - Security logger for logging blocked responses
 * @param toolName - The tool's name, or a function returning its current name. The
 *   function form is read each time the tool runs, so a tool renamed through its
 *   handle reaches Layer 5 under the name the client called (until 0.1.0 the
 *   creation-time name was captured, over stdio too).
 * @returns A wrapper function that validates responses
 */
export function createResponseWrapper(
  layer5: ContextualValidationLayer | undefined,
  logger: SecurityLogger | null,
  toolName: string | (() => string)
): <T>(handler: (...args: unknown[]) => T | Promise<T>) => (...args: unknown[]) => Promise<T | BlockedResponse> {
  const currentName = typeof toolName === 'function' ? toolName : () => toolName;

  return <T>(handler: (...args: unknown[]) => T | Promise<T>) => {
    return async (...callArgs: unknown[]): Promise<T | BlockedResponse> => {
      const response = await handler(...callArgs);
      const toolName = currentName();
      const args = callArgs.length >= 2 ? callArgs[0] : {};

      // Skip validation if Layer 5 is not available
      if (!layer5 || typeof layer5.validateResponse !== 'function') {
        return response;
      }

      try {
        const context: ResponseValidationContext = { tool: toolName, arguments: args };
        // The SDK's `extra` is always the last argument; over HTTP it names the calling session
        // (D22). Until 0.1.0 this was `{}`, so a response validator never saw a session.
        const extra = callArgs[callArgs.length - 1] as { sessionId?: unknown } | undefined;
        const sessionId = typeof extra?.sessionId === 'string' ? extra.sessionId : undefined;
        const validationResult = await layer5.validateResponse(response, context, sessionId === undefined ? {} : { sessionId });

        if (!validationResult.passed) {
          // Log the blocked response
          if (logger) {
            logger.logInfo(
              `[RESPONSE_BLOCKED] Tool: ${toolName}, Reason: ${validationResult.reason ?? 'Response validation failed'}, ` +
              `Severity: ${validationResult.severity ?? 'HIGH'}, Type: ${validationResult.violationType ?? 'RESPONSE_BLOCKED'}`
            );
          }

          // Return error response instead of blocked content
          return {
            content: [{
              type: 'text',
              text: `Response blocked: ${validationResult.reason ?? 'Response validation failed'}`
            }],
            isError: true
          };
        }
      } catch (error) {
        // Fail CLOSED. Until 0.0.21 this returned the unvalidated response and,
        // with the default null logger, said nothing (ship run #1, issue
        // 5ba0ebdd). Layer 5 now converts validator exceptions to failure
        // results itself, so reaching here means validateResponse broke —
        // the one case where returning the raw tool output is least justified.
        if (logger) {
          logger.logError(
            `[VALIDATOR_ERROR] Response validation failed for tool ${toolName}: ${error instanceof Error ? error.message : 'Unknown error'}`
          );
        }
        return {
          content: [{ type: 'text', text: 'Response blocked: response validation failed' }],
          isError: true
        };
      }

      return response;
    };
  };
}
