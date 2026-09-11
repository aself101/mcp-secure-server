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
 * @param layer5 - The contextual validation layer (may be undefined)
 * @param logger - Security logger for logging blocked responses
 * @param toolName - Name of the tool being wrapped
 * @returns A wrapper function that validates responses
 */
export function createResponseWrapper(
  layer5: ContextualValidationLayer | undefined,
  logger: SecurityLogger | null,
  toolName: string
): <T>(handler: (args: unknown) => Promise<T>) => (args: unknown) => Promise<T | BlockedResponse> {

  return <T>(handler: (args: unknown) => Promise<T>) => {
    return async (args: unknown): Promise<T | BlockedResponse> => {
      const response = await handler(args);

      // Skip validation if Layer 5 is not available
      if (!layer5 || typeof layer5.validateResponse !== 'function') {
        return response;
      }

      try {
        const context: ResponseValidationContext = { tool: toolName, arguments: args };
        const validationResult = await layer5.validateResponse(response, context, {});

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
