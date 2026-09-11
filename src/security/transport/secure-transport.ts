/**
 * Transport wrapper that validates all MCP messages before delivery.
 * Intercepts onmessage to run security validation, blocking malicious requests
 * with proper JSON-RPC error responses.
 */

import type { Transport, TransportSendOptions } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { JSONRPCMessage, MessageExtraInfo } from '@modelcontextprotocol/sdk/types.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { Severity, ViolationType } from '../../types/index.js';
import { isSeverity, isViolationType, getErrorMessage } from '../../types/index.js';

/**
 * MCP Transport interface - extends SDK Transport for type compatibility.
 * This ensures SecureTransport can wrap any SDK-compatible transport.
 */
export interface McpTransport extends Transport {
  // Inherits all Transport members, can add custom extensions here
}

/**
 * MCP message structure - structurally compatible with SDK's JSONRPCMessage.
 * This allows the transport to handle all JSON-RPC message types while
 * maintaining flexibility for validation processing.
 */
export interface McpMessage {
  jsonrpc?: string;
  method?: string;
  id?: string | number | null;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
  [key: string]: unknown;
}

/**
 * View an SDK JSONRPCMessage through the permissive internal McpMessage
 * interface for inspection and validation. This is a widening (every union
 * member is assignable to the all-optional interface), so no assertion is
 * needed. The narrowing direction — internal -> SDK — no longer exists:
 * until 0.0.21 `_handleMessage` received only this widened view and had to
 * `as unknown as JSONRPCMessage` it back to forward it (ship run #1, issue
 * 9fa5f64d). It now keeps the original SDK object and forwards that.
 */
function asMcpMessage(message: JSONRPCMessage): McpMessage {
  return message;
}

/** Validation result from validator function */
export interface TransportValidationResult {
  passed: boolean;
  allowed: boolean;
  reason?: string | null;
  severity?: Severity | string;
  violationType?: ViolationType | string | null;
}

/** Validator function signature */
export type TransportValidator = (
  message: McpMessage,
  context: TransportValidationContext
) => Promise<TransportValidationResult> | TransportValidationResult;

/** Validation context passed to validator */
export interface TransportValidationContext {
  timestamp: number;
  transportLevel: boolean;
}

/** SecureTransport options */
export interface SecureTransportOptions {
  errorSanitizer?: ErrorSanitizer | null;
}

/** JSON-RPC error response */
interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
  };
}

/** Message type classification */
type MessageType = 'request' | 'notification' | 'response' | 'unknown';

/**
 * Handler types matching SDK Transport interface.
 * Uses SDK types directly for type-safe handler signatures.
 */
type SdkMessageHandler = (<T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => void) | undefined;
type SdkErrorHandler = ((error: Error) => void) | undefined;
type SdkCloseHandler = (() => void) | undefined;

/**
 * Secure transport wrapper that intercepts MCP messages for security validation.
 *
 * Implements the SDK Transport interface for seamless integration with McpServer.
 * Wraps any MCP transport to validate incoming messages before they reach handlers.
 * Blocks malicious requests with proper JSON-RPC error responses.
 *
 * @example
 * ```typescript
 * import { SecureTransport } from 'mcp-security';
 *
 * const secureTransport = new SecureTransport(
 *   originalTransport,
 *   async (message, context) => {
 *     // Custom validation logic
 *     return { passed: true, allowed: true };
 *   }
 * );
 * ```
 */
export class SecureTransport implements Transport {
  private _transport: McpTransport;
  private _validator: TransportValidator;
  private _errorSanitizer: ErrorSanitizer | null;
  private _protocolOnMessage: SdkMessageHandler;
  private _protocolOnError: SdkErrorHandler;
  private _protocolOnClose: SdkCloseHandler;

  constructor(
    transport: McpTransport,
    validator: TransportValidator,
    options: SecureTransportOptions = {}
  ) {
    this._transport = transport;
    this._validator = validator;
    this._errorSanitizer = options.errorSanitizer ?? null;
    this._protocolOnMessage = undefined;
    this._protocolOnError = undefined;
    this._protocolOnClose = undefined;

    this._setupTransportCallbacks();
  }

  private _setupTransportCallbacks(): void {
    this._transport.onmessage = <T extends JSONRPCMessage>(message: T, extra?: MessageExtraInfo) => {
      return this._handleMessage(message, extra);
    };

    this._transport.onerror = (error: Error) => {
      if (this._protocolOnError) {
        this._protocolOnError(error);
      }
    };

    this._transport.onclose = () => {
      if (this._protocolOnClose) {
        this._protocolOnClose();
      }
    };
  }

  private async _handleMessage(original: JSONRPCMessage, extra?: MessageExtraInfo): Promise<void> {
    const message = asMcpMessage(original);
    const messageType = this._getMessageType(message);

    if (messageType === 'response') {
      this._forwardToProtocol(original, extra);
      return;
    }

    const validationResult = await this._validateMessage(message);

    if (!validationResult.allowed) {
      if (messageType === 'request') {
        await this._sendBlockedResponse(message.id ?? null, validationResult);
      }
      return;
    }

    // Forward the SDK's own object, not the widened view — same reference,
    // correct static type, no cast.
    this._forwardToProtocol(original, extra);
  }

  private _getMessageType(message: McpMessage): MessageType {
    if (message.method !== undefined && message.id !== undefined) {
      return 'request';
    }
    if (message.method !== undefined && message.id === undefined) {
      return 'notification';
    }
    if (message.id !== undefined && (message.result !== undefined || message.error !== undefined)) {
      return 'response';
    }
    return 'unknown';
  }

  private async _validateMessage(message: McpMessage): Promise<TransportValidationResult> {
    try {
      const context: TransportValidationContext = {
        timestamp: Date.now(),
        transportLevel: true
      };
      return await this._validator(message, context);
    } catch (_error) {
      return {
        allowed: false,
        passed: false,
        reason: 'Validation error',
        severity: 'CRITICAL',
        violationType: 'VALIDATION_ERROR'
      };
    }
  }

  private async _sendBlockedResponse(
    requestId: string | number | null,
    validationResult: TransportValidationResult
  ): Promise<void> {
    let errorResponse: JsonRpcErrorResponse | ReturnType<ErrorSanitizer['createSanitizedErrorResponse']>;

    const severity: Severity = isSeverity(validationResult.severity)
      ? validationResult.severity
      : 'HIGH';
    const violationType: ViolationType = isViolationType(validationResult.violationType)
      ? validationResult.violationType
      : 'POLICY_VIOLATION';

    if (this._errorSanitizer) {
      errorResponse = this._errorSanitizer.createSanitizedErrorResponse(
        requestId,
        validationResult.reason ?? 'Request blocked by security policy',
        severity,
        violationType
      );
    } else {
      errorResponse = {
        jsonrpc: '2.0',
        id: requestId,
        error: {
          code: -32602,
          message: validationResult.reason ?? 'Request blocked by security policy'
        }
      };
    }

    try {
      await this._transport.send(errorResponse as JSONRPCMessage);
    } catch (error) {
      if (this._protocolOnError) {
        const wrappedError = new Error(`Failed to send blocked response: ${getErrorMessage(error)}`);
        wrappedError.cause = error;
        this._protocolOnError(wrappedError);
      }
    }
  }

  private _forwardToProtocol(message: JSONRPCMessage, extra?: MessageExtraInfo): void {
    if (this._protocolOnMessage) {
      this._protocolOnMessage(message, extra);
    }
  }

  get onmessage(): SdkMessageHandler {
    return this._protocolOnMessage;
  }

  set onmessage(handler: SdkMessageHandler) {
    this._protocolOnMessage = handler;
  }

  get onerror(): SdkErrorHandler {
    return this._protocolOnError;
  }

  set onerror(handler: SdkErrorHandler) {
    this._protocolOnError = handler;
  }

  get onclose(): SdkCloseHandler {
    return this._protocolOnClose;
  }

  set onclose(handler: SdkCloseHandler) {
    this._protocolOnClose = handler;
  }

  async start(): Promise<void> {
    return this._transport.start();
  }

  async close(): Promise<void> {
    return this._transport.close();
  }

  async send(message: JSONRPCMessage, options?: TransportSendOptions): Promise<void> {
    const sanitized = this._sanitizeOutgoingMessage(message);
    return this._transport.send(sanitized as JSONRPCMessage, options);
  }

  private _sanitizeOutgoingMessage(message: unknown): unknown {
    if (!this._errorSanitizer) return message;

    const sanitized = this._errorSanitizer.sanitizeOutgoingError(message);
    return sanitized ?? message;
  }

  get sessionId(): string | undefined {
    return this._transport.sessionId;
  }
}
