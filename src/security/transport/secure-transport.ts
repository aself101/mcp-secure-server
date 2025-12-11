/**
 * Transport wrapper that validates all MCP messages before delivery.
 * Intercepts onmessage to run security validation, blocking malicious requests
 * with proper JSON-RPC error responses.
 */

import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { Severity, ViolationType } from '../../types/index.js';
import { isSeverity, isViolationType, getErrorMessage } from '../../types/index.js';

/** MCP Transport interface for wrapping */
export interface McpTransport {
  onmessage?: ((message: McpMessage, extra?: unknown) => void) | null;
  onerror?: ((error: Error) => void) | null;
  onclose?: (() => void) | null;
  start(): Promise<void>;
  close(): Promise<void>;
  send(message: unknown, options?: unknown): Promise<void>;
  sessionId?: string;
}

/** MCP message structure */
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

/** Message handler type */
type MessageHandler = ((message: McpMessage, extra?: unknown) => void) | null;
type ErrorHandler = ((error: Error) => void) | null;
type CloseHandler = (() => void) | null;

export class SecureTransport {
  private _transport: McpTransport;
  private _validator: TransportValidator;
  private _errorSanitizer: ErrorSanitizer | null;
  private _protocolOnMessage: MessageHandler;
  private _protocolOnError: ErrorHandler;
  private _protocolOnClose: CloseHandler;

  constructor(
    transport: McpTransport,
    validator: TransportValidator,
    options: SecureTransportOptions = {}
  ) {
    this._transport = transport;
    this._validator = validator;
    this._errorSanitizer = options.errorSanitizer ?? null;
    this._protocolOnMessage = null;
    this._protocolOnError = null;
    this._protocolOnClose = null;

    this._setupTransportCallbacks();
  }

  private _setupTransportCallbacks(): void {
    this._transport.onmessage = (message: McpMessage, extra?: unknown) => {
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

  private async _handleMessage(message: McpMessage, extra?: unknown): Promise<void> {
    const messageType = this._getMessageType(message);

    if (messageType === 'response') {
      this._forwardToProtocol(message, extra);
      return;
    }

    const validationResult = await this._validateMessage(message);

    if (!validationResult.allowed) {
      if (messageType === 'request') {
        await this._sendBlockedResponse(message.id ?? null, validationResult);
      }
      return;
    }

    this._forwardToProtocol(message, extra);
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
      await this._transport.send(errorResponse);
    } catch (error) {
      if (this._protocolOnError) {
        this._protocolOnError(new Error(`Failed to send blocked response: ${getErrorMessage(error)}`));
      }
    }
  }

  private _forwardToProtocol(message: McpMessage, extra?: unknown): void {
    if (this._protocolOnMessage) {
      this._protocolOnMessage(message, extra);
    }
  }

  get onmessage(): MessageHandler {
    return this._protocolOnMessage;
  }

  set onmessage(handler: MessageHandler) {
    this._protocolOnMessage = handler;
  }

  get onerror(): ErrorHandler {
    return this._protocolOnError;
  }

  set onerror(handler: ErrorHandler) {
    this._protocolOnError = handler;
  }

  get onclose(): CloseHandler {
    return this._protocolOnClose;
  }

  set onclose(handler: CloseHandler) {
    this._protocolOnClose = handler;
  }

  async start(): Promise<void> {
    return this._transport.start();
  }

  async close(): Promise<void> {
    return this._transport.close();
  }

  async send(message: unknown, options?: unknown): Promise<void> {
    const sanitized = this._sanitizeOutgoingMessage(message);
    return this._transport.send(sanitized, options);
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
