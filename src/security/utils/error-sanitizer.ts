/**
 * Error sanitization utilities to prevent information leakage.
 */

import { randomUUID, randomBytes } from 'node:crypto';
import type { Severity, ViolationType } from '../../types/index.js';

/** Logger interface for ErrorSanitizer */
export interface SecurityLogger {
  error(message: string, data: unknown): void;
  warn(message: string, data: unknown): void;
  info(message: string, data: unknown): void;
}

/** Configuration options for ErrorSanitizer */
export interface ErrorSanitizerOptions {
  /** Enable detailed error messages (for development only, default: false) */
  enableDetailedErrors?: boolean;
  /** Maximum length for log entries (default: 1000) */
  maxLogLength?: number;
  /**
   * Enable security event logging (default: true).
   * When enabled, security violations are logged via the provided logger
   * or stderr/stdout if no logger is provided. Set to false for silent operation.
   */
  enableSecurityLogging?: boolean;
  /**
   * Custom logger for security events. If not provided, uses process.stderr/stdout.
   * Provide a logger that implements error(), warn(), and info() methods.
   */
  logger?: SecurityLogger;
}

/** JSON-RPC error response structure */
export interface JsonRpcErrorResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data: {
      timestamp: string;
      token: string;
      retryAfterMs?: number;
      /** Validation reason — included to give MCP clients actionable diagnostics. */
      reason?: string;
      /** Which security layer rejected the request. */
      layer?: string;
    };
  };
}

/** Security violation log entry */
interface SecurityLogEntry {
  type: 'security_violation';
  severity: string;
  violationType: string;
  correlationId: string;
  reason: string;
  ts: string;
}

export class ErrorSanitizer {
  private readonly enableDetailedErrors: boolean;
  private readonly maxLogLength: number;
  private readonly enableSecurityLogging: boolean;
  private readonly logger?: SecurityLogger;

  constructor(options: ErrorSanitizerOptions = {}) {
    this.enableDetailedErrors = !!options.enableDetailedErrors;
    this.maxLogLength = options.maxLogLength || 1000;
    this.enableSecurityLogging = options.enableSecurityLogging ?? true;
    this.logger = options.logger;
  }

  redact(value: unknown): string {
    if (value === null || value === undefined) {
      return 'Validation value null or undefined';
    }

    const s = String(value);
    const trimmed = s.length > this.maxLogLength ? s.slice(0, this.maxLogLength) + '…' : s;

    return this.redactCredentials(this.redactPII(trimmed));
  }

  generateCorrelationId(): string {
    return `sec_${randomUUID()}`;
  }

  generatePublicToken(): string {
    return randomBytes(6).toString('hex');
  }

  getSanitizedMessage(type: string, _severity: string): string {
    const messageMap: Record<string, string> = {
      VALIDATION_ERROR: 'Request validation failed',
      POLICY_VIOLATION: 'Request violates policy',
      CONTEXT_VIOLATION: 'Request not permitted in context',
      RATE_LIMIT_EXCEEDED: 'Too many requests',
      INTERNAL_ERROR: 'Internal validation error',
      UNKNOWN: 'Request could not be processed'
    };

    return messageMap[type] || 'Request could not be processed';
  }

  mapSeverityToErrorCode(_severity: string, violationType: string): number {
    if (violationType === 'RATE_LIMIT_EXCEEDED') return -32000;
    if (violationType === 'INTERNAL_ERROR') return -32603;
    return -32602; // Invalid params
  }

  redactCredentials(text: string): string {
    return text
      // Cloud provider keys
      .replace(/\bAKIA[0-9A-Z]{16}\b/g, '****AWS_KEY****')
      .replace(/\bAISA[0-9A-Z]{16}\b/g, '****AWS_KEY****')
      .replace(/\bARIA[0-9A-Z]{16}\b/g, '****AWS_KEY****')

      // GitHub tokens
      .replace(/\bgh[pousrnt]_[A-Za-z0-9]{36,255}\b/g, '****GITHUB_TOKEN****')

      // Generic API keys
      .replace(/\b[sS][kK]_(?:test|live)_[a-zA-Z0-9]{20,}\b/gi, '****API_KEY****')
      .replace(/\b[a-zA-Z0-9]{32,}\b/g, (match) => {
        return /^[a-fA-F0-9]+$/.test(match) ? '****HEX_KEY****' : match;
      })

      // JWT tokens
      .replace(/\beyJ[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]*\b/g, '****JWT_TOKEN****')

      // Authorization headers
      .replace(/Bearer\s+[A-Za-z0-9._-]{10,}/gi, 'Bearer ****TOKEN****')
      .replace(/Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/gi, 'Authorization: Basic ****')
      .replace(/Authorization:\s*Bearer\s+[A-Za-z0-9._-]+/gi, 'Authorization: Bearer ****')

      // Database connection strings
      .replace(/\b\w+:\/\/[^:]+:[^@]+@[^/\s]+(?:\/[^\s]*)?/g, '****DB_CONNECTION****')

      // Private keys
      .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '****PRIVATE_KEY****')

      // Common password patterns
      .replace(/["']?password["']?\s*[:=]\s*["'][^"']+["']/gi, '"password": "****"')
      .replace(/["']?pass["']?\s*[:=]\s*["'][^"']+["']/gi, '"pass": "****"')
      .replace(/["']?secret["']?\s*[:=]\s*["'][^"']+["']/gi, '"secret": "****"');
  }

  redactPII(text: string): string {
    return text
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '****EMAIL****');
  }

  logSecurityViolation(
    correlationId: string,
    internalReason: string,
    severity: string,
    violationType: string
  ): void {
    if (!this.enableSecurityLogging) {
      return;
    }

    const entry: SecurityLogEntry = {
      type: 'security_violation',
      severity,
      violationType,
      correlationId,
      reason: this.redact(internalReason),
      ts: new Date().toISOString()
    };

    const message = '[SECURITY]';
    if (this.logger) {
      if (severity === 'CRITICAL' || severity === 'HIGH') {
        this.logger.error(message, entry);
      } else if (severity === 'MEDIUM') {
        this.logger.warn(message, entry);
      } else {
        this.logger.info(message, entry);
      }
    } else {
      const logLine = `${message} ${JSON.stringify(entry)}\n`;
      if (severity === 'CRITICAL' || severity === 'HIGH' || severity === 'MEDIUM') {
        process.stderr.write(logLine);
      } else {
        process.stdout.write(logLine);
      }
    }
  }

  createSanitizedErrorResponse(
    messageId: string | number | null,
    internalReason: string,
    severity: Severity | string = 'MEDIUM',
    violationType: ViolationType | string = 'UNKNOWN'
  ): JsonRpcErrorResponse {
    const correlationId = this.generateCorrelationId();
    const publicToken = this.generatePublicToken();

    this.logSecurityViolation(correlationId, internalReason, severity, violationType);

    const data: JsonRpcErrorResponse['error']['data'] = {
      timestamp: new Date().toISOString(),
      token: publicToken,
      // Include redacted reason and violation type so MCP clients get actionable diagnostics.
      // The reason is already redacted of credentials/PII by logSecurityViolation above.
      reason: this.redact(internalReason),
      layer: typeof violationType === 'string' ? violationType : undefined,
    };

    if (violationType === 'RATE_LIMIT_EXCEEDED') {
      data.retryAfterMs = 60000;
    }

    // When detailed errors are enabled, propagate the redacted reason as the
    // top-level message so callers (humans, LLMs, logs) can see what failed
    // without digging into the data envelope.
    const message = this.enableDetailedErrors
      ? `${this.getSanitizedMessage(violationType, severity)}: ${this.redact(internalReason)}`
      : this.getSanitizedMessage(violationType, severity);

    return {
      jsonrpc: '2.0',
      id: messageId ?? null,
      error: {
        code: this.mapSeverityToErrorCode(severity, violationType),
        message,
        data
      }
    };
  }

  createMiddlewareErrorResponse(
    messageId: string | number | null,
    errorMessage: string | Error | { message?: string }
  ): JsonRpcErrorResponse {
    const correlationId = this.generateCorrelationId();
    const publicToken = this.generatePublicToken();

    const detail = typeof errorMessage === 'string'
      ? errorMessage
      : ((errorMessage as Error)?.message || 'Middleware error');
    this.logSecurityViolation(correlationId, detail, 'HIGH', 'INTERNAL_ERROR');

    return {
      jsonrpc: '2.0',
      id: messageId ?? null,
      error: {
        code: -32603,
        message: 'Internal validation error',
        data: {
          timestamp: new Date().toISOString(),
          token: publicToken
        }
      }
    };
  }

  /**
   * Detects if error data contains Zod validation error patterns.
   * Zod errors have distinctive structures with codes like "too_big", "invalid_type", etc.
   */
  isZodError(errorData: unknown): boolean {
    if (!errorData || typeof errorData !== 'object') return false;

    const data = errorData as Record<string, unknown>;

    // Zod errors have specific code values
    const zodCodes = [
      'too_big', 'too_small', 'invalid_type', 'invalid_enum_value',
      'invalid_literal', 'custom', 'unrecognized_keys', 'invalid_union',
      'invalid_union_discriminator', 'invalid_date', 'invalid_string',
      'invalid_arguments', 'invalid_return_type', 'not_finite', 'not_multiple_of'
    ];

    // Check for Zod error code
    if (typeof data.code === 'string' && zodCodes.includes(data.code)) {
      return true;
    }

    // Check for Zod error array structure (issues array)
    if (Array.isArray(data.issues)) {
      const issues = data.issues as Array<Record<string, unknown>>;
      return issues.some(issue =>
        typeof issue.code === 'string' && zodCodes.includes(issue.code)
      );
    }

    // Check for path array (common in Zod errors)
    if (Array.isArray(data.path) && typeof data.code === 'string') {
      return true;
    }

    return false;
  }

  /**
   * Sanitizes a JSON-RPC error response that may contain Zod validation details.
   * Returns sanitized response if Zod patterns detected, null otherwise.
   *
   * Tool input validation errors (-32602) are preserved because the Zod details
   * describe the caller's input mistakes (field paths, expected types), not
   * internal implementation state. Stripping these makes errors undiagnosable.
   */
  sanitizeOutgoingError(message: unknown): unknown {
    if (!message || typeof message !== 'object') return null;

    const msg = message as Record<string, unknown>;

    // Current MCP SDKs CATCH their own input-validation McpError inside the
    // tools/call handler and wrap it into a CallToolResult ({content,
    // isError: true}) — so the raw dump leaves as a RESULT, not a protocol
    // error, and the error branch below never sees it. Rewrite the content
    // text in place; everything else about the result passes through.
    if (msg.jsonrpc === '2.0' && msg.result && typeof msg.result === 'object') {
      const rewritten = this.rewriteToolErrorResult(msg.result as Record<string, unknown>);
      if (rewritten !== null) {
        return { ...msg, result: rewritten };
      }
      return null;
    }

    // Must be a JSON-RPC error response with object error
    if (msg.jsonrpc !== '2.0' || !msg.error || typeof msg.error !== 'object') return null;

    const error = msg.error as Record<string, unknown>;
    const errorData = error.data;

    // The MCP SDK's own inputSchema validation throws before any tool handler
    // runs, with the raw Zod issue array serialized INTO THE MESSAGE STRING
    // ("Input validation error: Invalid arguments for tool X: [{...}]").
    // That surface bypasses every server-side error envelope — it is the error
    // a first-time caller hits most, delivered in the least readable shape.
    // Rewrite it into per-field prose; preserve code and id. Anything that
    // doesn't parse cleanly passes through untouched.
    if (error.code === -32602 && typeof error.message === 'string') {
      const rewritten = this.rewriteSdkValidationMessage(error.message);
      if (rewritten !== null) {
        return {
          jsonrpc: '2.0',
          id: (msg.id as string | number | null | undefined) ?? null,
          error: {
            code: -32602,
            message: rewritten,
            ...(errorData !== undefined ? { data: errorData } : {}),
          },
        };
      }
    }

    // Check if error data contains Zod patterns
    if (!this.isZodError(errorData)) return null;

    // -32602 (Invalid params) errors describe the caller's input — preserve
    // the validation details so they can fix their request. These are not
    // internal implementation leaks; they are the input contract.
    if (error.code === -32602) return null;

    // Log the original error internally
    const correlationId = this.generateCorrelationId();
    this.logSecurityViolation(
      correlationId,
      `Zod validation error sanitized: ${JSON.stringify(errorData)}`,
      'LOW',
      'VALIDATION_ERROR'
    );

    // Return sanitized error response with enough context to debug
    return {
      jsonrpc: '2.0',
      id: msg.id ?? null,
      error: {
        code: -32602,
        message: 'Invalid input parameters',
        data: {
          timestamp: new Date().toISOString(),
          token: this.generatePublicToken(),
          reason: 'Input failed schema validation (Zod). Check parameter types and required fields.',
          layer: 'OUTGOING_SANITIZER',
        }
      }
    };
  }

  /**
   * Rewrites the MCP SDK's raw tool-input validation message into readable
   * per-field prose. Returns null when the message is not the SDK's
   * "Invalid arguments for tool X: [zod json]" shape (pass through unchanged).
   */
  rewriteSdkValidationMessage(message: string): string | null {
    const match = /Invalid arguments for tool ([\w./-]+):\s*([\s\S]+)$/.exec(message);
    if (!match) return null;

    const toolName = match[1];
    const payload = (match[2] as string).trim();

    let lines: string[] | null = null;
    if (payload.startsWith('[')) {
      // Older MCP SDKs serialize the raw Zod issue array into the message.
      lines = this.formatZodIssueArray(payload);
    } else if (/ at [\w[\].]+/.test(payload) || /^(Required|Invalid|Expected|Unrecognized)/.test(payload)) {
      // Current MCP SDKs format "<message> at <dot.path>" lines (zod-compat
      // getParseErrorMessage). Reorder to "<path>: <message>" prose.
      lines = payload.split('\n').map((line) => {
        const m = / at ([\w[\].]+)$/.exec(line);
        if (m) return `${m[1] as string}: ${line.slice(0, m.index)}`;
        return line;
      });
    }
    if (lines === null || lines.length === 0) return null;

    return (
      `Invalid arguments for tool ${String(toolName)} — ${lines.join('; ')}. ` +
      `Fix the named field(s) and retry; check parameter types and required fields against the tool's input schema.`
    );
  }

  /**
   * Rewrites an isError CallToolResult whose text is the MCP SDK's raw
   * input-validation message. Returns the rewritten result object, or null
   * when the result is not that shape (pass through unchanged).
   */
  rewriteToolErrorResult(result: Record<string, unknown>): Record<string, unknown> | null {
    if (result.isError !== true || !Array.isArray(result.content)) return null;
    const content = result.content as Array<Record<string, unknown>>;
    let changed = false;
    const newContent = content.map((item) => {
      if (item.type !== 'text' || typeof item.text !== 'string') return item;
      // Strip the McpError prefix chain before matching; the rewrite result
      // stands on its own without it.
      const text = item.text;
      if (!/Input validation error: Invalid arguments for tool /.test(text)) return item;
      const rewritten = this.rewriteSdkValidationMessage(
        text.replace(/^MCP error -?\d+:\s*/, '').replace(/^Input validation error:\s*/, ''),
      );
      if (rewritten === null) return item;
      changed = true;
      return { ...item, text: rewritten };
    });
    return changed ? { ...result, content: newContent } : null;
  }

  /** Format a serialized Zod issue array (older MCP SDK message payloads). */
  private formatZodIssueArray(payload: string): string[] | null {
    let issues: unknown;
    try {
      issues = JSON.parse(payload);
    } catch {
      return null;
    }
    if (!Array.isArray(issues) || issues.length === 0 || !this.isZodError({ issues })) {
      return null;
    }
    return (issues as Array<Record<string, unknown>>).map((issue) => {
      const path = Array.isArray(issue.path) && issue.path.length > 0
        ? issue.path.join('.')
        : '(input)';
      const base = typeof issue.message === 'string' ? issue.message : 'invalid';
      if (issue.code === 'invalid_type') {
        const expected = typeof issue.expected === 'string' ? issue.expected : 'a different type';
        const received = issue.received === 'undefined'
          ? 'the field is missing'
          : `received ${String(issue.received)}`;
        return `${path}: ${base} (expected ${expected}, ${received})`;
      }
      return `${path}: ${base}`;
    });
  }

  static createProductionConfig(): ErrorSanitizerOptions {
    return {
      enableDetailedErrors: false,
      maxLogLength: 500
    };
  }

  static createDevelopmentConfig(): ErrorSanitizerOptions {
    return {
      enableDetailedErrors: true,
      maxLogLength: 2000
    };
  }

  /** Shared singleton instance for production use */
  private static sharedInstance: ErrorSanitizer | null = null;

  /**
   * Get or create a shared ErrorSanitizer instance with production config.
   * Use this instead of creating new instances to reduce memory allocation.
   */
  static getSharedInstance(): ErrorSanitizer {
    if (!ErrorSanitizer.sharedInstance) {
      ErrorSanitizer.sharedInstance = new ErrorSanitizer(
        ErrorSanitizer.createProductionConfig()
      );
    }
    return ErrorSanitizer.sharedInstance;
  }
}

export function createSanitizedErrorResponse(
  messageId: string | number | null,
  internalReason: string,
  severity?: Severity | string,
  violationType?: ViolationType | string,
  options: ErrorSanitizerOptions = {}
): JsonRpcErrorResponse {
  const sanitizer = new ErrorSanitizer(options);
  return sanitizer.createSanitizedErrorResponse(messageId, internalReason, severity, violationType);
}
