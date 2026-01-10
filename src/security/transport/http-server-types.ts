/**
 * Type definitions for HTTP server transport.
 * @module http-server-types
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ValidationPipeline } from '../utils/validation-pipeline.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { SecurityLogger } from '../utils/security-logger.js';

/** Options for createSecureHttpHandler (no routing) */
export interface HttpHandlerOptions {
  /** Maximum request body size in bytes (default: 51200 = 50KB) */
  maxBodySize?: number;
  /** Request body parse timeout in milliseconds (default: 30000 = 30s) */
  requestTimeout?: number;
}

/** Options for createSecureHttpServer (includes routing) */
export interface HttpServerOptions extends HttpHandlerOptions {
  /** MCP endpoint path (default: '/mcp') */
  endpoint?: string;
}

/** Request handler function type */
export type SecureHttpHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

/** MCP HTTP transport interface */
export interface McpHttpTransport {
  handleRequest(req: IncomingMessage, res: ServerResponse, body?: unknown): Promise<void>;
}

/**
 * Interface for SecureMcpServer HTTP integration.
 * SecureMcpServer implements this interface to allow createSecureHttpHandler
 * and createSecureHttpServer to access required internals.
 */
export interface SecureServerHttpInterface {
  /** Access to validation pipeline for request validation */
  readonly _validationPipeline: ValidationPipeline;
  /** Access to error sanitizer for safe error responses */
  readonly _errorSanitizer: ErrorSanitizer;
  /** Optional security logger for request tracking */
  readonly _securityLogger: SecurityLogger | null;
  /** MCP server for transport connection - uses unknown to avoid SDK type coupling */
  readonly _mcpServer: {
    connect(transport: unknown): Promise<void>;
  };
}
