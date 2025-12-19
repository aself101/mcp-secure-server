/**
 * HTTP server with security validation for MCP requests.
 * Uses node:http directly for zero external dependencies.
 *
 * ## Transport Lifecycle
 *
 * Each handler maintains a singleton transport instance per SecureMcpServer.
 * This is intentional - MCP connections are stateful and the SDK's
 * StreamableHTTPServerTransport manages session state internally.
 *
 * The transport is lazily initialized on first request and reconnects
 * automatically if the connection is lost.
 *
 * ## CORS Handling
 *
 * CORS is not handled automatically. Wrap the handler for browser clients:
 *
 * ```typescript
 * const handler = createSecureHttpHandler(server);
 * const corsHandler = async (req, res) => {
 *   res.setHeader('Access-Control-Allow-Origin', '*');
 *   res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
 *   res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Mcp-Session-Id');
 *   if (req.method === 'OPTIONS') {
 *     res.writeHead(204).end();
 *     return;
 *   }
 *   return handler(req, res);
 * };
 * ```
 */

import { createServer, IncomingMessage, ServerResponse, Server } from 'node:http';
import type { ValidationPipeline, PipelineContext } from '../utils/validation-pipeline.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import { isSeverity, isViolationType } from '../../types/index.js';
import type { Severity, ViolationType } from '../../types/index.js';

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
interface McpHttpTransport {
  handleRequest(req: IncomingMessage, res: ServerResponse, body?: unknown): Promise<void>;
}

/** Internal interface for accessing SecureMcpServer internals */
interface SecureMcpServerInternal {
  validationPipeline: ValidationPipeline;
  _errorSanitizer: ErrorSanitizer;
  _securityLogger: SecurityLogger | null;
  mcpServer: {
    connect(transport: McpHttpTransport): Promise<void>;
  };
}

/** Map violation types to HTTP status codes */
function getHttpStatusForViolation(violationType: ViolationType): number {
  switch (violationType) {
    case 'RATE_LIMIT_EXCEEDED':
    case 'QUOTA_EXCEEDED':
    case 'BURST_ACTIVITY':
      return 429;
    case 'SIZE_LIMIT_EXCEEDED':
    case 'OVERSIZED_MESSAGE':
    case 'OVERSIZED_PARAMS':
      return 413;
    case 'POLICY_VIOLATION':
    case 'TOOL_NOT_ALLOWED':
    case 'RESOURCE_POLICY_VIOLATION':
    case 'SIDE_EFFECT_NOT_ALLOWED':
      return 403;
    default:
      return 400;
  }
}

/**
 * Creates an HTTP request handler with security validation.
 * Use this for composing multiple MCP endpoints on a single server.
 *
 * Supports all MCP HTTP transport methods:
 * - POST: JSON-RPC requests (validated through security pipeline)
 * - GET: SSE streaming (passed directly to transport)
 * - DELETE: Session cleanup (passed directly to transport)
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Handler configuration options
 * @returns Request handler function (req, res) => Promise<void>
 *
 * @example
 * ```typescript
 * import { SecureMcpServer, createSecureHttpHandler } from 'mcp-security';
 * import { createServer } from 'node:http';
 *
 * const adminServer = new SecureMcpServer({ name: 'admin', version: '1.0' });
 * const publicServer = new SecureMcpServer({ name: 'public', version: '1.0' });
 *
 * const adminHandler = createSecureHttpHandler(adminServer);
 * const publicHandler = createSecureHttpHandler(publicServer);
 *
 * const httpServer = createServer(async (req, res) => {
 *   if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
 *   if (req.url?.startsWith('/api/public')) return publicHandler(req, res);
 *   res.writeHead(404).end();
 * });
 * ```
 */
export function createSecureHttpHandler(
  secureMcpServer: SecureMcpServerInternal,
  options: HttpHandlerOptions = {}
): SecureHttpHandler {
  const { maxBodySize = 51200, requestTimeout = 30000 } = options;

  const pipeline = secureMcpServer.validationPipeline;
  const errorSanitizer = secureMcpServer._errorSanitizer;
  const logger = secureMcpServer._securityLogger;

  let transport: McpHttpTransport | null = null;
  let connected = false;

  /** Initialize or reconnect transport */
  async function ensureTransport(): Promise<McpHttpTransport> {
    if (!transport) {
      const { StreamableHTTPServerTransport } = await import(
        '@modelcontextprotocol/sdk/server/streamableHttp.js'
      );
      transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    }

    if (!connected) {
      try {
        await secureMcpServer.mcpServer.connect(transport);
        connected = true;
      } catch (err) {
        // Reset state on connection failure for retry
        transport = null;
        connected = false;
        throw err;
      }
    }

    return transport;
  }

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method;

    // MCP HTTP transport supports POST (requests), GET (SSE), DELETE (cleanup)
    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'GET, POST, DELETE' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    // GET (SSE) and DELETE (session cleanup) bypass validation - no request body
    if (method === 'GET' || method === 'DELETE') {
      try {
        const t = await ensureTransport();
        await t.handleRequest(req, res);
        if (logger) {
          logger.logInfo(`HTTP ${method} request completed`);
        }
      } catch (_err) {
        // Reset connection state AND transport for full reconnection on next request
        transport = null;
        connected = false;
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }

    // POST requests: validate Content-Type
    const contentType = req.headers['content-type'];
    if (!contentType?.includes('application/json')) {
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
      return;
    }

    // Parse request body with timeout
    let body: unknown;
    try {
      body = await parseJsonBody(req, maxBodySize, requestTimeout);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid request';
      const status = message.includes('timeout') ? 408 : 400;
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: message }));
      return;
    }

    const sessionId = (req.headers['mcp-session-id'] as string) || 'stateless';

    const context: PipelineContext = {
      timestamp: Date.now(),
      sessionId,
      transportLevel: true,
      httpRequest: true
    };

    const result = await pipeline.validate(body as Record<string, unknown>, context);

    if (logger) {
      logger.logSecurityDecision(result, body as Record<string, unknown>, 'HTTP-Transport');
    }

    if (!result.passed) {
      const requestId = (body as { id?: string | number | null })?.id ?? null;
      const severity: Severity = isSeverity(result.severity) ? result.severity : 'HIGH';
      const violationType: ViolationType = isViolationType(result.violationType)
        ? result.violationType
        : 'POLICY_VIOLATION';

      const errorResponse = errorSanitizer.createSanitizedErrorResponse(
        requestId,
        result.reason ?? 'Request blocked by security policy',
        severity,
        violationType
      );
      const httpStatus = getHttpStatusForViolation(violationType);
      res.writeHead(httpStatus, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errorResponse));
      return;
    }

    try {
      const t = await ensureTransport();
      await t.handleRequest(req, res, body);
      if (logger) {
        const rpcMethod = (body as { method?: string })?.method;
        logger.logInfo(`HTTP POST request completed: ${rpcMethod || 'unknown'}`);
      }
    } catch (_err) {
      // Reset connection state AND transport for full reconnection on next request
      transport = null;
      connected = false;
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  };
}

/**
 * Creates a standalone HTTP server with security validation.
 * Zero external dependencies - uses node:http directly.
 *
 * URL matching is flexible:
 * - Matches `/mcp`, `/mcp/`, and `/mcp?query=value`
 * - Trailing slashes and query strings are handled correctly
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Server configuration options
 * @returns Node.js HTTP server (call .listen() to start)
 *
 * @example
 * ```typescript
 * const httpServer = createSecureHttpServer(server, { endpoint: '/mcp' });
 * httpServer.listen(3000, () => {
 *   console.log('MCP server listening on http://localhost:3000/mcp');
 * });
 * ```
 */
export function createSecureHttpServer(
  secureMcpServer: SecureMcpServerInternal,
  options: HttpServerOptions = {}
): Server {
  const { endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);

  // Normalize endpoint for matching (remove trailing slash)
  const normalizedEndpoint = endpoint.replace(/\/$/, '');

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    // Parse URL to extract pathname (handles query strings)
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/$/, ''); // Remove trailing slash

    if (pathname !== normalizedEndpoint) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    await handler(req, res);
  });
}

/**
 * Parse JSON body from request with size limit and timeout.
 *
 * @param req - HTTP request
 * @param maxSize - Maximum body size in bytes
 * @param timeoutMs - Timeout in milliseconds
 * @returns Parsed JSON body
 * @throws Error if body exceeds size, times out, or is invalid JSON
 */
async function parseJsonBody(
  req: IncomingMessage,
  maxSize: number,
  timeoutMs: number
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    let completed = false;

    const timeout = setTimeout(() => {
      if (!completed) {
        completed = true;
        req.destroy();
        reject(new Error('Request timeout'));
      }
    }, timeoutMs);

    const cleanup = () => {
      clearTimeout(timeout);
      completed = true;
    };

    req.on('data', (chunk: Buffer) => {
      if (completed) return;

      size += chunk.length;
      if (size > maxSize) {
        cleanup();
        req.destroy();
        reject(new Error(`Body exceeds ${maxSize} bytes`));
        return;
      }
      data += chunk.toString();
    });

    req.on('end', () => {
      if (completed) return;
      cleanup();

      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });

    req.on('error', (err) => {
      if (completed) return;
      cleanup();
      reject(err);
    });
  });
}
