/**
 * HTTP server with security validation for MCP requests.
 * Uses node:http directly for zero external dependencies.
 *
 * ## HTTPS in Production
 *
 * This module provides HTTP transport. For production deployments, always use HTTPS:
 *
 * **Option 1: Reverse Proxy (Recommended)**
 * Deploy behind nginx, Cloudflare, or a load balancer that terminates TLS.
 *
 * **Option 2: Node.js HTTPS**
 * ```typescript
 * import { createServer } from 'node:https';
 * import { readFileSync } from 'node:fs';
 *
 * const handler = createSecureHttpHandler(server);
 * const httpsServer = createServer({
 *   key: readFileSync('server.key'),
 *   cert: readFileSync('server.cert')
 * }, handler);
 * ```
 *
 * ## CORS Handling
 *
 * Wrap the handler for browser clients:
 * ```typescript
 * const handler = createSecureHttpHandler(server);
 * const corsHandler = async (req, res) => {
 *   res.setHeader('Access-Control-Allow-Origin', '*');
 *   if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
 *   return handler(req, res);
 * };
 * ```
 */

import { createServer, IncomingMessage, ServerResponse, Server } from 'node:http';
import type { PipelineContext } from '../utils/validation-pipeline.js';
import { isSeverity, isViolationType } from '../../types/index.js';
import type { Severity, ViolationType } from '../../types/index.js';
import { parseJsonBody } from './http-body-parser.js';
import { HttpTransportManager } from './http-transport-manager.js';
import type {
  HttpHandlerOptions,
  HttpServerOptions,
  SecureHttpHandler,
  SecureServerHttpInterface
} from './http-server-types.js';

// Re-export types for public API
export type {
  HttpHandlerOptions,
  HttpServerOptions,
  SecureHttpHandler,
  SecureServerHttpInterface
} from './http-server-types.js';

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
 * Supports POST (JSON-RPC), GET (SSE streaming), DELETE (session cleanup).
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Handler configuration options
 * @returns Request handler function
 *
 * @example
 * ```typescript
 * const handler = createSecureHttpHandler(server);
 * const httpServer = createServer(handler);
 * ```
 */
export function createSecureHttpHandler(
  secureMcpServer: SecureServerHttpInterface,
  options: HttpHandlerOptions = {}
): SecureHttpHandler {
  const { maxBodySize = 51200, requestTimeout = 30000 } = options;

  const pipeline = secureMcpServer._validationPipeline;
  const errorSanitizer = secureMcpServer._errorSanitizer;
  const logger = secureMcpServer._securityLogger;
  const transportManager = new HttpTransportManager(secureMcpServer);

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method;

    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      res.writeHead(405, { 'Content-Type': 'application/json', 'Allow': 'GET, POST, DELETE' });
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    // GET (SSE) and DELETE (session cleanup) bypass validation
    if (method === 'GET' || method === 'DELETE') {
      try {
        const transport = await transportManager.ensureTransport();
        await transport.handleRequest(req, res);
        logger?.logInfo(`HTTP ${method} request completed`);
      } catch {
        transportManager.handleConnectionFailure();
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }

    // POST: validate Content-Type
    if (!req.headers['content-type']?.includes('application/json')) {
      res.writeHead(415, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Content-Type must be application/json' }));
      return;
    }

    // Parse request body
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

    // Run security validation
    const context: PipelineContext = {
      timestamp: Date.now(),
      sessionId: (req.headers['mcp-session-id'] as string) || 'stateless',
      transportLevel: true,
      httpRequest: true
    };

    const result = await pipeline.validate(body as Record<string, unknown>, context);
    logger?.logSecurityDecision(result, body as Record<string, unknown>, 'HTTP-Transport');

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
      res.writeHead(getHttpStatusForViolation(violationType), { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(errorResponse));
      return;
    }

    // Forward validated request to MCP transport
    try {
      const transport = await transportManager.ensureTransport();
      await transport.handleRequest(req, res, body);
      const rpcMethod = (body as { method?: string })?.method;
      logger?.logInfo(`HTTP POST request completed: ${rpcMethod || 'unknown'}`);
    } catch {
      transportManager.handleConnectionFailure();
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  };
}

/**
 * Creates a standalone HTTP server with security validation.
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Server configuration options
 * @returns Node.js HTTP server (call .listen() to start)
 *
 * @example
 * ```typescript
 * const httpServer = createSecureHttpServer(server, { endpoint: '/mcp' });
 * httpServer.listen(3000);
 * ```
 */
export function createSecureHttpServer(
  secureMcpServer: SecureServerHttpInterface,
  options: HttpServerOptions = {}
): Server {
  const { endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);
  const normalizedEndpoint = endpoint.replace(/\/$/, '');

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/$/, '');

    if (pathname !== normalizedEndpoint) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    await handler(req, res);
  });
}
