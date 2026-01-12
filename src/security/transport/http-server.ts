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
import { ErrorRateLimiter, getClientIp } from './error-rate-limiter.js';
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

// Note: HttpsServerOptions is exported directly from this file (not http-server-types.js)

/** Security headers applied to all responses */
const SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'application/json',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store',
  'X-XSS-Protection': '0',
  // CSP: Strict policy for JSON API (no scripts, styles, or external resources)
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  // HSTS: Enable strict transport security when served over HTTPS
  // Note: Browsers ignore this header over HTTP, so it's safe to include unconditionally
  // For production, consider increasing max-age to 31536000 (1 year) at reverse proxy level
  'Strict-Transport-Security': 'max-age=86400; includeSubDomains'
};

/** Write response with security headers */
function writeSecureResponse(
  res: ServerResponse,
  statusCode: number,
  body: unknown,
  extraHeaders: Record<string, string> = {}
): void {
  res.writeHead(statusCode, { ...SECURITY_HEADERS, ...extraHeaders });
  res.end(JSON.stringify(body));
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
  const errorRateLimiter = new ErrorRateLimiter();

  /** Check error rate limit and return 429 if exceeded */
  const checkErrorRateLimit = (req: IncomingMessage, res: ServerResponse): boolean => {
    const clientIp = getClientIp(req);
    if (errorRateLimiter.shouldRateLimit(clientIp)) {
      writeSecureResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '60' });
      return true;
    }
    return false;
  };

  /** Record an error for rate limiting */
  const recordError = (req: IncomingMessage): void => {
    const clientIp = getClientIp(req);
    errorRateLimiter.recordError(clientIp);
  };

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method;

    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      if (checkErrorRateLimit(req, res)) return;
      recordError(req);
      writeSecureResponse(res, 405, { error: 'Method not allowed' }, { 'Allow': 'GET, POST, DELETE' });
      return;
    }

    // GET (SSE) and DELETE (session cleanup) bypass validation
    if (method === 'GET' || method === 'DELETE') {
      try {
        const transport = await transportManager.ensureTransport();
        await transport.handleRequest(req, res);
        logger?.logInfo(`HTTP ${method} request completed`);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        logger?.logError(`HTTP ${method} request failed: ${errorMessage}`);
        transportManager.handleConnectionFailure();
        writeSecureResponse(res, 500, { error: 'Internal server error' });
      }
      return;
    }

    // POST: validate Content-Type
    if (!req.headers['content-type']?.includes('application/json')) {
      if (checkErrorRateLimit(req, res)) return;
      recordError(req);
      writeSecureResponse(res, 415, { error: 'Content-Type must be application/json' });
      return;
    }

    // Parse request body
    let body: unknown;
    try {
      body = await parseJsonBody(req, maxBodySize, requestTimeout);
    } catch (err) {
      if (checkErrorRateLimit(req, res)) return;
      recordError(req);
      const message = err instanceof Error ? err.message : 'Invalid request';
      const status = message.includes('timeout') ? 408 : 400;
      writeSecureResponse(res, status, { error: message });
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
      writeSecureResponse(res, getHttpStatusForViolation(violationType), errorResponse);
      return;
    }

    // Forward validated request to MCP transport
    try {
      const transport = await transportManager.ensureTransport();
      await transport.handleRequest(req, res, body);
      const rpcMethod = (body as { method?: string })?.method;
      logger?.logInfo(`HTTP POST request completed: ${rpcMethod || 'unknown'}`);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      const rpcMethod = (body as { method?: string })?.method;
      logger?.logError(`HTTP POST request failed (${rpcMethod || 'unknown'}): ${errorMessage}`);
      transportManager.handleConnectionFailure();
      writeSecureResponse(res, 500, { error: 'Internal server error' });
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
  const errorRateLimiter = new ErrorRateLimiter();

  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/$/, '');

    if (pathname !== normalizedEndpoint) {
      const clientIp = getClientIp(req);
      if (errorRateLimiter.shouldRateLimit(clientIp)) {
        writeSecureResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '60' });
        return;
      }
      errorRateLimiter.recordError(clientIp);
      writeSecureResponse(res, 404, { error: 'Not found' });
      return;
    }

    await handler(req, res);
  });
}

/** HTTPS server options for secure MCP transport */
export interface HttpsServerOptions extends HttpServerOptions {
  /** TLS private key (PEM format string or Buffer) */
  key: string | Buffer;
  /** TLS certificate (PEM format string or Buffer) */
  cert: string | Buffer;
  /** Optional CA certificate chain */
  ca?: string | Buffer | (string | Buffer)[];
}

/**
 * Creates an HTTPS server with security validation.
 * Recommended for production deployments.
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - HTTPS server options including TLS certificates
 * @returns Node.js HTTPS server (call .listen() to start)
 *
 * @example
 * ```typescript
 * import { readFileSync } from 'node:fs';
 *
 * const httpsServer = createSecureHttpsServer(server, {
 *   key: readFileSync('server.key'),
 *   cert: readFileSync('server.cert'),
 *   endpoint: '/mcp'
 * });
 * httpsServer.listen(3443);
 * ```
 */
export function createSecureHttpsServer(
  secureMcpServer: SecureServerHttpInterface,
  options: HttpsServerOptions
): Server {
  // Dynamic require to avoid loading https module when not needed
  const https = require('node:https');

  const { key, cert, ca, endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);
  const normalizedEndpoint = endpoint.replace(/\/$/, '');
  const errorRateLimiter = new ErrorRateLimiter();

  const tlsOptions: { key: string | Buffer; cert: string | Buffer; ca?: string | Buffer | (string | Buffer)[] } = { key, cert };
  if (ca) tlsOptions.ca = ca;

  return https.createServer(tlsOptions, async (req: IncomingMessage, res: ServerResponse) => {
    const parsedUrl = new URL(req.url || '/', `https://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname.replace(/\/$/, '');

    if (pathname !== normalizedEndpoint) {
      const clientIp = getClientIp(req);
      if (errorRateLimiter.shouldRateLimit(clientIp)) {
        writeSecureResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '60' });
        return;
      }
      errorRateLimiter.recordError(clientIp);
      writeSecureResponse(res, 404, { error: 'Not found' });
      return;
    }

    await handler(req, res);
  }) as Server;
}
