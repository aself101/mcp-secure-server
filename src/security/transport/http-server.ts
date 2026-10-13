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
// Static, not `require('node:https')`: this package ships as ESM (package.json
// "type": "module"), where `require` is not defined. The dynamic require
// compiled clean under tsc and passed every test (vitest supplies a `require`
// shim to src/), and threw `ReferenceError: require is not defined` on the
// first call in the published dist/ — the "recommended for production" TLS
// path was unusable from 0.0.17 to 0.0.20 (ship run #1, 2026-09-10). The
// module is ~free to load; laziness bought nothing.
import { createServer as createHttpsServer } from 'node:https';
import { safeLogDecision, type PipelineContext, type PipelineLogger } from '../utils/validation-pipeline.js';
import { isSeverity, isViolationType } from '../../types/index.js';
import type { Severity, ViolationType } from '../../types/index.js';
import { parseJsonBody } from './http-body-parser.js';
import { HttpTransportManager } from './http-transport-manager.js';
import { ErrorRateLimiter } from './error-rate-limiter.js';
import { createClientIpResolver, type ClientIpResolver, type TrustProxy } from './client-ip.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import { WarningChannel, WARNING_CODES } from '../warnings.js';
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

/** Which per-IP limiter refused a request; sent as X-RateLimit-Scope so operators can tell the three 429s apart. */
type RateLimitScope = 'errors' | 'sessionless' | 'not-found';

/** Write a 429 for a per-IP limiter and log the key it fired on */
function writeRateLimited(res: ServerResponse, scope: RateLimitScope, clientIp: string, logger: SecurityLogger | null): void {
  logger?.logInfo(`HTTP 429 (${scope}) for client ${clientIp}`);
  writeSecureResponse(res, 429, { error: 'Too many requests' }, { 'Retry-After': '60', 'X-RateLimit-Scope': scope });
}

/** Per-IP request ceilings must be positive integers; NaN or Infinity would silently disable the limit. */
function requirePositiveInteger(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive integer (got ${String(value)})`);
  }
  return value;
}

/** Session id header must be visible ASCII (MCP spec) and bounded; arrays (repeated header) are rejected. */
function isValidSessionId(value: string | string[]): boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && /^[\x21-\x7e]+$/.test(value);
}

/** The experimental label, carried at runtime (spec D4; perverse P12 for its scope). */
const HTTP_EXPERIMENTAL_MESSAGE =
  'The mcp-secure-server HTTP transport is experimental in this release. It has no authentication, ' +
  'and session ids are bearer credentials. Layer 3 rate limits are shared by every client of a ' +
  'server, so one client can exhaust the budget for all. Not for untrusted multi-tenant use until 0.2.0.';

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
  const {
    maxBodySize = 51200,
    requestTimeout = 30000,
    sessionlessRequestsPerMinute = 60,
    sessionlessRequestsPerHour = 600
  } = options;
  const resolveClientIp = createClientIpResolver({ trustProxy: options.trustProxy });
  requirePositiveInteger('sessionlessRequestsPerMinute', sessionlessRequestsPerMinute);
  requirePositiveInteger('sessionlessRequestsPerHour', sessionlessRequestsPerHour);

  const pipeline = secureMcpServer._validationPipeline;
  const errorSanitizer = secureMcpServer._errorSanitizer;
  const logger = secureMcpServer._securityLogger;
  const transportManager = new HttpTransportManager(secureMcpServer);
  const errorRateLimiter = new ErrorRateLimiter();
  // GET/DELETE have no body for the message pipeline to validate, so the
  // per-IP windowed counter is their only per-client control. Same counter
  // class as the error limiter; here it counts requests, not errors.
  const sessionlessRateLimiter = new ErrorRateLimiter({
    errorsPerMinute: sessionlessRequestsPerMinute,
    errorsPerHour: sessionlessRequestsPerHour
  });

  /** Check error rate limit and return 429 if exceeded */
  const checkErrorRateLimit = (clientIp: string, res: ServerResponse): boolean => {
    if (errorRateLimiter.shouldRateLimit(clientIp)) {
      writeRateLimited(res, 'errors', clientIp, logger);
      return true;
    }
    return false;
  };

  /** Record an error for rate limiting */
  const recordError = (clientIp: string): void => {
    errorRateLimiter.recordError(clientIp);
  };

  // Last, after every option has been validated, so a constructor that throws
  // leaves the server's registrations open (spec A, the freeze).
  (secureMcpServer._warnings ?? new WarningChannel())
    .oncePerProcess(WARNING_CODES.HTTP_EXPERIMENTAL, HTTP_EXPERIMENTAL_MESSAGE);
  secureMcpServer._freezeRegistrations?.();

  // Resolved once, before any await: after a mid-body reset the socket no
  // longer reports its peer, and until 0.0.26 aborted POSTs were charged to
  // a shared 'unknown' key instead of the client that sent them.
  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const method = req.method;
    const clientIp = resolveClientIp(req);

    if (method !== 'POST' && method !== 'GET' && method !== 'DELETE') {
      if (checkErrorRateLimit(clientIp, res)) return;
      recordError(clientIp);
      writeSecureResponse(res, 405, { error: 'Method not allowed' }, { 'Allow': 'GET, POST, DELETE' });
      return;
    }

    // Mcp-Session-Id is forwarded to the SDK on every method and used as the
    // pipeline's sessionId on POST; bound its shape before either sees it.
    // MCP spec: visible ASCII (0x21-0x7E). Length cap is ours.
    const sessionHeader = req.headers['mcp-session-id'];
    if (sessionHeader !== undefined && !isValidSessionId(sessionHeader)) {
      if (checkErrorRateLimit(clientIp, res)) return;
      recordError(clientIp);
      writeSecureResponse(res, 400, { error: 'Invalid Mcp-Session-Id header' });
      return;
    }

    // GET (SSE) and DELETE (session cleanup) carry no JSON-RPC body, so the
    // message pipeline (Layers 1-5) has nothing to validate. Until 2026-09-10
    // that meant NO control at all on this branch — not even the error
    // lockout applied, so an IP already throttled for probing could still open
    // SSE streams and tear down sessions without limit (ship run #1, AF-003).
    // Both per-IP counters now gate it.
    if (method === 'GET' || method === 'DELETE') {
      if (checkErrorRateLimit(clientIp, res)) return;
      if (sessionlessRateLimiter.shouldRateLimit(clientIp)) {
        writeRateLimited(res, 'sessionless', clientIp, logger);
        return;
      }
      sessionlessRateLimiter.recordError(clientIp);
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
      if (checkErrorRateLimit(clientIp, res)) return;
      recordError(clientIp);
      writeSecureResponse(res, 415, { error: 'Content-Type must be application/json' });
      return;
    }

    // Parse request body
    let body: unknown;
    try {
      body = await parseJsonBody(req, maxBodySize, requestTimeout);
    } catch (err) {
      if (checkErrorRateLimit(clientIp, res)) return;
      recordError(clientIp);
      const message = err instanceof Error ? err.message : 'Invalid request';
      const status = message.includes('timeout') ? 408 : 400;
      writeSecureResponse(res, status, { error: message });
      return;
    }

    // Run security validation. Option-derived fields (policy, logger, verbose)
    // come from the server — until 0.0.21 this context had none of them, so
    // Layer 4 saw `policy: undefined` and denied every write/network tool
    // over HTTP whatever defaultPolicy said (ship run #1, issue 1debab5a).
    const context: PipelineContext = secureMcpServer._createPipelineContext({
      sessionId: (req.headers['mcp-session-id'] as string) || 'stateless',
      // The transport is stateless (no session ids are issued), so the header
      // above is client-chosen; per-client Layer 5 limits key on this instead.
      clientId: clientIp,
      transportLevel: true,
      httpRequest: true,
      originalMessage: body,
      requestId: (body as { id?: unknown } | null)?.id
    });

    const result = await pipeline.validate(body as Record<string, unknown>, context);
    // SecurityLogger's typed signature narrows PipelineLogger's; structurally compatible (see transport-validator.ts).
    safeLogDecision(logger as PipelineLogger | undefined, result, body, 'HTTP-Transport');

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
  return createServer(createEndpointListener(handler, endpoint, handlerOptions.trustProxy, secureMcpServer._securityLogger));
}

/**
 * Routes requests to `handler` when the path matches `endpoint`, 404s the rest
 * (error-rate-limited), and guarantees the listener never rejects.
 *
 * Two invariants, both learned from ship run #1 (2026-09-10):
 *
 * - The URL is parsed against a CONSTANT base. Until then it was
 *   `new URL(req.url, `http://${req.headers.host}`)`, and `new URL` throws on
 *   a Host containing a forbidden host code point (`^`, space, `[`, ...). The
 *   Host header contributes nothing to endpoint matching, so it was pure
 *   attack surface.
 * - The body is wrapped: `http.createServer` discards the promise an async
 *   listener returns, so any throw became an unhandled rejection and, under
 *   Node's default policy, a process exit. One unauthenticated request
 *   (`GET /mcp` with `Host: a^b`) took the server down. The whole body is
 *   now inside a try, so the promise this async listener returns (and Node
 *   discards) cannot reject; a throw ends the response with 500.
 */
function createEndpointListener(
  handler: SecureHttpHandler,
  endpoint: string,
  trustProxy: TrustProxy | undefined,
  logger: SecurityLogger | null
): SecureHttpHandler {
  const normalizedEndpoint = endpoint.replace(/\/$/, '');
  const errorRateLimiter = new ErrorRateLimiter();
  const resolveClientIp: ClientIpResolver = createClientIpResolver({ trustProxy, onWarning: false });

  return async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      const pathname = new URL(req.url ?? '/', 'http://localhost').pathname.replace(/\/$/, '');

      if (pathname !== normalizedEndpoint) {
        const clientIp = resolveClientIp(req);
        if (errorRateLimiter.shouldRateLimit(clientIp)) {
          writeRateLimited(res, 'not-found', clientIp, logger);
          return;
        }
        errorRateLimiter.recordError(clientIp);
        writeSecureResponse(res, 404, { error: 'Not found' });
        return;
      }

      await handler(req, res);
    } catch (err) {
      logger?.logError(`HTTP listener error: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) {
        writeSecureResponse(res, 500, { error: 'Internal server error' });
      } else if (!res.writableEnded) {
        res.end();
      }
    }
  };
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
  const { key, cert, ca, endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);

  const tlsOptions: { key: string | Buffer; cert: string | Buffer; ca?: string | Buffer | (string | Buffer)[] } = { key, cert };
  if (ca) tlsOptions.ca = ca;

  return createHttpsServer(tlsOptions, createEndpointListener(handler, endpoint, handlerOptions.trustProxy, secureMcpServer._securityLogger));
}
