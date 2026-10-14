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
 * Wrap the handler for browser clients. Echo the request's `Origin` only when it is listed
 * (never `*`, never `null`), and pass the same list as `allowedOrigins`. The wrapper must
 * never delete or rewrite `Origin`: the handler validates it, and a wrapper that strips it
 * turns that check off for every page on the machine. A client with an opaque origin (an
 * Electron renderer on `file://`, a sandboxed frame) sends `Origin: null`, which cannot be
 * listed; connect from a context that sends no `Origin` (Electron's main process) or from a
 * listed origin instead.
 * ```typescript
 * const allowedOrigins = ['http://localhost:5173'];
 * const handler = createSecureHttpHandler(server, { allowedOrigins });
 * const corsHandler = async (req, res) => {
 *   const origin = req.headers.origin;
 *   const listed = origin !== undefined && allowedOrigins.includes(origin);
 *   if (listed) {
 *     res.setHeader('Access-Control-Allow-Origin', origin);
 *     res.setHeader('Vary', 'Origin');
 *     res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
 *     res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID');
 *     res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
 *   }
 *   if (req.method === 'OPTIONS') { res.writeHead(listed ? 204 : 403).end(); return; }
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
import { ErrorRateLimiter } from './error-rate-limiter.js';
import { createClientIpResolver, type ClientIpResolver, type TrustProxy } from './client-ip.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import { WarningChannel, WARNING_CODES } from '../warnings.js';
import { SessionRegistry } from './session-registry.js';
import { createSessionFlow } from './http-session-flow.js';
import { boundAddress, createOriginPolicy, exposureMessage, isLoopbackAddress } from './http-origin.js';
import { writeSecureResponse, writeRateLimited, requirePositiveInteger } from './http-response.js';
import type {
  HttpHandlerOptions,
  HttpServerOptions,
  SecureHttpHandler,
  SessionHttpHandler,
  SecureServerHttpInterface
} from './http-server-types.js';

// Re-export types for public API
export type {
  HttpHandlerOptions,
  HttpServerOptions,
  SecureHttpHandler,
  SessionHttpHandler,
  SecureServerHttpInterface
} from './http-server-types.js';

// Note: HttpsServerOptions is exported directly from this file (not http-server-types.js)

/** Distinguishes handlers in per-handler warning keys. */
let handlerSequence = 0;

/** The experimental label, carried at runtime (spec D4; perverse P12 for its scope). */
const HTTP_EXPERIMENTAL_MESSAGE =
  'The mcp-secure-server HTTP transport is experimental in this release. It has no authentication, ' +
  'and session ids are bearer credentials. Layer 3 rate limits are shared by every client of a ' +
  'server, so one client can exhaust the budget for all. Not for untrusted multi-tenant use until 0.2.0.';

/**
 * Creates an HTTP request handler with security validation: one MCP session per client,
 * server-issued session ids, Origin validation, and session bounds (spec
 * http-transport-per-session v0.4.3). Supports POST (JSON-RPC), GET (the SSE stream) and
 * DELETE (end a session).
 *
 * Creating it **freezes the server's registrations** — register every tool, resource and
 * prompt first. Through 0.0.27 the handler shared one stateless SDK transport, which the
 * SDK refuses to reuse, so every request after the first answered 500 (issue 4bf30630).
 *
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Handler configuration options
 * @returns Request handler with `close()` and `sessionCount`
 *
 * @example
 * ```typescript
 * // server: new SecureMcpServer(info, { toolRegistry: [{ name: 'echo', sideEffects: 'none' }] })
 * server.tool('echo', { text: z.string() }, async ({ text }) => ({ content: [{ type: 'text', text }] }));
 * const handler = createSecureHttpHandler(server, { allowedOrigins: ['http://localhost:5173'] });
 * const httpServer = createServer(handler);
 * httpServer.listen(3000, '127.0.0.1');
 * // shutting down: close the sessions first, then the server
 * await handler.close();
 * httpServer.close();
 * ```
 */
export function createSecureHttpHandler(
  secureMcpServer: SecureServerHttpInterface,
  options: HttpHandlerOptions = {}
): SessionHttpHandler {
  const {
    maxBodySize = 51200,
    requestTimeout = 30000,
    sessionlessRequestsPerMinute = 60,
    sessionlessRequestsPerHour = 600
  } = options;
  if (typeof secureMcpServer._createSessionServer !== 'function') {
    throw new TypeError(
      'createSecureHttpHandler needs a server that can build one McpServer per session ' +
      '(_createSessionServer): a SecureMcpServer from mcp-secure-server 0.1.0 or later.'
    );
  }
  requirePositiveInteger('sessionlessRequestsPerMinute', sessionlessRequestsPerMinute);
  requirePositiveInteger('sessionlessRequestsPerHour', sessionlessRequestsPerHour);
  const originPolicy = createOriginPolicy(options.allowedOrigins, options.allowedHosts);
  const warnings = secureMcpServer._warnings ?? new WarningChannel();
  const handlerKey = String(++handlerSequence);
  const resolveClientIp = createClientIpResolver({
    trustProxy: options.trustProxy,
    // Keyed per kind: one handler can be misconfigured in more than one way (CGC-6, run #17).
    onWarning: (message, kind) => warnings.once(WARNING_CODES.TRUST_PROXY, message, `${WARNING_CODES.TRUST_PROXY}:${handlerKey}:${kind}`)
  });
  const logger = secureMcpServer._securityLogger;
  const semantics = secureMcpServer._validationPipeline.getLayerByClassName?.('SemanticsValidationLayer') as
    { releaseSession?(id: string): void } | undefined;
  const createSessionServer = secureMcpServer._createSessionServer.bind(secureMcpServer);
  const registries = secureMcpServer._httpRegistries;

  const registry: SessionRegistry = new SessionRegistry({
    createSessionServer,
    releaseSession: id => semantics?.releaseSession?.(id),
    refuse: (res, status, message, headers) => writeSecureResponse(res, status, { error: message }, headers),
    log: message => logger?.logInfo(message),
    sanitizeOutgoing: message =>
      (secureMcpServer._errorSanitizer?.sanitizeOutgoingError(message) as typeof message | null) ?? message,
    onClosed: () => { registries?.delete(registry); }
  }, {
    maxHttpSessions: options.maxHttpSessions,
    maxHttpSessionsPerClient: options.maxHttpSessionsPerClient,
    httpSessionIdleTtlMs: options.httpSessionIdleTtlMs
  });

  let exposureChecked = false;
  const flow = createSessionFlow({
    pipeline: secureMcpServer._validationPipeline,
    errorSanitizer: secureMcpServer._errorSanitizer,
    logger,
    createContext: fields => secureMcpServer._createPipelineContext(fields),
    registry,
    resolveClientIp,
    errorLockout: new ErrorRateLimiter(),
    // GET/DELETE have no body for the message pipeline to validate, so this per-key
    // windowed counter is their only per-client bound (D10). Same counter class as the
    // error lockout; here it counts requests, not errors.
    streamLimiter: new ErrorRateLimiter({ errorsPerMinute: sessionlessRequestsPerMinute, errorsPerHour: sessionlessRequestsPerHour }),
    responseLimiter: new ErrorRateLimiter({ errorsPerMinute: 600, errorsPerHour: 36_000 }),
    originPolicy,
    maxBodySize,
    requestTimeout,
    onRequest: req => {
      if (exposureChecked) return;
      exposureChecked = true;
      const address = boundAddress(req);
      if (address && !isLoopbackAddress(address)) {
        warnings.once(WARNING_CODES.HTTP_EXPOSED, exposureMessage(address), `${WARNING_CODES.HTTP_EXPOSED}:${handlerKey}`);
      }
    }
  });

  const handler = (async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      await flow(req, res);
    } catch (err) {
      logger?.logError(`HTTP ${req.method ?? '?'} request failed: ${err instanceof Error ? err.message : String(err)}`);
      if (!res.headersSent) writeSecureResponse(res, 500, { error: 'Internal server error' });
      else if (!res.writableEnded) res.end();
    }
  }) as SessionHttpHandler;
  Object.defineProperty(handler, 'close', { value: () => registry.close() });
  Object.defineProperty(handler, 'sessionCount', { get: () => registry.sessionCount });

  // Last, after every option has been validated, so a constructor that throws
  // leaves the server's registrations open (spec A, the freeze).
  registries?.add(registry);
  warnings.oncePerProcess(WARNING_CODES.HTTP_EXPERIMENTAL, HTTP_EXPERIMENTAL_MESSAGE);
  secureMcpServer._freezeRegistrations?.();
  return handler;
}

/**
 * A server whose `close()` closes the handler's sessions first. Node fires a server's
 * `close` event only after every connection has ended, and a GET stream whose client
 * stopped reading never ends by itself, so a `close`-event listener would wait forever.
 */
function closingSessionsFirst(server: Server, handler: SessionHttpHandler): Server {
  const close = server.close.bind(server);
  server.close = (callback?: (err?: Error) => void): Server => {
    void handler.close().finally(() => close(callback));
    return server;
  };
  return server;
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
 * // server: new SecureMcpServer(info, { toolRegistry: [{ name: 'echo', sideEffects: 'none' }] })
 * server.tool('echo', { text: z.string() }, async ({ text }) => ({ content: [{ type: 'text', text }] }));
 * const httpServer = createSecureHttpServer(server, { endpoint: '/mcp' }); // freezes registrations
 * // Loopback only: the transport has no authentication. Bind wider only behind authentication.
 * httpServer.listen(3000, '127.0.0.1');
 * ```
 */
export function createSecureHttpServer(
  secureMcpServer: SecureServerHttpInterface,
  options: HttpServerOptions = {}
): Server {
  const { endpoint = '/mcp', ...handlerOptions } = options;
  const handler = createSecureHttpHandler(secureMcpServer, handlerOptions);
  return closingSessionsFirst(
    createServer(createEndpointListener(handler, endpoint, handlerOptions.trustProxy, secureMcpServer._securityLogger)),
    handler
  );
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
 * httpsServer.listen(3443, '127.0.0.1');
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

  return closingSessionsFirst(
    createHttpsServer(tlsOptions, createEndpointListener(handler, endpoint, handlerOptions.trustProxy, secureMcpServer._securityLogger)),
    handler
  );
}
