/**
 * Type definitions for HTTP server transport.
 * @module http-server-types
 */

import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ValidationPipeline } from '../utils/validation-pipeline.js';
import type { ErrorSanitizer } from '../utils/error-sanitizer.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import type { PipelineContext } from '../utils/validation-pipeline.js';
import type { TrustProxy } from './client-ip.js';
import type { WarningChannel } from '../warnings.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/** Options for createSecureHttpHandler (no routing) */
export interface HttpHandlerOptions {
  /** Maximum request body size in bytes (default: 51200 = 50KB) */
  maxBodySize?: number;
  /** Request body parse timeout in milliseconds (default: 30000 = 30s) */
  requestTimeout?: number;
  /**
   * Per-client ceiling on GET (SSE stream) and DELETE (session end) requests on
   * known sessions, per minute (default: 60). These methods carry no JSON-RPC
   * body, so the 5-layer message pipeline cannot run on them; this is the only
   * per-client bound on that path. The name predates sessions: it meters GET
   * and DELETE. A request without a session header is a 400 charged to the
   * error lockout instead, and an unknown session id a 404 (never metered).
   */
  sessionlessRequestsPerMinute?: number;
  /** Per-client ceiling on GET/DELETE requests per hour (default: 600). */
  sessionlessRequestsPerHour?: number;
  /**
   * Exact `Origin` values a browser client may send, in serialized form
   * (`scheme://host[:port]`, lowercase, no path, no trailing slash, no default
   * port). A request whose `Origin` is not listed gets 403; one without `Origin`
   * (non-browser clients) is allowed. Default `[]`. `"null"` cannot be listed.
   * Electron renderers, browser extensions and webviews send `Origin` and must be
   * listed. A wrapper in front of the handler must never delete or rewrite
   * `Origin`: the handler cannot see it, and the check is then off for every page.
   */
  allowedOrigins?: string[];
  /**
   * Exact `Host` values accepted (default: no Host check). Defence in depth
   * against DNS rebinding where a proxy strips `Origin`; it does not restrict
   * non-browser clients, which can send any Host. `[]` throws.
   */
  allowedHosts?: string[];
  /** Reserved + live MCP sessions on this handler (default 1000). */
  maxHttpSessions?: number;
  /**
   * Reserved + live MCP sessions per client key (default 10). Many users behind
   * one proxy or NAT share one key: list the proxy in `trustProxy` rather than
   * raising this, which removes the per-client bound.
   */
  maxHttpSessionsPerClient?: number;
  /** A session with no request in flight is closed after this long (default 30 min). */
  httpSessionIdleTtlMs?: number;
  /**
   * Which forwarding hops to trust when resolving the rate-limit key every
   * per-client-IP limit keys on (default: 0 = none).
   * - 0: the socket peer; X-Forwarded-For and X-Real-IP are ignored.
   * - N: the Nth X-Forwarded-For entry from the right. Correct only if every
   *   request passes through exactly N proxies that APPEND to X-Forwarded-For.
   * - string[]: your proxies' addresses / CIDRs (or 'loopback' | 'linklocal' |
   *   'uniquelocal'). The client is the first untrusted address walking right to
   *   left from the socket peer; a request from an UNLISTED address is keyed on
   *   its own address. Every listed address is treated as a proxy, so list only
   *   your proxies — named ranges also trust any client inside them. Prefer
   *   this form whenever the proxy addresses are known.
   * Invalid values throw TypeError here. See `createClientIpResolver`.
   */
  trustProxy?: TrustProxy;
}

/** Options for createSecureHttpServer (includes routing) */
export interface HttpServerOptions extends HttpHandlerOptions {
  /** MCP endpoint path (default: '/mcp') */
  endpoint?: string;
}

/** Request handler function type */
export type SecureHttpHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;

/** The handler `createSecureHttpHandler` returns: a request handler with session lifecycle. */
export interface SessionHttpHandler extends SecureHttpHandler {
  /**
   * Close every session (a GET whose client stopped reading is destroyed after 5 s) and
   * refuse new ones. Call it before `server.close()` when building your own server; the
   * package's server factories do it for you. The server's registrations stay frozen: a
   * handler, once attached, freezes them for good, closed or not.
   */
  close(): Promise<void>;
  /** Reserved + live sessions. */
  readonly sessionCount: number;
}

/** What a server needs from an attached HTTP session registry. */
export interface HttpSessionRegistryHandle {
  close(): Promise<void>;
  /** The McpServer of a live session, or undefined. */
  sessionServer(id: string): McpServer | undefined;
}

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
  /**
   * Builds the pipeline context from server options (policy, logger, verbose)
   * plus the given transport-specific fields. The single writer of that
   * structure — see SecureMcpServer._createPipelineContext.
   */
  _createPipelineContext(transportFields: Record<string, unknown>): PipelineContext;
  /**
   * The server's warning channel (D18). Optional so a custom implementation still
   * type-checks; without it the handler warns through `process.emitWarning`.
   */
  readonly _warnings?: WarningChannel;
  /**
   * Freeze the server's registrations. Called as the last step of a successful
   * handler construction; optional for custom implementations.
   */
  _freezeRegistrations?(): void;
  /** A fresh McpServer carrying the frozen registration set, one per HTTP session. */
  _createSessionServer?(): McpServer;
  /** HTTP session registries attached to the server; `shutdown()` closes them. */
  readonly _httpRegistries?: Set<HttpSessionRegistryHandle>;
}
