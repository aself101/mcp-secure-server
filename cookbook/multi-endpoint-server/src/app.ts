/**
 * Build the multi-endpoint example: two SecureMcpServers with different tools and policies,
 * one session handler each, composed behind one listener with custom routing and a CORS
 * wrapper for browser clients.
 *
 * - /api/admin - Admin API with user management and system stats
 * - /api/public - Public API with health and status checks
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createSecureHttpHandler, type SessionHttpHandler } from 'mcp-secure-server';
import { createAdminServer, registerAdminTools } from './servers/admin-server.js';
import { createPublicServer, registerPublicTools } from './servers/public-server.js';

export interface MultiEndpointOptions {
  /** Exact browser origins allowed on both endpoints (scheme://host[:port]). Default: none. */
  allowedOrigins?: string[];
}

export interface MultiEndpointApp {
  listener: Server;
  adminHandler: SessionHttpHandler;
  publicHandler: SessionHttpHandler;
  /** Close every session on both endpoints, then the listener. */
  close(): Promise<void>;
}

export function createMultiEndpointApp(options: MultiEndpointOptions = {}): MultiEndpointApp {
  const allowedOrigins = options.allowedOrigins ?? [];

  const adminServer = createAdminServer();
  const publicServer = createPublicServer();
  // Register first: creating a handler freezes the server's registrations.
  registerAdminTools(adminServer);
  registerPublicTools(publicServer);

  // The same origin list goes to the handlers (which refuse unlisted origins with 403)
  // and to the CORS wrapper (which tells browsers which origins may read responses).
  const adminHandler = createSecureHttpHandler(adminServer, { allowedOrigins });
  const publicHandler = createSecureHttpHandler(publicServer, { allowedOrigins });

  // CORS: echo the request's Origin only when it is listed — never '*', never 'null' — and
  // answer preflights before the handlers. This wrapper never deletes or rewrites Origin: the
  // handlers validate it, and a wrapper that strips it turns that check off for every page on
  // the machine. A client with an opaque origin (a file:// page, a sandboxed frame) sends
  // Origin: null, which cannot be listed; connect from a context that sends no Origin
  // (Electron's main process, a server) or from a listed origin.
  const listed = new Set(allowedOrigins);
  const listener = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const origin = req.headers.origin;
    const isListed = origin !== undefined && listed.has(origin);
    if (isListed) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID');
      res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(isListed ? 204 : 403).end();
      return;
    }

    if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
    if (req.url?.startsWith('/api/public')) return publicHandler(req, res);

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: 'Not found',
      message: 'Use one of the available endpoints',
      endpoints: { admin: '/api/admin', public: '/api/public' }
    }));
  });

  const close = async () => {
    await Promise.all([adminHandler.close(), publicHandler.close()]);
    await new Promise<void>((resolve) => listener.close(() => resolve()));
  };

  return { listener, adminHandler, publicHandler, close };
}
