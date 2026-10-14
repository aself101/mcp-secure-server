/**
 * Build the example: a SecureMcpServer with its tools, a session HTTP handler, and a
 * listener with a CORS wrapper for browser clients (the MCP Inspector).
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { SecureMcpServer, createSecureHttpHandler, type SessionHttpHandler } from 'mcp-secure-server';
import { registerTools, TOOL_NAMES } from './tools.js';

export interface ExampleOptions {
  /** Exact browser origins allowed (the Inspector's UI is http://localhost:6274). */
  allowedOrigins?: string[];
  securityLevel?: 'basic' | 'standard' | 'paranoid';
  httpSessionIdleTtlMs?: number;
  maxHttpSessionsPerClient?: number;
  /** Where warnings go; default: console.warn with the code. */
  onWarning?: (message: string, code: string) => void;
  /** Log one line per request (method, session prefix, JSON-RPC method, status). */
  logRequest?: (line: string) => void;
}

export interface Example { server: SecureMcpServer; handler: SessionHttpHandler; listener: Server }

export function createExample(options: ExampleOptions = {}): Example {
  const allowedOrigins = options.allowedOrigins ?? ['http://localhost:6274'];
  const server = new SecureMcpServer({ name: 'http-session-server', version: '1.0.0' }, {
    securityLevel: options.securityLevel ?? 'standard',
    capabilities: { logging: {} },
    toolRegistry: TOOL_NAMES.map(name => ({ name, sideEffects: 'none' as const })),
    onWarning: options.onWarning ?? ((message, code) => console.warn(`[${code}] ${message}`))
  });
  registerTools(server); // before the handler: creating it freezes registrations

  const handler = createSecureHttpHandler(server, {
    allowedOrigins,
    httpSessionIdleTtlMs: options.httpSessionIdleTtlMs,
    maxHttpSessionsPerClient: options.maxHttpSessionsPerClient
  });

  // CORS for browser clients: echo the request's Origin only when it is listed (never '*',
  // never 'null'), and answer preflights before the handler. This wrapper never deletes or
  // rewrites Origin: the handler validates it, and a wrapper that strips it turns that check
  // off for every page on the machine.
  const listed = new Set(allowedOrigins);
  const listener = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    if (options.logRequest) {
      const started = Date.now();
      const sid = req.headers['mcp-session-id'];
      res.on('close', () => options.logRequest!(
        `${req.method} ${sid ? String(sid).slice(0, 8) : '--------'} -> ${res.statusCode}` +
        `${res.getHeader('mcp-session-id') ? ` new ${String(res.getHeader('mcp-session-id')).slice(0, 8)}` : ''} (${Date.now() - started} ms)`));
    }
    const origin = req.headers.origin;
    if (origin && listed.has(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID');
      res.setHeader('Access-Control-Expose-Headers', 'Mcp-Session-Id');
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(origin && listed.has(origin) ? 204 : 403).end();
      return;
    }
    if (new URL(req.url ?? '/', 'http://localhost').pathname !== '/mcp') {
      res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'Not found' }));
      return;
    }
    await handler(req, res);
  });

  return { server, handler, listener };
}
