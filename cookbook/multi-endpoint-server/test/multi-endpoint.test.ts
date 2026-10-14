import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { request, createServer } from 'node:http';
import type { Server, IncomingMessage, ServerResponse } from 'node:http';
import { createSecureHttpHandler } from 'mcp-secure-server';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createMultiEndpointApp, type MultiEndpointApp } from '../src/app.js';
import { createAdminServer, registerAdminTools } from '../src/servers/admin-server.js';

function parseSSE(data: string): unknown {
  const lines = data.split('\n');
  for (const line of lines) {
    if (line.startsWith('data: ')) {
      const jsonStr = line.slice(6);
      if (jsonStr.trim()) {
        return JSON.parse(jsonStr);
      }
    }
  }
  return JSON.parse(data);
}

/**
 * Since mcp-secure-server 0.1.0 every request other than `initialize` needs the session
 * id the server issued; a request without one is a 400 before the security pipeline.
 * The helper initializes once per endpoint and sends that id with every later request.
 */
const sessions = new Map<string, string>();

async function httpRequest(port: number, path: string, body: unknown): Promise<{ status: number; body: unknown }> {
  const key = `${port}${path}`;
  let sid = sessions.get(key);
  if (!sid) {
    const init = await postWithSession(port, path, {
      jsonrpc: '2.0', id: 0, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'cookbook-test', version: '1.0.0' } }
    });
    sid = init.sessionId;
    // The endpoint refused to start a session (wrong path, a policy): that refusal is the answer.
    if (init.status !== 200 || !sid) return init;
    sessions.set(key, sid);
  }
  return postWithSession(port, path, body, sid);
}

function postWithSession(
  port: number,
  path: string,
  body: unknown,
  sessionId?: string
): Promise<{ status: number; body: unknown; sessionId?: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: 'localhost',
      port,
      path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
        ...(sessionId ? { 'Mcp-Session-Id': sessionId } : {})
      }
    }, (res: IncomingMessage) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const contentType = res.headers['content-type'] || '';
          const parsed = contentType.includes('text/event-stream')
            ? parseSSE(data)
            : JSON.parse(data);
          resolve({
            status: res.statusCode ?? 500,
            body: parsed,
            sessionId: res.headers['mcp-session-id'] as string | undefined
          });
        } catch {
          resolve({ status: res.statusCode ?? 500, body: data, sessionId: res.headers['mcp-session-id'] as string | undefined });
        }
      });
    });

    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

const BROWSER_ORIGIN = 'http://localhost:5173';

/** Start the example's own app (routing, CORS wrapper and handlers) on an ephemeral loopback port. */
async function startApp(): Promise<{ app: MultiEndpointApp; port: number }> {
  const app = createMultiEndpointApp({ allowedOrigins: [BROWSER_ORIGIN] });
  await new Promise<void>((resolve) => app.listener.listen(0, '127.0.0.1', resolve));
  const addr = app.listener.address();
  return { app, port: typeof addr === 'object' && addr ? addr.port : 0 };
}

describe('Multi-Endpoint Server', () => {
  let app: MultiEndpointApp;
  let port: number;

  beforeEach(async () => {
    ({ app, port } = await startApp());
  });

  afterEach(async () => {
    sessions.clear();
    app.listener.closeAllConnections();
    await app.close();
  });

  describe('routing', () => {
    it('routes /api/admin to admin handler', async () => {
      const response = await httpRequest(port, '/api/admin', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'list-users', arguments: {} }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      expect(content).toBeDefined();
      const parsed = JSON.parse(content!);
      expect(parsed.users).toBeDefined();
      expect(Array.isArray(parsed.users)).toBe(true);
    });

    it('routes /api/public to public handler', async () => {
      const response = await httpRequest(port, '/api/public', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'health', arguments: {} }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      expect(content).toBeDefined();
      const parsed = JSON.parse(content!);
      expect(parsed.status).toBe('healthy');
    });

    it('returns 404 for unknown endpoint', async () => {
      const response = await httpRequest(port, '/api/unknown', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'health', arguments: {} }
      });

      expect(response.status).toBe(404);
    });
  });

  describe('admin API tools', () => {
    it('list-users returns paginated users', async () => {
      const response = await httpRequest(port, '/api/admin', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'list-users', arguments: { limit: 2, offset: 0 } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.users.length).toBe(2);
      expect(parsed.pagination.total).toBeGreaterThan(0);
    });

    it('list-users filters by role', async () => {
      const response = await httpRequest(port, '/api/admin', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'list-users', arguments: { role: 'admin' } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      parsed.users.forEach((user: { role: string }) => {
        expect(user.role).toBe('admin');
      });
    });

    it('system-stats returns basic stats', async () => {
      const response = await httpRequest(port, '/api/admin', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'system-stats', arguments: {} }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.stats.uptime).toBeDefined();
      expect(parsed.stats.nodeVersion).toBeDefined();
    });
  });

  describe('public API tools', () => {
    it('health returns healthy status', async () => {
      const response = await httpRequest(port, '/api/public', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'health', arguments: {} }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.status).toBe('healthy');
      expect(parsed.timestamp).toBeDefined();
    });

    it('status returns service info', async () => {
      const response = await httpRequest(port, '/api/public', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'status', arguments: {} }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.service).toBe('multi-endpoint-server');
      expect(parsed.version).toBe('1.0.0');
      expect(parsed.endpoints.admin).toBe('/api/admin');
      expect(parsed.endpoints.public).toBe('/api/public');
    });
  });

  describe('endpoint isolation', () => {
    it('admin tools not available on public endpoint', async () => {
      const response = await httpRequest(port, '/api/public', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'list-users', arguments: {} }
      });

      // Security framework returns 403 for tool not allowed violations
      expect(response.status).toBe(403);
      const result = response.body as { error?: { code?: number } };
      expect(result.error).toBeDefined();
    });

    it('public tools not available on admin endpoint', async () => {
      const response = await httpRequest(port, '/api/admin', {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'health', arguments: {} }
      });

      // Security framework returns 403 for tool not allowed violations
      expect(response.status).toBe(403);
      const result = response.body as { error?: { code?: number } };
      expect(result.error).toBeDefined();
    });
  });
});

describe('Multi-Endpoint Server with MCP SDK clients and browser origins', () => {
  let app: MultiEndpointApp;
  let port: number;

  beforeEach(async () => {
    ({ app, port } = await startApp());
  });

  afterEach(async () => {
    app.listener.closeAllConnections();
    await app.close();
  });

  const connect = async (path: string, name: string) => {
    const client = new Client({ name, version: '1.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}${path}`)));
    return client;
  };
  const resultOf = (r: unknown) => JSON.parse((r as { content: Array<{ text: string }> }).content[0]!.text);

  it('serves several clients on each endpoint at once, each in its own session', async () => {
    const [admin1, admin2, public1] = await Promise.all([
      connect('/api/admin', 'admin-1'), connect('/api/admin', 'admin-2'), connect('/api/public', 'public-1')
    ]);
    for (let round = 0; round < 2; round++) {
      const [u1, u2, h] = await Promise.all([
        admin1.callTool({ name: 'list-users', arguments: {} }),
        admin2.callTool({ name: 'system-stats', arguments: {} }),
        public1.callTool({ name: 'health', arguments: {} })
      ]);
      expect(Array.isArray(resultOf(u1).users)).toBe(true);
      expect(resultOf(u2)).toBeTypeOf('object');
      expect(resultOf(h).status).toBe('healthy');
    }
    expect(app.adminHandler.sessionCount).toBe(2);
    expect(app.publicHandler.sessionCount).toBe(1);
    await Promise.all([admin1.close(), admin2.close(), public1.close()]);
  });

  it('answers CORS for the listed origin and refuses an unlisted one with 403', async () => {
    const url = `http://127.0.0.1:${port}/api/public`;
    const initialize = JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize',
      params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'page', version: '1' } } });
    const post = (origin: string) => fetch(url, {
      method: 'POST',
      headers: { origin, 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
      body: initialize
    });

    const listed = await post(BROWSER_ORIGIN);
    expect(listed.status).toBe(200);
    expect(listed.headers.get('access-control-allow-origin')).toBe(BROWSER_ORIGIN);
    expect(listed.headers.get('access-control-expose-headers')).toContain('Mcp-Session-Id');
    await listed.body?.cancel();

    const unlisted = await post('https://evil.example');
    expect(unlisted.status).toBe(403);
    expect(unlisted.headers.get('access-control-allow-origin')).toBeNull();

    const preflight = await fetch(url, { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } });
    expect(preflight.status).toBe(403);
  });
});

/** Raw request helper for the reverse-proxy cases. */
function rawStatus(port: number, method: string, path: string, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method, headers }, (res: IncomingMessage) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 500));
    });
    req.on('error', reject);
    req.end();
  });
}

describe('Multi-Endpoint Server behind a reverse proxy (shared trustProxy)', () => {
  let httpServer: Server;
  let port: number;

  beforeEach(async () => {
    const trustProxy = ['loopback'];
    const adminServer = createAdminServer();
    registerAdminTools(adminServer);
    const adminHandler = createSecureHttpHandler(adminServer as Parameters<typeof createSecureHttpHandler>[0], { trustProxy });
    httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
      res.writeHead(404).end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it('keys each handler\'s limits on the proxy-appended client, not the spoofed entry', async () => {
    let status = 0;
    for (let i = 0; i < 100 && status !== 429; i++) {
      status = await rawStatus(port, 'PUT', '/api/admin', { 'X-Forwarded-For': `198.51.100.${i}, 203.0.113.1` });
    }
    expect(status).toBe(429);
    expect(await rawStatus(port, 'PUT', '/api/admin', { 'X-Forwarded-For': 'spoof, 203.0.113.2' })).toBe(405);
  });
});
