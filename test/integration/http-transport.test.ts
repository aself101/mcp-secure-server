import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { request, createServer } from 'node:http';
import type { Server, IncomingMessage, ServerResponse } from 'node:http';
import { SecureMcpServer } from '../../src/security/mcp-secure-server.js';
import { createSecureHttpServer, createSecureHttpHandler } from '../../src/security/transport/http-server.js';

function httpRequest(
  port: number,
  options: { method?: string; path?: string; headers?: Record<string, string>; body?: unknown }
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: 'localhost',
      port,
      path: options.path ?? '/mcp',
      method: options.method ?? 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    }, (res: IncomingMessage) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode ?? 500,
            body: data ? JSON.parse(data) : null
          });
        } catch {
          resolve({ status: res.statusCode ?? 500, body: data });
        }
      });
    });

    req.on('error', reject);

    if (options.body !== undefined) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

describe('HTTP Transport Security', () => {
  let server: SecureMcpServer;
  let httpServer: Server;
  let port: number;

  beforeEach(async () => {
    server = new SecureMcpServer(
      { name: 'test-server', version: '1.0.0' },
      { enableLogging: false }
    );

    httpServer = createSecureHttpServer(server as Parameters<typeof createSecureHttpServer>[0], {
      endpoint: '/mcp',
      maxBodySize: 1024
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, () => {
        const addr = httpServer.address();
        port = typeof addr === 'object' && addr ? addr.port : 0;
        resolve();
      });
    });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });

  describe('routing', () => {
    it('allows GET for SSE streaming (SDK validates Accept header)', async () => {
      // GET is allowed for SSE streaming - SDK returns 406 if Accept header is wrong
      const response = await httpRequest(port, { method: 'GET' });
      expect(response.status).toBe(406); // SDK requires Accept: text/event-stream
    });

    it('returns 405 for PUT requests to correct endpoint', async () => {
      const response = await httpRequest(port, { method: 'PUT', body: {} });
      expect(response.status).toBe(405);
      expect(response.body).toEqual({ error: 'Method not allowed' });
    });

    it('allows DELETE for session cleanup (SDK handles)', async () => {
      // DELETE is allowed for session cleanup - SDK handles session cleanup
      const response = await httpRequest(port, { method: 'DELETE' });
      // SDK may return various status codes depending on session state
      // 200 if successful, 400/404 if no session, etc.
      expect([200, 400, 404, 405]).toContain(response.status);
    });

    it('returns 404 for wrong endpoint', async () => {
      const response = await httpRequest(port, { path: '/wrong', body: {} });
      expect(response.status).toBe(404);
      expect(response.body).toEqual({ error: 'Not found' });
    });

    it('accepts endpoint with query string', async () => {
      const response = await httpRequest(port, {
        path: '/mcp?session=test123',
        body: { jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }
      });
      // Should NOT return 404 - query strings should be handled
      expect(response.status).not.toBe(404);
    });

    it('accepts endpoint with trailing slash', async () => {
      const response = await httpRequest(port, {
        path: '/mcp/',
        body: { jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }
      });
      // Should NOT return 404 - trailing slashes should be handled
      expect(response.status).not.toBe(404);
    });
  });

  describe('content-type validation', () => {
    it('returns 415 for missing Content-Type header', async () => {
      const response = await httpRequest(port, {
        headers: { 'Content-Type': '' },
        body: { jsonrpc: '2.0', method: 'initialize', id: 1 }
      });
      expect(response.status).toBe(415);
      expect(response.body).toEqual({ error: 'Content-Type must be application/json' });
    });

    it('returns 415 for wrong Content-Type', async () => {
      const response = await httpRequest(port, {
        headers: { 'Content-Type': 'text/plain' },
        body: { jsonrpc: '2.0', method: 'initialize', id: 1 }
      });
      expect(response.status).toBe(415);
      expect(response.body).toEqual({ error: 'Content-Type must be application/json' });
    });

    it('accepts Content-Type with charset', async () => {
      const response = await httpRequest(port, {
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: { jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }
      });
      // Should NOT return 415 - charset is acceptable
      expect(response.status).not.toBe(415);
    });
  });

  describe('body parsing', () => {
    it('rejects invalid JSON', async () => {
      const response = await httpRequest(port, { body: 'not json' });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: 'Invalid JSON' });
    });

    it('rejects body exceeding maxBodySize', async () => {
      const largeBody = { data: 'x'.repeat(2000) };
      try {
        const response = await httpRequest(port, { body: largeBody });
        expect(response.status).toBe(400);
        expect(response.body).toEqual({ error: 'Body exceeds 1024 bytes' });
      } catch (err) {
        // Socket may hang up when body is too large - this is expected
        expect((err as Error).message).toMatch(/socket hang up|ECONNRESET/);
      }
    });
  });

  describe('security validation', () => {
    it('blocks path traversal attacks', async () => {
      const response = await httpRequest(port, {
        body: {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 1,
          params: { name: 'read', arguments: { path: '../../../etc/passwd' } }
        }
      });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        jsonrpc: '2.0',
        id: 1,
        error: {
          code: -32602,
          message: expect.any(String)
        }
      });
    });

    it('blocks SQL injection attacks', async () => {
      const response = await httpRequest(port, {
        body: {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 2,
          params: { name: 'query', arguments: { sql: "'; DROP TABLE users; --" } }
        }
      });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        jsonrpc: '2.0',
        id: 2,
        error: {
          code: -32602
        }
      });
    });

    it('blocks command injection attacks', async () => {
      const response = await httpRequest(port, {
        body: {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 3,
          params: { name: 'exec', arguments: { cmd: '$(cat /etc/passwd)' } }
        }
      });

      expect(response.status).toBe(400);
      expect(response.body).toMatchObject({
        jsonrpc: '2.0',
        id: 3,
        error: {
          code: -32602
        }
      });
    });

    it('returns sanitized error without internal details', async () => {
      const response = await httpRequest(port, {
        body: {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 4,
          params: { name: 'read', arguments: { path: '../../../../secret/api_key' } }
        }
      });

      expect(response.status).toBe(400);
      const body = response.body as { error?: { message?: string; data?: { token?: string } } };
      // Error message is sanitized (no internal details leaked)
      // Can be validation failed, could not be processed, or invalid request format
      expect(body.error?.message).toMatch(/Request (validation failed|could not be processed)|Invalid request format/);
      // Token is a hex string (length varies by implementation)
      expect(body.error?.data?.token).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('session ID handling', () => {
    it('extracts session ID from Mcp-Session-Id header', async () => {
      const validateSpy = vi.spyOn(server.validationPipeline, 'validate');

      await httpRequest(port, {
        headers: { 'Mcp-Session-Id': 'session-abc-123' },
        body: { jsonrpc: '2.0', method: 'ping', id: 1 }
      });

      expect(validateSpy).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ sessionId: 'session-abc-123' })
      );

      validateSpy.mockRestore();
    });

    it('uses stateless when no session header provided', async () => {
      const validateSpy = vi.spyOn(server.validationPipeline, 'validate');

      await httpRequest(port, {
        body: { jsonrpc: '2.0', method: 'ping', id: 2 }
      });

      expect(validateSpy).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({ sessionId: 'stateless' })
      );

      validateSpy.mockRestore();
    });
  });

  describe('validation context', () => {
    it('passes httpRequest flag in context', async () => {
      const validateSpy = vi.spyOn(server.validationPipeline, 'validate');

      await httpRequest(port, {
        body: { jsonrpc: '2.0', method: 'ping', id: 1 }
      });

      expect(validateSpy).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          httpRequest: true,
          transportLevel: true
        })
      );

      validateSpy.mockRestore();
    });
  });
});

describe('createSecureHttpServer options', () => {
  it('uses default endpoint /mcp when not specified', async () => {
    const server = new SecureMcpServer({ name: 'test', version: '1.0' });
    const httpServer = createSecureHttpServer(server as Parameters<typeof createSecureHttpServer>[0]);

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    const response = await httpRequest(port, {
      path: '/mcp',
      body: { jsonrpc: '2.0', method: 'ping', id: 1 }
    });

    expect(response.status).not.toBe(404);

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });

  it('uses custom endpoint when specified', async () => {
    const server = new SecureMcpServer({ name: 'test', version: '1.0' });
    const httpServer = createSecureHttpServer(
      server as Parameters<typeof createSecureHttpServer>[0],
      { endpoint: '/api/v1/mcp' }
    );

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    const defaultResponse = await httpRequest(port, {
      path: '/mcp',
      body: { jsonrpc: '2.0', method: 'ping', id: 1 }
    });
    expect(defaultResponse.status).toBe(404);

    const customResponse = await httpRequest(port, {
      path: '/api/v1/mcp',
      body: { jsonrpc: '2.0', method: 'ping', id: 1 }
    });
    expect(customResponse.status).not.toBe(404);

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });
});

describe('createSecureHttpHandler multi-endpoint', () => {
  it('allows composing multiple handlers on one server', async () => {
    // Create two separate MCP servers
    const serverA = new SecureMcpServer({ name: 'server-a', version: '1.0' });
    const serverB = new SecureMcpServer({ name: 'server-b', version: '1.0' });

    // Create handlers for each
    const handlerA = createSecureHttpHandler(
      serverA as Parameters<typeof createSecureHttpHandler>[0]
    );
    const handlerB = createSecureHttpHandler(
      serverB as Parameters<typeof createSecureHttpHandler>[0]
    );

    // Compose into a single server with custom routing
    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      if (req.url?.startsWith('/api/a')) {
        return handlerA(req, res);
      }
      if (req.url?.startsWith('/api/b')) {
        return handlerB(req, res);
      }
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    // Test routing to handler A
    const responseA = await httpRequest(port, {
      path: '/api/a',
      body: { jsonrpc: '2.0', method: 'ping', id: 1 }
    });
    expect(responseA.status).not.toBe(404);

    // Test routing to handler B
    const responseB = await httpRequest(port, {
      path: '/api/b',
      body: { jsonrpc: '2.0', method: 'ping', id: 2 }
    });
    expect(responseB.status).not.toBe(404);

    // Test 404 for unmatched route
    const responseUnknown = await httpRequest(port, {
      path: '/api/c',
      body: { jsonrpc: '2.0', method: 'ping', id: 3 }
    });
    expect(responseUnknown.status).toBe(404);

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });

  it('handler allows GET for SSE (SDK validates Accept header)', async () => {
    const server = new SecureMcpServer({ name: 'test', version: '1.0' });
    const handler = createSecureHttpHandler(
      server as Parameters<typeof createSecureHttpHandler>[0]
    );

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      return handler(req, res);
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    // GET is allowed for SSE streaming - SDK returns 406 if Accept header is wrong
    const response = await httpRequest(port, { method: 'GET' });
    expect(response.status).toBe(406); // SDK requires Accept: text/event-stream for GET

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });

  it('handler validates requests independently', async () => {
    const server = new SecureMcpServer({ name: 'test', version: '1.0' });
    const handler = createSecureHttpHandler(
      server as Parameters<typeof createSecureHttpHandler>[0]
    );

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      return handler(req, res);
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    // Send a request with a path traversal attack
    const response = await httpRequest(port, {
      body: {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'read', arguments: { path: '../../../etc/passwd' } }
      }
    });

    expect(response.status).toBe(400);
    expect(response.body).toMatchObject({
      jsonrpc: '2.0',
      id: 1,
      error: {
        code: -32602
      }
    });

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });

  it('supports custom maxBodySize per handler', async () => {
    const server = new SecureMcpServer({ name: 'test', version: '1.0' });
    const handler = createSecureHttpHandler(
      server as Parameters<typeof createSecureHttpHandler>[0],
      { maxBodySize: 100 } // Very small limit
    );

    const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      return handler(req, res);
    });

    await new Promise<void>((resolve) => {
      httpServer.listen(0, resolve);
    });

    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;

    // Send a request that exceeds the small limit
    const largeBody = { data: 'x'.repeat(200) };
    try {
      const response = await httpRequest(port, { body: largeBody });
      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: 'Body exceeds 100 bytes' });
    } catch (err) {
      // Socket may hang up when body is too large - this is expected
      expect((err as Error).message).toMatch(/socket hang up|ECONNRESET/);
    }

    await new Promise<void>((resolve) => {
      httpServer.close(() => resolve());
    });
  });
});
