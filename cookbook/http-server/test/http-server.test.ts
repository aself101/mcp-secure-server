import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { request } from 'node:http';
import type { Server, IncomingMessage } from 'node:http';
import { SecureMcpServer } from 'mcp-secure-server';
import { calculatorSchema, calculatorHandler } from '../src/tools/calculator.js';
import { echoSchema, echoHandler } from '../src/tools/echo.js';

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

function httpRequest(
  port: number,
  body: unknown
): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: 'localhost',
      port,
      path: '/mcp',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream'
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
            body: parsed
          });
        } catch {
          resolve({ status: res.statusCode ?? 500, body: data });
        }
      });
    });

    req.on('error', reject);
    req.write(JSON.stringify(body));
    req.end();
  });
}

describe('HTTP Server Example', () => {
  let server: SecureMcpServer;
  let httpServer: Server;
  let port: number;

  beforeEach(async () => {
    server = new SecureMcpServer(
      { name: 'test-http-server', version: '1.0.0' },
      {
        enableLogging: false,
        toolRegistry: [
          { name: 'calculator', sideEffects: 'none', quotaPerMinute: 60 },
          { name: 'echo', sideEffects: 'none', quotaPerMinute: 60 }
        ]
      }
    );

    server.tool('calculator', 'Perform arithmetic', calculatorSchema.shape, calculatorHandler);
    server.tool('echo', 'Echo back input', echoSchema.shape, echoHandler);

    httpServer = server.createHttpServer({ endpoint: '/mcp' });

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

  describe('calculator tool', () => {
    it('performs addition', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'calculator', arguments: { operation: 'add', a: 5, b: 3 } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      expect(content).toBeDefined();
      const parsed = JSON.parse(content!);
      expect(parsed.result).toBe(8);
      expect(parsed.expression).toBe('5 + 3 = 8');
    });

    it('performs division', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 2,
        params: { name: 'calculator', arguments: { operation: 'divide', a: 10, b: 2 } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.result).toBe(5);
    });

    it('handles division by zero', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 3,
        params: { name: 'calculator', arguments: { operation: 'divide', a: 10, b: 0 } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }>, isError?: boolean } };
      expect(result?.result?.isError).toBe(true);
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.error).toBe('Division by zero');
    });
  });

  describe('echo tool', () => {
    it('echoes message back', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 4,
        params: { name: 'echo', arguments: { message: 'Hello, World!' } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.original).toBe('Hello, World!');
      expect(parsed.processed).toBe('Hello, World!');
    });

    it('applies uppercase transform', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 5,
        params: { name: 'echo', arguments: { message: 'hello', uppercase: true } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.processed).toBe('HELLO');
    });

    it('applies reverse transform', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 6,
        params: { name: 'echo', arguments: { message: 'hello', reverse: true } }
      });

      expect(response.status).toBe(200);
      const result = response.body as { result?: { content?: Array<{ text?: string }> } };
      const content = result?.result?.content?.[0]?.text;
      const parsed = JSON.parse(content!);
      expect(parsed.processed).toBe('olleh');
    });
  });

  describe('security validation', () => {
    it('blocks path traversal in arguments', async () => {
      const response = await httpRequest(port, {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 7,
        params: { name: 'echo', arguments: { message: '../../../etc/passwd' } }
      });

      expect(response.status).toBe(400);
      const body = response.body as { error?: { code?: number } };
      expect(body.error?.code).toBe(-32602);
    });

    it('returns 404 for wrong endpoint', async () => {
      const response = await new Promise<{ status: number; body: unknown }>((resolve, reject) => {
        const req = request({
          hostname: 'localhost',
          port,
          path: '/wrong',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' }
        }, (res: IncomingMessage) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            resolve({ status: res.statusCode ?? 500, body: JSON.parse(data) });
          });
        });
        req.on('error', reject);
        req.write(JSON.stringify({}));
        req.end();
      });

      expect(response.status).toBe(404);
    });
  });
});

/** Raw request helper for the reverse-proxy cases: returns status and the rate-limit scope header. */
function rawRequest(
  port: number,
  method: string,
  headers: Record<string, string>,
  path = '/mcp'
): Promise<{ status: number; scope: string | undefined }> {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, path, method, headers }, (res: IncomingMessage) => {
      res.resume();
      res.on('end', () => resolve({
        status: res.statusCode ?? 500,
        scope: res.headers['x-ratelimit-scope'] as string | undefined
      }));
    });
    req.on('error', reject);
    req.end();
  });
}

/** Sends bad-method requests as `client` (via a proxy-appended X-Forwarded-For) until locked out. */
async function lockOut(port: number, xffFor: (i: number) => string): Promise<{ status: number; scope: string | undefined }> {
  for (let i = 0; i < 100; i++) {
    const res = await rawRequest(port, 'PUT', { 'X-Forwarded-For': xffFor(i) });
    if (res.status === 429) return res;
  }
  throw new Error('never rate limited');
}

describe('HTTP Server Example behind a reverse proxy (trustProxy)', () => {
  let httpServer: Server;
  let port: number;

  const listen = async (trustProxy?: string[]) => {
    const server = new SecureMcpServer({ name: 'http-proxy-test', version: '1.0.0' }, { enableLogging: false });
    httpServer = server.createHttpServer({ endpoint: '/mcp', ...(trustProxy ? { trustProxy } : {}) });
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
  };

  afterEach(async () => {
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it('with trustProxy, clients behind the proxy are limited separately', async () => {
    await listen(['loopback']);
    const limited = await lockOut(port, (i) => `198.51.100.${i}, 203.0.113.1`);
    expect(limited.scope).toBe('errors');
    const other = await rawRequest(port, 'PUT', { 'X-Forwarded-For': 'spoof, 203.0.113.2' });
    expect(other.status).toBe(405);
  });

  it('without trustProxy, a rotating X-Forwarded-For cannot dodge the lockout', async () => {
    await listen();
    const limited = await lockOut(port, (i) => `198.51.100.${i}`);
    expect(limited.status).toBe(429);
    const next = await rawRequest(port, 'PUT', { 'X-Forwarded-For': '203.0.113.99' });
    expect(next.status).toBe(429);
  });
});
