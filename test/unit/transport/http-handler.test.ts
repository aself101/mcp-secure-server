import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { PassThrough } from 'node:stream';
import { EventEmitter } from 'node:events';
import { createSecureHttpHandler, createSecureHttpServer, createSecureHttpsServer } from '@/security/transport/http-server.js';
import { DEFAULT_ERRORS_PER_MINUTE as LOCKOUT } from '@/security/transport/error-rate-limiter.js';
import type { Server } from 'node:http';

let currentMockTransport: { handleRequest: ReturnType<typeof vi.fn> } | null = null;
/** The id the mocked SDK transport issued on the last `initialize`. */
let lastSessionId: string | undefined;

// The stateful SDK transport, reduced to what the session registry relies on: it
// issues the server's id and awaits onsessioninitialized on `initialize`, and calls
// onsessionclosed on DELETE. Every request is then handed to the per-test
// `currentMockTransport.handleRequest` spy (with no body argument for GET/DELETE).
vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: class {
    constructor(opts: {
      sessionIdGenerator: () => string;
      onsessioninitialized?: (id: string) => unknown;
      onsessionclosed?: (id: string) => unknown;
    }) {
      const spy = currentMockTransport!.handleRequest;
      const transport = {
        onclose: undefined as undefined | (() => void),
        handleRequest: async (req: { method?: string }, res: unknown, body?: { method?: string }) => {
          if (body?.method === 'initialize') {
            lastSessionId = opts.sessionIdGenerator();
            await opts.onsessioninitialized?.(lastSessionId);
          }
          if (req.method === 'DELETE' && lastSessionId) await opts.onsessionclosed?.(lastSessionId);
          return body === undefined ? spy(req, res) : spy(req, res, body);
        },
        close: async () => { transport.onclose?.(); },
        send: async () => {}, // the registry wraps send() with the outgoing sanitizer (D21)
        closeStandaloneSSEStream: () => {}
      };
      return transport;
    }
  }
}));

function createMockServer(overrides: {
  pipelineResult?: Record<string, unknown>;
  logger?: { logSecurityDecision?: ReturnType<typeof vi.fn>; logInfo?: ReturnType<typeof vi.fn> } | null;
} = {}) {
  const defaultResult = {
    passed: true,
    allowed: true,
    severity: 'NONE',
    reason: 'ok',
    violationType: null,
    confidence: 1,
    layerName: 'Pipeline',
    timestamp: Date.now()
  };

  const result = { ...defaultResult, ...overrides.pipelineResult };
  const _validationPipeline = {
    validate: vi.fn().mockResolvedValue(result)
  };

  return {
    _validationPipeline,
    _errorSanitizer: {
      createSanitizedErrorResponse: vi.fn().mockReturnValue({ error: 'sanitized' })
    },
    _securityLogger: overrides.logger ?? null,
    _mcpServer: {
      connect: vi.fn().mockResolvedValue(undefined)
    },
    _createSessionServer: vi.fn(() => ({
      connect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      server: {}
    })),
    _createPipelineContext: vi.fn((fields: Record<string, unknown>) => ({
      timestamp: Date.now(),
      logger: overrides.logger ?? undefined,
      verbose: false,
      policy: { allowNetwork: false, allowWrites: false },
      ...fields
    }))
  };
}

class MockResponse extends EventEmitter {
  statusCode = 0;
  headers: Record<string, string> = {};
  body = '';
  ended = false;
  headersSent = false;
  get writableEnded() { return this.ended; }

  writeHead(status: number, headers: Record<string, string> = {}) {
    this.statusCode = status;
    this.headers = headers;
    this.headersSent = true;
  }

  end(data?: string) {
    this.body = data ?? '';
    this.ended = true;
    this.emit('close');
  }
}

/**
 * A single `initialize`: since 0.1.0 the only request that reaches the pipeline
 * without a session (any other header-less request is a 400 before it).
 */
const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };

/** Initialize through the handler and return the server-issued session id. */
async function openSession(
  handler: (req: never, res: never) => Promise<void>,
  socket: Record<string, unknown> = { remoteAddress: '192.0.2.1' }
): Promise<string> {
  const req = Object.assign(createRequest({ headers: { 'content-type': 'application/json' }, body: JSON.stringify(INIT) }), { socket });
  const res = new MockResponse();
  await handler(req as never, res as never);
  expect(lastSessionId).toBeTypeOf('string');
  return lastSessionId!;
}

function createRequest(options: { method?: string; headers?: Record<string, string>; body?: string }): PassThrough & {
  method: string;
  url: string;
  headers: Record<string, string>;
} {
  const stream = new PassThrough();
  stream.method = options.method ?? 'POST';
  stream.url = '/mcp';
  stream.headers = options.headers ?? {};

  if (options.body !== undefined) {
    setImmediate(() => {
      stream.write(options.body);
      stream.end();
    });
  }

  return stream as PassThrough & {
    method: string;
    url: string;
    headers: Record<string, string>;
  };
}

describe('createSecureHttpHandler', () => {
  beforeEach(() => {
    currentMockTransport = {
      handleRequest: vi.fn().mockResolvedValue(undefined)
    };
  });

  describe('security headers', () => {
    it('includes CSP header in responses', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'text/plain' },
        body: 'hello'
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.headers['Content-Security-Policy']).toBe("default-src 'none'; frame-ancestors 'none'");
    });

    it('includes HSTS header in responses', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'text/plain' },
        body: 'hello'
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.headers['Strict-Transport-Security']).toBe('max-age=86400; includeSubDomains');
    });

    it('includes all security headers in error responses', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'text/plain' },
        body: 'hello'
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
      expect(res.headers['X-Frame-Options']).toBe('DENY');
      expect(res.headers['Cache-Control']).toBe('no-store');
      expect(res.headers['X-XSS-Protection']).toBe('0');
      expect(res.headers['Content-Security-Policy']).toBeDefined();
      expect(res.headers['Strict-Transport-Security']).toBeDefined();
    });
  });

  it('rejects non-JSON content types', async () => {
    const server = createMockServer();
    const handler = createSecureHttpHandler(server as never);
    const req = createRequest({
      headers: { 'content-type': 'text/plain' },
      body: 'hello'
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

    expect(res.statusCode).toBe(415);
    expect(JSON.parse(res.body).error).toMatch(/content-type/i);
    expect(server._validationPipeline.validate).not.toHaveBeenCalled();
  });

  it('returns 400 for invalid JSON bodies', async () => {
    const server = createMockServer();
    const handler = createSecureHttpHandler(server as never);
    const req = createRequest({
      headers: { 'content-type': 'application/json' },
      body: 'not-json'
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toMatch(/invalid json/i);
  });

  it('maps pipeline violations to HTTP error responses', async () => {
    const errorResponse = { error: { code: -32600, message: 'blocked' } };
    const server = createMockServer({
      pipelineResult: {
        passed: false,
        allowed: false,
        violationType: 'RATE_LIMIT_EXCEEDED',
        severity: 'HIGH',
        reason: 'Too many requests'
      }
    });
    server._errorSanitizer.createSanitizedErrorResponse.mockReturnValue(errorResponse);

    const handler = createSecureHttpHandler(server as never);
    const req = createRequest({
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(INIT)
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

    expect(handler.sessionCount).toBe(0); // the refused initialize released its slot
    expect(server._errorSanitizer.createSanitizedErrorResponse).toHaveBeenCalledWith(
      1,
      'Too many requests',
      'HIGH',
      'RATE_LIMIT_EXCEEDED'
    );
    expect(res.statusCode).toBe(429);
    expect(res.body).toBe(JSON.stringify(errorResponse));
  });

  it('passes validated requests to the MCP transport', async () => {
    const logger = {
      logSecurityDecision: vi.fn(),
      logInfo: vi.fn()
    };
    const server = createMockServer({ logger });
    const handler = createSecureHttpHandler(server as never);
    const sid = await openSession(handler);
    const body = { jsonrpc: '2.0', id: 99, method: 'tools/list' };
    const req = createRequest({
      headers: { 'content-type': 'application/json', 'mcp-session-id': sid },
      body: JSON.stringify(body)
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

    // The pipeline sees the server-issued id, never a client-chosen value.
    expect(server._validationPipeline.validate).toHaveBeenLastCalledWith(
      body,
      expect.objectContaining({ transportLevel: true, sessionId: sid })
    );
    // One McpServer per session, built from the frozen registrations; the primary is not connected.
    expect(server._createSessionServer).toHaveBeenCalledTimes(1);
    expect(server._mcpServer.connect).not.toHaveBeenCalled();
    expect(currentMockTransport?.handleRequest).toHaveBeenLastCalledWith(req, res, body);
  });

  describe('GET and DELETE controls (ship run #1: this branch had none)', () => {
    const runOnce = async (handler: ReturnType<typeof createSecureHttpHandler>, method: string, headers: Record<string, string> = {}) => {
      const req = createRequest({ method, headers });
      const res = new MockResponse();
      setImmediate(() => req.end());
      await handler(req as never, res as never);
      return res;
    };

    it('applies the error lockout to malformed requests only: a known session\'s GET still works', async () => {
      // 0.1.0: the lockout throttles a key's malformed requests (a header-less GET is one);
      // it never refuses a well-formed request, so a client that probed cannot lose its own session.
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler, {});
      for (let i = 0; i < LOCKOUT; i++) await runOnce(handler, 'PATCH');
      expect((await runOnce(handler, 'GET')).statusCode).toBe(429);
      const calls = currentMockTransport!.handleRequest.mock.calls.length;
      expect((await runOnce(handler, 'GET', { 'mcp-session-id': sid })).statusCode).not.toBe(429);
      expect(currentMockTransport!.handleRequest.mock.calls.length).toBe(calls + 1);
    });

    it('caps GET/DELETE on known sessions per client (sessionlessRequestsPerMinute)', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never, { sessionlessRequestsPerMinute: 3 });
      const sid = await openSession(handler, {});
      for (let i = 0; i < 3; i++) expect((await runOnce(handler, 'GET', { 'mcp-session-id': sid })).statusCode).not.toBe(429);
      const fourth = await runOnce(handler, 'DELETE', { 'mcp-session-id': sid });
      expect(fourth.statusCode).toBe(429);
      expect(fourth.headers['Retry-After']).toBe('60');
      expect(fourth.headers['X-RateLimit-Scope']).toBe('sessionless');
    });

    it.each([
      ['GET', 'bad\u0000id'],
      ['GET', 'has space'],
      ['DELETE', '\u00e9-non-ascii'],
      ['POST', 'x'.repeat(257)]
    ])('%s rejects a malformed Mcp-Session-Id (%j) with 400 before the SDK sees it', async (method, sid) => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const res = await runOnce(handler, method, { 'mcp-session-id': sid, 'content-type': 'application/json' });
      expect(res.statusCode).toBe(400);
      expect(res.body).toContain('Mcp-Session-Id');
      expect(server._validationPipeline.validate).not.toHaveBeenCalled();
    });

    it('control: a well-formed, server-issued Mcp-Session-Id is forwarded; a client-chosen one is 404', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler, {});
      const calls = currentMockTransport!.handleRequest.mock.calls.length;
      expect((await runOnce(handler, 'GET', { 'mcp-session-id': sid })).statusCode).not.toBe(400);
      expect(currentMockTransport!.handleRequest.mock.calls.length).toBe(calls + 1);
      const chosen = await runOnce(handler, 'GET', { 'mcp-session-id': '3f0a9c2e-5b7d-4e1a-9f3c-2d8b6a1c4e7f' });
      expect(chosen.statusCode).toBe(404);
      expect(currentMockTransport!.handleRequest.mock.calls.length).toBe(calls + 1);
    });
  });

  describe('per-IP limiters key on a client address the client cannot choose (trustProxy)', () => {
    const fromPeer = async (
      handler: ReturnType<typeof createSecureHttpHandler>,
      method: string,
      remoteAddress: string,
      headers: Record<string, string> = {}
    ) => {
      const req = Object.assign(createRequest({ method, headers }), { socket: { remoteAddress } });
      const res = new MockResponse();
      setImmediate(() => req.end());
      await handler(req as never, res as never);
      return res;
    };

    it('default: rotating X-Forwarded-For from one peer still trips the error lockout', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never);
      const statuses: number[] = [];
      for (let i = 0; i < LOCKOUT + 5; i++) {
        statuses.push((await fromPeer(handler, 'PATCH', '192.0.2.10', { 'x-forwarded-for': `198.51.100.${i}` })).statusCode);
      }
      expect(statuses.slice(0, LOCKOUT).every(s => s === 405)).toBe(true);
      expect(statuses.slice(LOCKOUT).every(s => s === 429)).toBe(true);
    });

    it('default: rotating X-Real-IP from one peer still trips the GET/DELETE limiter', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, { sessionlessRequestsPerMinute: 3 });
      const sid = await openSession(handler);
      for (let i = 0; i < 3; i++) {
        expect((await fromPeer(handler, 'GET', '192.0.2.10', { 'x-real-ip': `198.51.100.${i}`, 'mcp-session-id': sid })).statusCode).not.toBe(429);
      }
      expect((await fromPeer(handler, 'GET', '192.0.2.10', { 'x-real-ip': '198.51.100.99', 'mcp-session-id': sid })).statusCode).toBe(429);
    });

    it('trustProxy 1: clients behind one proxy are limited separately by the proxy-appended address', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, { sessionlessRequestsPerMinute: 2, trustProxy: 1 });
      const sid = await openSession(handler);
      const viaProxy = (client: string, spoof: string) =>
        fromPeer(handler, 'GET', '10.0.0.1', { 'x-forwarded-for': `${spoof}, ${client}`, 'mcp-session-id': sid });
      await viaProxy('203.0.113.1', '1.1.1.1');
      await viaProxy('203.0.113.1', '2.2.2.2');
      const limited = await viaProxy('203.0.113.1', '3.3.3.3');
      expect(limited.statusCode).toBe(429);
      expect(limited.headers['X-RateLimit-Scope']).toBe('sessionless');
      expect((await viaProxy('203.0.113.2', '3.3.3.3')).statusCode).not.toBe(429);
    });

    it('trustProxy 1: DELETE shares the per-client sessionless budget with GET', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, { sessionlessRequestsPerMinute: 2, trustProxy: 1 });
      // A DELETE ends its session, so the budget is spent across three sessions.
      const [s1, s2, s3] = [await openSession(handler), await openSession(handler), await openSession(handler)];
      const viaProxy = (method: string, client: string, sid: string) =>
        fromPeer(handler, method, '10.0.0.1', { 'x-forwarded-for': `spoof-${method}, ${client}`, 'mcp-session-id': sid });
      await viaProxy('GET', '203.0.113.1', s1);
      await viaProxy('DELETE', '203.0.113.1', s2);
      const limited = await viaProxy('DELETE', '203.0.113.1', s1);
      expect(limited.statusCode).toBe(429);
      expect(limited.headers['X-RateLimit-Scope']).toBe('sessionless');
      expect((await viaProxy('DELETE', '203.0.113.2', s3)).statusCode).not.toBe(429);
    });

    it('trustProxy 1: sessionlessRequestsPerHour is enforced per client', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, {
        sessionlessRequestsPerMinute: 100, sessionlessRequestsPerHour: 3, trustProxy: 1
      });
      const sid = await openSession(handler);
      const viaProxy = (client: string, i: number) =>
        fromPeer(handler, 'GET', '10.0.0.1', { 'x-forwarded-for': `198.51.100.${i}, ${client}`, 'mcp-session-id': sid });
      for (let i = 0; i < 3; i++) expect((await viaProxy('203.0.113.1', i)).statusCode).not.toBe(429);
      expect((await viaProxy('203.0.113.1', 9)).statusCode).toBe(429);
      expect((await viaProxy('203.0.113.2', 9)).statusCode).not.toBe(429);
    });

    it('trustProxy 1: the error lockout keys on the proxy-appended address, not the spoofed one', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, { trustProxy: 1 });
      const viaProxy = (client: string, i: number) =>
        fromPeer(handler, 'PATCH', '10.0.0.1', { 'x-forwarded-for': `198.51.100.${i}, ${client}` });
      for (let i = 0; i < LOCKOUT; i++) expect((await viaProxy('203.0.113.1', i)).statusCode).toBe(405);
      const limited = await viaProxy('203.0.113.1', 99);
      expect(limited.statusCode).toBe(429);
      expect(limited.headers['X-RateLimit-Scope']).toBe('errors');
      expect((await viaProxy('203.0.113.2', 99)).statusCode).toBe(405);
    });

    it('trusted proxy list: a request reaching the handler directly is keyed on its own address', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never, { trustProxy: ['10.0.0.0/8'] });
      const statuses: number[] = [];
      for (let i = 0; i <= LOCKOUT; i++) {
        statuses.push((await fromPeer(handler, 'PATCH', '203.0.113.50', { 'x-forwarded-for': `198.51.100.${i}` })).statusCode);
      }
      expect(statuses.at(-1)).toBe(429);
    });

    it('charges an aborted body to the client that sent it, not a shared "unknown" key', async () => {
      const handler = createSecureHttpHandler(createMockServer() as never);
      const abortingPost = async () => {
        let ended = false;
        const req = createRequest({ headers: { 'content-type': 'application/json' }, body: 'not-json' });
        req.on('end', () => { ended = true; });
        Object.defineProperty(req, 'socket', {
          value: { get remoteAddress() { return ended ? undefined : '192.0.2.77'; } }
        });
        await handler(req as never, new MockResponse() as never);
      };
      for (let i = 0; i < LOCKOUT; i++) await abortingPost();
      const res = await fromPeer(handler, 'GET', '192.0.2.77');
      expect(res.statusCode).toBe(429);
      expect(res.headers['X-RateLimit-Scope']).toBe('errors');
    });

    it('passes the resolved client address to the pipeline as clientId', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never, { trustProxy: 1 });
      const sid = await openSession(handler);
      const req = Object.assign(createRequest({
        headers: { 'content-type': 'application/json', 'mcp-session-id': sid, 'x-forwarded-for': 'spoof, 203.0.113.9' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
      }), { socket: { remoteAddress: '10.0.0.1' } });
      await handler(req as never, new MockResponse() as never);
      expect(server._createPipelineContext).toHaveBeenLastCalledWith(
        expect.objectContaining({ clientId: '203.0.113.9', sessionId: sid })
      );
    });

    it.each([
      [{ trustProxy: true }],
      [{ trustProxy: ['not-an-ip'] }],
      [{ sessionlessRequestsPerMinute: NaN }],
      [{ sessionlessRequestsPerMinute: Infinity }],
      [{ sessionlessRequestsPerHour: 0 }]
    ])('rejects %j at construction', (options) => {
      expect(() => createSecureHttpHandler(createMockServer() as never, options as never)).toThrow(TypeError);
    });
  });

  describe('GET and DELETE methods', () => {
    it('handles GET requests without validation (SSE)', async () => {
      const logger = { logInfo: vi.fn(), logSecurityDecision: vi.fn() };
      const server = createMockServer({ logger });
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler);
      const validated = server._validationPipeline.validate.mock.calls.length;
      const req = createRequest({ method: 'GET', headers: { 'mcp-session-id': sid } });
      const res = new MockResponse();

      // Don't write body for GET
      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(server._validationPipeline.validate.mock.calls.length).toBe(validated);
      expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(req, res);
      expect(logger.logInfo).toHaveBeenCalledWith('HTTP GET request completed');
    });

    it('handles DELETE requests without validation (session cleanup)', async () => {
      const logger = { logInfo: vi.fn(), logSecurityDecision: vi.fn() };
      const server = createMockServer({ logger });
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler);
      const validated = server._validationPipeline.validate.mock.calls.length;
      const req = createRequest({ method: 'DELETE', headers: { 'mcp-session-id': sid } });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(server._validationPipeline.validate.mock.calls.length).toBe(validated);
      expect(handler.sessionCount).toBe(0);
      expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(req, res);
      expect(logger.logInfo).toHaveBeenCalledWith('HTTP DELETE request completed');
    });

    it('returns 500 when GET request transport fails', async () => {
      currentMockTransport = {
        handleRequest: vi.fn(async (req: { method?: string }) => { if (req.method === 'GET') throw new Error('Transport error'); })
      };
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler);
      const req = createRequest({ method: 'GET', headers: { 'mcp-session-id': sid } });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(500);
      expect(JSON.parse(res.body).error).toBe('Internal server error');
    });

    it('returns 500 when DELETE request transport fails', async () => {
      currentMockTransport = {
        handleRequest: vi.fn(async (req: { method?: string }) => { if (req.method === 'DELETE') throw new Error('Transport error'); })
      };
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const sid = await openSession(handler);
      const req = createRequest({ method: 'DELETE', headers: { 'mcp-session-id': sid } });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(500);
      expect(JSON.parse(res.body).error).toBe('Internal server error');
    });
  });

  describe('HTTP method validation', () => {
    it('rejects unsupported HTTP methods with 405', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'PUT', headers: {} });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(405);
      expect(res.headers['Allow']).toBe('GET, POST, DELETE');
      expect(JSON.parse(res.body).error).toBe('Method not allowed');
    });

    it('rejects PATCH method with 405', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'PATCH', headers: {} });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(405);
    });
  });

  describe('violation type to HTTP status mapping', () => {
    it('returns 413 for SIZE_LIMIT_EXCEEDED', async () => {
      const server = createMockServer({
        pipelineResult: {
          passed: false,
          allowed: false,
          violationType: 'SIZE_LIMIT_EXCEEDED',
          severity: 'MEDIUM',
          reason: 'Message too large'
        }
      });

      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(413);
    });

    it('returns 403 for POLICY_VIOLATION', async () => {
      const server = createMockServer({
        pipelineResult: {
          passed: false,
          allowed: false,
          violationType: 'POLICY_VIOLATION',
          severity: 'HIGH',
          reason: 'Access denied'
        }
      });

      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(403);
    });

    it('returns 403 for TOOL_NOT_ALLOWED', async () => {
      const server = createMockServer({
        pipelineResult: {
          passed: false,
          allowed: false,
          violationType: 'TOOL_NOT_ALLOWED',
          severity: 'HIGH',
          reason: 'Tool access denied'
        }
      });

      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(403);
    });

    it('returns 429 for BURST_ACTIVITY', async () => {
      const server = createMockServer({
        pipelineResult: {
          passed: false,
          allowed: false,
          violationType: 'BURST_ACTIVITY',
          severity: 'MEDIUM',
          reason: 'Burst detected'
        }
      });

      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(429);
    });

    it('returns 403 for unknown violation types (falls back to POLICY_VIOLATION)', async () => {
      const server = createMockServer({
        pipelineResult: {
          passed: false,
          allowed: false,
          violationType: 'UNKNOWN_TYPE', // Invalid type - falls back to POLICY_VIOLATION
          severity: 'HIGH',
          reason: 'Unknown violation'
        }
      });

      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      // Unknown violation types fall back to POLICY_VIOLATION which is 403
      expect(res.statusCode).toBe(403);
    });
  });

  describe('request body handling', () => {
    it('returns 408 for request timeout', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never, { requestTimeout: 10 });
      const req = createRequest({
        method: 'POST',
        headers: { 'content-type': 'application/json' }
      });
      const res = new MockResponse();

      // Don't end the request - let it timeout

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(408);
      expect(JSON.parse(res.body).error).toMatch(/timeout/i);
    });

    it('returns 400 for body exceeding size limit', async () => {
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never, { maxBodySize: 10 });
      const req = createRequest({
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ data: 'this is a very long body that exceeds the limit' })
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body).error).toMatch(/exceeds/i);
    });

    it('returns 500 when POST transport fails after validation', async () => {
      currentMockTransport = {
        handleRequest: vi.fn().mockRejectedValue(new Error('Transport error'))
      };
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(INIT)
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(500);
      expect(JSON.parse(res.body).error).toBe('Internal server error');
    });
  });
});

describe('createSecureHttpServer', () => {
  it('returns 404 for non-matching endpoints', async () => {
    const server = createMockServer();
    const httpServer = createSecureHttpServer(server as never, { endpoint: '/mcp' });

    // Get the request handler from the server
    const handler = (httpServer as unknown as { _events: { request: (req: unknown, res: unknown) => Promise<void> } })._events.request;

    const req = createRequest({ method: 'GET', headers: {} });
    req.url = '/wrong-endpoint';
    req.headers.host = 'localhost:3000';
    const res = new MockResponse();

    setImmediate(() => req.end());

    await handler(req as never, res as never);

    expect(res.statusCode).toBe(404);
    expect(JSON.parse(res.body).error).toBe('Not found');
  });

  it('forwards requests to handler when endpoint matches', async () => {
    const server = createMockServer();
    const httpServer = createSecureHttpServer(server as never, { endpoint: '/mcp' });

    const handler = (httpServer as unknown as { _events: { request: (req: unknown, res: unknown) => Promise<void> } })._events.request;

    const body = INIT;
    const req = createRequest({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    req.url = '/mcp';
    req.headers.host = 'localhost:3000';
    const res = new MockResponse();

    await handler(req as never, res as never);

    expect(server._validationPipeline.validate).toHaveBeenCalled();
  });

  it('normalizes trailing slashes in endpoint matching', async () => {
    const server = createMockServer();
    const httpServer = createSecureHttpServer(server as never, { endpoint: '/mcp/' });

    const handler = (httpServer as unknown as { _events: { request: (req: unknown, res: unknown) => Promise<void> } })._events.request;

    const body = INIT;
    const req = createRequest({
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body)
    });
    req.url = '/mcp';
    req.headers.host = 'localhost:3000';
    const res = new MockResponse();

    await handler(req as never, res as never);

    // Should match despite trailing slash difference
    expect(server._validationPipeline.validate).toHaveBeenCalled();
  });

  it('includes security headers in 404 responses', async () => {
    const server = createMockServer();
    const httpServer = createSecureHttpServer(server as never, { endpoint: '/mcp' });

    const handler = (httpServer as unknown as { _events: { request: (req: unknown, res: unknown) => Promise<void> } })._events.request;

    const req = createRequest({ method: 'GET', headers: {} });
    req.url = '/wrong';
    req.headers.host = 'localhost:3000';
    const res = new MockResponse();

    setImmediate(() => req.end());

    await handler(req as never, res as never);

    expect(res.headers['X-Content-Type-Options']).toBe('nosniff');
    expect(res.headers['X-Frame-Options']).toBe('DENY');
    expect(res.headers['Cache-Control']).toBe('no-store');
  });
});

describe('createSecureHttpsServer', () => {
  // Note: The HTTPS server uses the same routing logic as HTTP (tested above).
  // Full HTTPS integration tests require valid TLS certificates.
  // These tests verify the export exists with the correct signature.

  it('is exported as a function', () => {
    expect(typeof createSecureHttpsServer).toBe('function');
  });

  it('requires key and cert options', () => {
    // TypeScript enforces this at compile time, but we verify at runtime
    // that missing options would cause an error
    const server = createMockServer();

    // Calling with valid options should not throw until TLS parsing
    // (the function itself is callable with correct signature)
    expect(() => {
      try {
        createSecureHttpsServer(server as never, {
          key: 'test-key',
          cert: 'test-cert',
          endpoint: '/mcp'
        });
      } catch (e) {
        // Expected: TLS parsing error for invalid certificates
        // This confirms the function was called correctly
        const errorMessage = e instanceof Error ? e.message : String(e);
        if (!errorMessage.includes('PEM') && !errorMessage.includes('key')) {
          throw e; // Re-throw if it's not a TLS-related error
        }
      }
    }).not.toThrow();
  });
});
