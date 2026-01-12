import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PassThrough } from 'node:stream';
import { createSecureHttpHandler } from '@/security/transport/http-server.js';

let currentMockTransport: { handleRequest: ReturnType<typeof vi.fn> } | null = null;

vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: class {
    constructor() {
      return currentMockTransport;
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
    }
  };
}

class MockResponse {
  statusCode = 0;
  headers: Record<string, string> = {};
  body = '';
  ended = false;

  writeHead(status: number, headers: Record<string, string> = {}) {
    this.statusCode = status;
    this.headers = headers;
  }

  end(data?: string) {
    this.body = data ?? '';
    this.ended = true;
  }
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
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

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
    const body = { jsonrpc: '2.0', id: 99, method: 'tools/list' };
    const req = createRequest({
      headers: { 'content-type': 'application/json', 'mcp-session-id': 'test' },
      body: JSON.stringify(body)
    });
    const res = new MockResponse();

    await handler(req as never, res as never);

    expect(server._validationPipeline.validate).toHaveBeenCalledWith(
      body,
      expect.objectContaining({
        transportLevel: true,
        sessionId: 'test'
      })
    );
    expect(server._mcpServer.connect).toHaveBeenCalled();
    expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(
      req,
      res,
      body
    );
  });

  describe('GET and DELETE methods', () => {
    it('handles GET requests without validation (SSE)', async () => {
      const logger = { logInfo: vi.fn(), logSecurityDecision: vi.fn() };
      const server = createMockServer({ logger });
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'GET', headers: {} });
      const res = new MockResponse();

      // Don't write body for GET
      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(server._validationPipeline.validate).not.toHaveBeenCalled();
      expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(req, res);
      expect(logger.logInfo).toHaveBeenCalledWith('HTTP GET request completed');
    });

    it('handles DELETE requests without validation (session cleanup)', async () => {
      const logger = { logInfo: vi.fn(), logSecurityDecision: vi.fn() };
      const server = createMockServer({ logger });
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'DELETE', headers: {} });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(server._validationPipeline.validate).not.toHaveBeenCalled();
      expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(req, res);
      expect(logger.logInfo).toHaveBeenCalledWith('HTTP DELETE request completed');
    });

    it('returns 500 when GET request transport fails', async () => {
      currentMockTransport = {
        handleRequest: vi.fn().mockRejectedValue(new Error('Transport error'))
      };
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'GET', headers: {} });
      const res = new MockResponse();

      setImmediate(() => req.end());

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(500);
      expect(JSON.parse(res.body).error).toBe('Internal server error');
    });

    it('returns 500 when DELETE request transport fails', async () => {
      currentMockTransport = {
        handleRequest: vi.fn().mockRejectedValue(new Error('Transport error'))
      };
      const server = createMockServer();
      const handler = createSecureHttpHandler(server as never);
      const req = createRequest({ method: 'DELETE', headers: {} });
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
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
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'test' })
      });
      const res = new MockResponse();

      await handler(req as never, res as never);

      expect(res.statusCode).toBe(500);
      expect(JSON.parse(res.body).error).toBe('Internal server error');
    });
  });
});
