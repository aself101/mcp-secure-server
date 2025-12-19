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
  const validationPipeline = {
    validate: vi.fn().mockResolvedValue(result)
  };

  return {
    validationPipeline,
    _errorSanitizer: {
      createSanitizedErrorResponse: vi.fn().mockReturnValue({ error: 'sanitized' })
    },
    _securityLogger: overrides.logger ?? null,
    mcpServer: {
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
    expect(server.validationPipeline.validate).not.toHaveBeenCalled();
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

    expect(server.validationPipeline.validate).toHaveBeenCalledWith(
      body,
      expect.objectContaining({
        transportLevel: true,
        sessionId: 'test'
      })
    );
    expect(server.mcpServer.connect).toHaveBeenCalled();
    expect(currentMockTransport?.handleRequest).toHaveBeenCalledWith(
      req,
      res,
      body
    );
  });
});
