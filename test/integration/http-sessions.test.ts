/**
 * Per-session HTTP transport, end to end, with the SDK's own client.
 *
 * Negative control for issue 4bf30630 (spec http-transport-per-session v0.4.3, Phase 0): through
 * 0.0.27 the handler shared one stateless SDK transport, which the SDK refuses to reuse, so every
 * request after the first answered 500 and the package never saw it. Every earlier HTTP test sent
 * one request to a fresh server, so none could fail on this. This one sends many requests from two
 * clients and asserts every status.
 *
 * MSS_HTTP_SESSIONS_TARGET points the import at a built `dist/index.js` (the checklist's run
 * "against 0.0.27's dist"); by default it imports the source tree.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createServer, request } from 'node:http';
import type { Server, IncomingMessage } from 'node:http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';

type Pkg = typeof import('../../src/index.js');
const target = process.env.MSS_HTTP_SESSIONS_TARGET;
const pkg: Pkg = target ? await import(target) : await import('../../src/index.js');

interface Exchange { method: string; rpc: string; status: number }

/** A fetch that records the status of every exchange, so a failure names the request that broke. */
function recordingFetch(log: Exchange[]): typeof fetch {
  return async (input, init) => {
    const res = await fetch(input, init);
    let rpc = '-';
    if (typeof init?.body === 'string') {
      try { rpc = (JSON.parse(init.body) as { method?: string }).method ?? 'response'; } catch { rpc = '?'; }
    }
    log.push({ method: init?.method ?? 'GET', rpc, status: res.status });
    return res;
  };
}

function rawPost(port: number, body: unknown, sessionId?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: '127.0.0.1', port, path: '/mcp', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-06-18',
        ...(sessionId ? { 'mcp-session-id': sessionId } : {})
      }
    }, (res: IncomingMessage) => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: data }));
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

describe('HTTP sessions (SDK client, multiple clients)', () => {
  let httpServer: Server;
  let port: number;
  let url: URL;

  beforeEach(async () => {
    const server = new pkg.SecureMcpServer({ name: 'sessions-test', version: '1.0.0' }, {
      enableLogging: false,
      toolRegistry: [{ name: 'echo', sideEffects: 'none' }]
    });
    server.registerTool('echo', { description: 'echo', inputSchema: { text: z.string() } },
      async ({ text }) => ({ content: [{ type: 'text', text }] }));
    const handler = pkg.createSecureHttpHandler(server as Parameters<typeof pkg.createSecureHttpHandler>[0]);
    httpServer = createServer(handler);
    await new Promise<void>(resolve => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address();
    port = typeof addr === 'object' && addr ? addr.port : 0;
    url = new URL(`http://127.0.0.1:${port}/mcp`);
  });

  afterEach(async () => {
    httpServer.closeAllConnections();
    await new Promise<void>(resolve => httpServer.close(() => resolve()));
  });

  it('serves two concurrent clients end to end, and DELETE ends only its own session', async () => {
    const logA: Exchange[] = [];
    const logB: Exchange[] = [];
    const a = new Client({ name: 'client-a', version: '1.0.0' });
    const b = new Client({ name: 'client-b', version: '1.0.0' });
    const ta = new StreamableHTTPClientTransport(url, { fetch: recordingFetch(logA) });
    const tb = new StreamableHTTPClientTransport(url, { fetch: recordingFetch(logB) });

    const run = async (c: Client, t: StreamableHTTPClientTransport, who: string) => {
      await c.connect(t);
      const tools = await c.listTools();
      expect(tools.tools.map(x => x.name)).toEqual(['echo']);
      const res = await c.callTool({ name: 'echo', arguments: { text: who } });
      expect(res.content).toEqual([{ type: 'text', text: who }]);
    };
    // Bounded: on a broken transport an SDK client can wait on a response that never comes, and a
    // vitest timeout would hide the statuses below, which are what this test is about.
    const bounded = (p: Promise<void>, who: string) => Promise.race([p, new Promise<void>((_, reject) =>
      setTimeout(() => reject(new Error(`${who} did not finish within 4 s`)), 4000).unref())]);
    const settled = await Promise.allSettled([bounded(run(a, ta, 'A'), 'A'), bounded(run(b, tb, 'B'), 'B')]);
    if (process.env.MSS_HTTP_SESSIONS_DEBUG) console.log(JSON.stringify({ logA, logB, settled }, null, 1));

    // Status of every exchange first: on a broken transport this is the assertion that names
    // which request failed and how, before any client-side error message.
    const failures = [...logA.map(e => ({ who: 'A', ...e })), ...logB.map(e => ({ who: 'B', ...e }))]
      .filter(e => e.status >= 400);
    expect(failures, `non-2xx exchanges: ${JSON.stringify(failures)}`).toEqual([]);
    expect(settled.map(s => s.status)).toEqual(['fulfilled', 'fulfilled']);

    const idA = ta.sessionId;
    const idB = tb.sessionId;
    expect(idA).toBeTypeOf('string');
    expect(idB).toBeTypeOf('string');
    expect(idA).not.toBe(idB);

    await ta.terminateSession();
    const afterDelete = await rawPost(port, { jsonrpc: '2.0', id: 9, method: 'tools/list' }, idA);
    expect(afterDelete.status).toBe(404);

    const stillB = await b.callTool({ name: 'echo', arguments: { text: 'B again' } });
    expect(stillB.content).toEqual([{ type: 'text', text: 'B again' }]);
    expect(logB.filter(e => e.status >= 400)).toEqual([]);

    await a.close();
    await b.close();
  });

  // D21 (consumer-validate run #17, CGC-2): a session's outgoing messages go through the same
  // sanitizer as the connect() connection. The SDK's own input-validation failure is the case that
  // reaches a first-time caller: it leaves as a tool result carrying the raw Zod issue array, which
  // the sanitizer rewrites into prose. Through 0.0.27 HTTP connected unwrapped.
  it('sanitizes outgoing messages exactly as the connect() connection does', async () => {
    const call = async (c: Client) => {
      const res = await c.callTool({ name: 'echo', arguments: { text: 42 } });
      return (res.content as Array<{ text: string }>)[0]!.text;
    };
    const http = new Client({ name: 'http', version: '1.0.0' });
    await http.connect(new StreamableHTTPClientTransport(url));
    const overHttp = await call(http);
    await http.close();

    const { InMemoryTransport } = await import('@modelcontextprotocol/sdk/inMemory.js');
    const stdio = new pkg.SecureMcpServer({ name: 'stdio-twin', version: '1.0.0' }, {
      enableLogging: false, toolRegistry: [{ name: 'echo', sideEffects: 'none' }]
    });
    stdio.registerTool('echo', { description: 'echo', inputSchema: { text: z.string() } },
      async ({ text }) => ({ content: [{ type: 'text', text }] }));
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await stdio.connect(st);
    const local = new Client({ name: 'stdio', version: '1.0.0' });
    await local.connect(ct);
    const overConnect = await call(local);
    await local.close();
    await stdio.close();

    // Mutation: drop sanitizeOutgoing from the registry deps -> the raw issue array reaches HTTP.
    expect(overConnect).toMatch(/^Invalid arguments for tool echo — text: /); // the rewrite, not 'MCP error -32602: Input validation error: [...]'
    expect(overHttp).toMatch(/^Invalid arguments for tool echo — text: /);
    expect(overHttp).toBe(overConnect);
  });

  // D22 (consumer-validate run #17, CGC-1): Layer 5 response validators receive the calling
  // session's id over HTTP. Until 0.1.0 their context was always {}, so a "per-session" egress
  // budget was one process-wide budget.
  it('gives Layer 5 response validators the calling session id', async () => {
    const seen: Array<string | undefined> = [];
    const server = new pkg.SecureMcpServer({ name: 'rv-test', version: '1.0.0' }, {
      enableLogging: false, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'],
      toolRegistry: [{ name: 'echo', sideEffects: 'none' }]
    });
    const layer5 = server.validationPipeline.getLayerByClassName('ContextualValidationLayer') as unknown as {
      addResponseValidator(name: string, fn: (r: unknown, q: unknown, c: { sessionId?: string }) => { passed: boolean }, o: object): void;
    };
    layer5.addResponseValidator('record-session', (_r, _q, c) => { seen.push(c.sessionId); return { passed: true }; }, { enabled: true });
    server.registerTool('echo', { inputSchema: { text: z.string() } }, async ({ text }) => ({ content: [{ type: 'text', text }] }));
    const handler = pkg.createSecureHttpHandler(server as Parameters<typeof pkg.createSecureHttpHandler>[0]);
    const local = createServer(handler);
    await new Promise<void>(resolve => local.listen(0, '127.0.0.1', resolve));
    const addr = local.address();
    const transports = [0, 1].map(() => new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/mcp`)));
    const clients = transports.map((_, i) => new Client({ name: `rv-${i}`, version: '1.0.0' }));
    try {
      for (const [i, c] of clients.entries()) {
        await c.connect(transports[i]!);
        await c.callTool({ name: 'echo', arguments: { text: 'x' } });
      }
      // Mutation: pass {} as before -> [undefined, undefined].
      expect(seen).toEqual(transports.map(t => t.sessionId));
      expect(seen.every(id => typeof id === 'string')).toBe(true);
      expect(seen[0]).not.toBe(seen[1]);
    } finally {
      for (const c of clients) await c.close();
      local.closeAllConnections();
      await (handler as { close?: () => Promise<void> }).close?.();
      await new Promise<void>(resolve => local.close(() => resolve()));
    }
  });

  // Spec Tests, "presets": if a preset's Layer 4 defaults refused the SDK handshake
  // (initialize -> notifications/initialized -> GET -> tools/list), they are fixed in 0.1.0.
  // paranoid enforces Layer 4 chaining, which refused notifications/initialized until 0.1.0
  // (notifications now bypass chaining): the SDK client failed to connect.
  it.each(['basic', 'standard', 'paranoid'] as const)('the SDK client handshake succeeds under the %s preset', async (securityLevel) => {
    const server = new pkg.SecureMcpServer({ name: 'preset-test', version: '1.0.0' }, {
      enableLogging: false, securityLevel, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'],
      toolRegistry: [{ name: 'echo', sideEffects: 'none' }]
    });
    server.registerTool('echo', { inputSchema: { text: z.string() } }, async ({ text }) => ({ content: [{ type: 'text', text }] }));
    const handler = pkg.createSecureHttpHandler(server as Parameters<typeof pkg.createSecureHttpHandler>[0]);
    const local = createServer(handler);
    await new Promise<void>(resolve => local.listen(0, '127.0.0.1', resolve));
    const addr = local.address();
    const log: Exchange[] = [];
    const client = new Client({ name: 'preset-client', version: '1.0.0' });
    try {
      await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${typeof addr === 'object' && addr ? addr.port : 0}/mcp`), { fetch: recordingFetch(log) }));
      expect((await client.listTools()).tools.map(t => t.name)).toEqual(['echo']);
      expect(log.filter(e => e.status >= 400)).toEqual([]);
    } finally {
      await client.close();
      local.closeAllConnections();
      await (handler as { close?: () => Promise<void> }).close?.();
      await new Promise<void>(resolve => local.close(() => resolve()));
    }
  });
});
