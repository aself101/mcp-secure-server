/**
 * The per-session request flow end to end (spec http-transport-per-session v0.4.3, C and D;
 * checklist Phase 3a acceptance). Real SecureMcpServer, real node:http(s) servers, raw
 * requests where the exact exchange matters and the SDK client where a host's behaviour
 * does. Each test names the mutation that must make it fail; they were run when it was
 * written (checklist, Phase 3a record).
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { createServer, request } from 'node:http';
import type { Server, IncomingMessage, ClientRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SecureMcpServer } from '../../src/security/mcp-secure-server.js';
import { createSecureHttpHandler, createSecureHttpServer, createSecureHttpsServer } from '../../src/security/transport/http-server.js';
import type { SessionHttpHandler } from '../../src/security/transport/http-server-types.js';
import { DEFAULT_ERRORS_PER_MINUTE as LOCKOUT } from '../../src/security/transport/error-rate-limiter.js';
import { SessionRegistry } from '../../src/security/transport/session-registry.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { LateRegistrationError } from '../../src/security/registration-log.js';
import { _resetProcessWarnings, type WarningCode } from '../../src/security/warnings.js';

const ACCEPT = 'application/json, text/event-stream';
const INIT = (capabilities: Record<string, unknown> = {}) => ({
  jsonrpc: '2.0', id: 0, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities, clientInfo: { name: 'flow-test', version: '1' } }
});
const PING = { jsonrpc: '2.0', id: 9, method: 'ping' };

interface Reply { status: number; headers: IncomingMessage['headers']; text: string; json: unknown }
interface Rig {
  server: SecureMcpServer; handler: SessionHttpHandler; http: Server; port: number;
  warnings: Array<{ code: WarningCode; message: string }>; sessionServers: McpServer[];
}
const rigs: Rig[] = [];
const open = new Set<ClientRequest>();

afterEach(async () => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const r of open) r.destroy();
  open.clear();
  for (const rig of rigs.splice(0)) {
    rig.http.closeAllConnections();
    await rig.handler.close();
    await new Promise<void>(resolve => rig.http.close(() => resolve()));
  }
  _resetProcessWarnings();
});

async function rig(options: Parameters<typeof createSecureHttpHandler>[1] = {}, opts: {
  bind?: string; serverOptions?: Record<string, unknown>; setup?: (s: SecureMcpServer) => void;
} = {}): Promise<Rig> {
  const warnings: Rig['warnings'] = [];
  const server = new SecureMcpServer({ name: 'flow', version: '1' }, {
    enableLogging: false,
    onWarning: (message: string, code: WarningCode) => { warnings.push({ code, message }); },
    toolRegistry: ['a', 'b', 'slow', 'raw'].map(name => ({ name, sideEffects: 'none' as const })),
    ...opts.serverOptions
  });
  opts.setup?.(server);
  const sessionServers: McpServer[] = [];
  const create = server._createSessionServer.bind(server);
  vi.spyOn(server, '_createSessionServer').mockImplementation(() => { const s = create(); sessionServers.push(s); return s; });
  const handler = createSecureHttpHandler(server, options);
  const http = createServer(handler);
  await new Promise<void>(resolve => http.listen(0, opts.bind ?? '127.0.0.1', resolve));
  const addr = http.address();
  const r: Rig = { server, handler, http, port: typeof addr === 'object' && addr ? addr.port : 0, warnings, sessionServers };
  rigs.push(r);
  return r;
}

function send(port: number, opts: { method?: string; headers?: Record<string, string>; body?: unknown; host?: string } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const q = request({
      host: opts.host ?? '127.0.0.1', port, path: '/mcp', method: opts.method ?? 'POST',
      headers: {
        ...(opts.body !== undefined ? { 'content-type': 'application/json', accept: ACCEPT } : {}),
        'mcp-protocol-version': '2025-06-18',
        ...opts.headers
      }
    }, res => {
      let text = '';
      res.on('data', c => { text += c; });
      res.on('end', () => {
        const data = text.split('\n').find(l => l.startsWith('data: '));
        let json: unknown = null;
        try { json = JSON.parse(data ? data.slice(6) : text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, text, json });
      });
    });
    open.add(q);
    q.on('error', reject);
    q.end(opts.body === undefined ? undefined : typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body));
  });
}
async function session(r: Rig, capabilities: Record<string, unknown> = {}): Promise<string> {
  const init = await send(r.port, { body: INIT(capabilities) });
  expect(init.status).toBe(200);
  const sid = init.headers['mcp-session-id'] as string;
  expect((await send(r.port, { headers: { 'mcp-session-id': sid }, body: { jsonrpc: '2.0', method: 'notifications/initialized' } })).status).toBe(202);
  return sid;
}
/** Whether the key is locked out, without charging it: a malformed request answers 405 or 429. */
const lockedOut = async (port: number) => (await send(port, { method: 'PUT' })).status === 429;
async function charge(port: number, n: number) { for (let i = 0; i < n; i++) await send(port, { method: 'PATCH' }); }

describe('Origin and Host (D)', () => {
  it('refuses an unlisted Origin with 403 before any session, pipeline or lockout charge', async () => {
    const r = await rig({ allowedOrigins: ['http://localhost:5173'] });
    const validate = vi.spyOn(r.server.validationPipeline, 'validate');
    // Mutation: skip the check when allowedOrigins is empty (the SDK's behaviour) -> covered below.
    for (let i = 0; i < LOCKOUT; i++) {
      const refused = await send(r.port, { headers: { origin: 'https://evil.example' }, body: INIT() });
      expect(refused.status).toBe(403);
      expect(refused.json).toMatchObject({ jsonrpc: '2.0', id: null, error: { message: expect.stringContaining('allowedOrigins') } });
    }
    expect(r.handler.sessionCount).toBe(0);
    expect(validate).not.toHaveBeenCalled();
    expect(await lockedOut(r.port)).toBe(false); // 20 refusals charged nothing
    expect((await send(r.port, { headers: { origin: 'http://localhost:5173' }, body: INIT() })).status).toBe(200);
    expect((await send(r.port, { body: INIT() })).status).toBe(200); // no Origin: a non-browser client
    expect((await send(r.port, { headers: { origin: 'null' }, body: INIT() })).status).toBe(403);
  });

  it('refuses any Origin when allowedOrigins is empty (the default)', async () => {
    const r = await rig();
    // Mutation: skip the check when the list is empty -> 200.
    expect((await send(r.port, { headers: { origin: 'http://localhost:5173' }, body: INIT() })).status).toBe(403);
  });

  it('validates allowedOrigins and allowedHosts at construction', () => {
    const s = () => new SecureMcpServer({ name: 'x', version: '1' }, { enableLogging: false, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'] });
    // Mutation: accept "null" with a warning (v0.4.1) -> construction succeeds.
    expect(() => createSecureHttpHandler(s(), { allowedOrigins: ['null'] })).toThrow(/cannot list "null"/);
    // Mutation: normalize instead of validating -> the typo silently never matches.
    for (const bad of ['https://app.example.com/', 'https://app.example.com/path', 'https://App.example.com', 'https://a.example:443']) {
      expect(() => createSecureHttpHandler(s(), { allowedOrigins: [bad] })).toThrow(/not a serialized origin/);
    }
    expect(() => createSecureHttpHandler(s(), { allowedHosts: [] })).toThrow(/non-empty/);
    expect(() => createSecureHttpHandler(s(), { allowedOrigins: ['chrome-extension://abcdef', 'http://localhost:5173'] })).not.toThrow();
  });

  it('with allowedHosts set, refuses an unlisted Host even without an Origin', async () => {
    const r = await rig({ allowedHosts: ['127.0.0.1:1'] });
    // Mutation: check Host only when Origin is present -> this request passes.
    const refused = await send(r.port, { body: INIT() });
    expect(refused.status).toBe(403);
    expect(JSON.stringify(refused.json)).toContain('allowedHosts');
  });
});

describe('exposure warning (D16)', () => {
  const exposed = (r: Rig) => r.warnings.filter(w => w.code === 'MCP_SECURE_SERVER_HTTP_EXPOSED');

  it('warns once for a listener bound to every interface, even when reached over loopback', async () => {
    const r = await rig({}, { bind: '0.0.0.0' });
    // Mutation: test the connection's localAddress (127.0.0.1 here) -> silent.
    await send(r.port, { body: INIT() });
    await send(r.port, { body: INIT() });
    expect(exposed(r)).toHaveLength(1);
    expect(exposed(r)[0]!.message).toContain('no authentication');
  });

  it('is silent on 127.0.0.1, still warns with allowedHosts set, and is silenced only by name', async () => {
    const local = await rig();
    await send(local.port, { body: INIT() });
    expect(exposed(local)).toHaveLength(0);
    // Mutation: let allowedHosts silence it (v0.4.2) -> no report.
    const hosts = await rig({ allowedHosts: ['127.0.0.1:1'] }, { bind: '0.0.0.0' });
    await send(hosts.port, { body: INIT() });
    expect(exposed(hosts)).toHaveLength(1);
    const silenced = await rig({}, { bind: '0.0.0.0', serverOptions: { silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPOSED'] } });
    await send(silenced.port, { body: INIT() });
    expect(exposed(silenced)).toHaveLength(0);
  });
});

describe('the lockout, unknown ids and malformed shapes (C)', () => {
  it('answers unknown ids 404 without the pipeline, the lockout or a 429 — even while locked out', async () => {
    const r = await rig();
    const validate = vi.spyOn(r.server.validationPipeline, 'validate');
    await charge(r.port, LOCKOUT);
    expect(await lockedOut(r.port)).toBe(true);
    // Mutation: consult the lockout or meter unknown ids -> 429 appears.
    const statuses = new Set<number>();
    for (let i = 0; i < 200; i++) statuses.add((await send(r.port, { headers: { 'mcp-session-id': `guess-${i}` }, body: PING })).status);
    expect([...statuses]).toEqual([404]);
    expect(validate).not.toHaveBeenCalled();
  });

  it('refuses header-less non-initialize requests with 400 before the pipeline, and charges them', async () => {
    const r = await rig();
    const validate = vi.spyOn(r.server.validationPipeline, 'validate');
    // Mutation: run the pipeline with sessionId undefined -> the spy is called.
    expect((await send(r.port, { body: PING })).status).toBe(400);
    expect((await send(r.port, { method: 'GET', headers: { accept: 'text/event-stream' } })).status).toBe(400);
    expect(validate).not.toHaveBeenCalled();
    for (let i = 0; i < LOCKOUT - 2; i++) await send(r.port, { body: PING });
    expect(await lockedOut(r.port)).toBe(true);
  });

  it('charges a malformed body to the lockout even when it carries a known session id', async () => {
    const r = await rig();
    const sid = await session(r);
    // Mutation: look the session up before the malformed checks -> not charged.
    for (let i = 0; i < LOCKOUT; i++) await send(r.port, { headers: { 'mcp-session-id': sid }, body: '{not json' });
    expect(await lockedOut(r.port)).toBe(true);
  });

  it('never refuses a well-formed request because the key is locked out', async () => {
    const r = await rig();
    const sid = await session(r);
    await charge(r.port, LOCKOUT);
    expect(await lockedOut(r.port)).toBe(true);
    // Mutation: keep the unconditional GET/DELETE consultation -> the GET is refused.
    const get = request({ host: '127.0.0.1', port: r.port, path: '/mcp', method: 'GET', headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': '2025-06-18' } });
    open.add(get);
    const getStatus = await new Promise<number>(resolve => { get.on('response', res => resolve(res.statusCode ?? 0)); get.end(); });
    expect(getStatus).toBe(200);
    expect((await send(r.port, { headers: { 'mcp-session-id': sid }, body: PING })).status).toBe(200);
    expect((await send(r.port, { body: INIT() })).status).toBe(200);
  });

  it('refuses a batch body with -32600, header-less and on a known session, before the pipeline, charged', async () => {
    const r = await rig();
    const sid = await session(r);
    const validate = vi.spyOn(r.server.validationPipeline, 'validate');
    // Mutation: drop the array check -> header-less gets the header-required 400; on a session
    // the array reaches the pipeline and Layer 1 refuses it uncharged.
    for (const headers of [{}, { 'mcp-session-id': sid }]) {
      const reply = await send(r.port, { headers, body: [INIT()] });
      expect(reply.status).toBe(400);
      expect(reply.json).toMatchObject({ error: { code: -32600, message: 'Batch requests are not supported' } });
    }
    expect(validate).not.toHaveBeenCalled();
    for (let i = 0; i < LOCKOUT - 2; i++) await send(r.port, { headers: { 'mcp-session-id': sid }, body: [PING] });
    expect(await lockedOut(r.port)).toBe(true);
  });
});

describe('the GET/DELETE limiter (D10)', () => {
  it('meters known-session GET/DELETE per key; unknown ids still 404; header-less ones charge the lockout instead', async () => {
    const r = await rig({ sessionlessRequestsPerMinute: 2 });
    const sid = await session(r);
    // Accept without text/event-stream: the SDK answers 406 at once, and the request is still metered.
    const get = (headers: Record<string, string>) => send(r.port, { method: 'GET', headers: { accept: 'application/json', ...headers } });
    expect((await get({ 'mcp-session-id': sid })).status).toBe(406);
    expect((await get({ 'mcp-session-id': sid })).status).toBe(406);
    // Mutation: drop the limiter call (v0.4.2's retirement) -> 406 again.
    const third = await get({ 'mcp-session-id': sid });
    expect(third.status).toBe(429);
    expect(third.headers['x-ratelimit-scope']).toBe('sessionless');
    expect((await get({ 'mcp-session-id': 'unknown-id' })).status).toBe(404);
    expect(await lockedOut(r.port)).toBe(false); // the limiter's 429 charged nothing
    for (let i = 0; i < LOCKOUT - 1; i++) expect((await get({})).status).toBe(400);
    expect(await lockedOut(r.port)).toBe(true);
    expect(() => createSecureHttpHandler(new SecureMcpServer({ name: 'z', version: '1' }, { enableLogging: false, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'] }), { sessionlessRequestsPerMinute: 0 })).toThrow(TypeError);
  });
});

describe('client responses (D14)', () => {
  /** Open a GET stream (resolving once it is established) and collect the server-initiated requests it carries. */
  async function stream(port: number, sid: string) {
    const events: Array<{ id: number | string; method: string }> = [];
    let established!: () => void;
    const ready = new Promise<void>(resolve => { established = resolve; });
    const q = request({ host: '127.0.0.1', port, path: '/mcp', method: 'GET', headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': '2025-06-18' } }, res => {
      expect(res.statusCode).toBe(200);
      established();
      res.on('data', (c: Buffer) => {
        for (const line of c.toString().split('\n')) {
          if (!line.startsWith('data: ')) continue;
          try { const m = JSON.parse(line.slice(6)); if (m.method) events.push(m); } catch { /* keepalive */ }
        }
      });
    });
    open.add(q);
    q.end();
    await ready;
    return events;
  }

  it('forwards a well-formed response (ping, and a sampling answer with ZWJ and ZWNJ text) without the pipeline', async () => {
    const r = await rig();
    const sid = await session(r, { sampling: {} });
    const events = await stream(r.port, sid);
    await vi.waitFor(() => expect(r.sessionServers).toHaveLength(1));
    const sessionServer = r.sessionServers[0]!;
    const validate = vi.spyOn(r.server.validationPipeline, 'validate');
    const pinged = sessionServer.server.ping();
    await vi.waitFor(() => expect(events.find(e => e.method === 'ping')).toBeDefined());
    const pingId = events.find(e => e.method === 'ping')!.id;
    // Mutation: route responses through the pipeline -> Layer 1 refuses the answer to ping.
    expect((await send(r.port, { headers: { 'mcp-session-id': sid }, body: { jsonrpc: '2.0', id: pingId, result: {} } })).status).toBe(202);
    await expect(pinged).resolves.toBeDefined();

    const sampled = sessionServer.server.createMessage({ messages: [{ role: 'user', content: { type: 'text', text: 'hi' } }], maxTokens: 10 });
    await vi.waitFor(() => expect(events.find(e => e.method === 'sampling/createMessage')).toBeDefined());
    const sampleId = events.find(e => e.method === 'sampling/createMessage')!.id;
    const text = 'family 👨‍👩‍👧 — می‌خواهم'; // ZWJ sequence; ZWNJ in Persian
    // Mutation: apply Layer 1's encoding check -> refused.
    const answer = { jsonrpc: '2.0', id: sampleId, result: { role: 'assistant', model: 'm', content: { type: 'text', text } } };
    expect((await send(r.port, { headers: { 'mcp-session-id': sid }, body: answer })).status).toBe(202);
    await expect(sampled).resolves.toMatchObject({ content: { text } });
    expect(validate).not.toHaveBeenCalled();
  });

  it('refuses a malformed response shape with 400', async () => {
    const r = await rig();
    const sid = await session(r);
    for (const body of [{ jsonrpc: '1.0', id: 1, result: {} }, { jsonrpc: '2.0', id: 1, result: {}, error: { code: 1, message: 'x' } }]) {
      expect((await send(r.port, { headers: { 'mcp-session-id': sid }, body })).status).toBe(400);
    }
  });

  it('meters responses per session: the 601st in a minute is 429 and another session on the key is unaffected', async () => {
    const r = await rig();
    const a = await session(r);
    const b = await session(r);
    const answer = (sid: string, i: number) => send(r.port, { headers: { 'mcp-session-id': sid }, body: { jsonrpc: '2.0', id: 100000 + i, result: {} } });
    // Mutation: meter per key -> session b is throttled too.
    for (let i = 0; i < 600; i++) expect((await answer(a, i)).status).not.toBe(429);
    const over = await answer(a, 600);
    expect(over.status).toBe(429);
    expect(over.headers['x-ratelimit-scope']).toBe('responses');
    expect((await answer(b, 0)).status).not.toBe(429);
  }, 30_000);
});

describe('Layer 5 and escape hatches over HTTP (Phase 1, HTTP halves)', () => {
  it('a renamed tool reaches Layer 5 under its current name in an HTTP session', async () => {
    const r = await rig({}, {
      setup: s => { s.tool('a', { q: z.string() }, async ({ q }) => ({ content: [{ type: 'text', text: q }] })).update({ name: 'b' }); }
    });
    const layer5 = r.server.validationPipeline.getLayerByClassName('ContextualValidationLayer') as unknown as { validateResponse: (...a: unknown[]) => Promise<unknown> };
    const spy = vi.spyOn(layer5, 'validateResponse').mockResolvedValue({ passed: true });
    const sid = await session(r);
    // Mutation: replay an unwrapped callback with a fresh name capture -> "a".
    const reply = await send(r.port, { headers: { 'mcp-session-id': sid }, body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'b', arguments: { q: 'x' } } } });
    expect(reply.status).toBe(200);
    expect(spy.mock.calls.map(c => (c[1] as { tool: string }).tool)).toEqual(['b']);
  });

  it('a tool registered through the escape hatch after the freeze reaches stdio only', async () => {
    const r = await rig({}, { setup: s => { s.tool('a', async () => ({ content: [] })); } });
    r.server.mcpServer.registerTool('raw', {}, async () => ({ content: [] }));
    const sid = await session(r);
    const list = await send(r.port, { headers: { 'mcp-session-id': sid }, body: { jsonrpc: '2.0', id: 4, method: 'tools/list' } });
    const names = (list.json as { result: { tools: Array<{ name: string }> } }).result.tools.map(t => t.name);
    expect(names).toEqual(['a']);
    expect(Object.keys(r.server._mcpServer['_registeredTools'])).toContain('raw');
  });
});

describe('failure visibility (C.6)', () => {
  it('a failure inside onsessioninitialized answers 404 with no internal text and releases the slot', async () => {
    const r = await rig();
    const proto = SessionRegistry.prototype as unknown as { holds: (e: unknown) => boolean };
    const real = proto.holds;
    let calls = 0;
    vi.spyOn(proto, 'holds').mockImplementation(function (this: unknown, e: unknown) {
      calls += 1;
      if (calls === 3) throw new Error('registry insert failed');
      return real.call(this, e);
    });
    // Mutation: drop the callback's try/catch -> the SDK answers 400 with the thrown text (probe 04).
    const reply = await send(r.port, { body: INIT() });
    expect(reply.status).toBe(404);
    expect(reply.text).not.toContain('registry insert failed');
    await vi.waitFor(() => expect(r.handler.sessionCount).toBe(0));
  });

  it('logs a protocol error once and keeps the session; a 5xx closes it', async () => {
    const logInfo = vi.fn();
    // The logger is read at handler construction, so it is in place before the handler.
    const server = new SecureMcpServer({ name: 'log', version: '1' }, { enableLogging: false, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'] });
    (server as unknown as { _securityLogger: unknown })._securityLogger = { logInfo, logError: vi.fn(), logSecurityDecision: vi.fn(), logDecision: vi.fn() };
    const handler = createSecureHttpHandler(server);
    const http = createServer(handler);
    await new Promise<void>(resolve => http.listen(0, '127.0.0.1', resolve));
    const addr = http.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    rigs.push({ server, handler, http, port, warnings: [], sessionServers: [] });
    const init = await send(port, { body: INIT() });
    const sid = init.headers['mcp-session-id'] as string;
    logInfo.mockClear();
    // A POST without the Accept the protocol requires: the SDK answers 406.
    const bad = await send(port, { headers: { 'mcp-session-id': sid, accept: 'application/json' }, body: PING });
    expect(bad.status).toBe(406);
    // Mutation: listen on both transport.onerror and Server.onerror -> two lines.
    expect(logInfo.mock.calls.filter(c => String(c[0]).startsWith('HTTP session'))).toHaveLength(1);
    expect((await send(port, { headers: { 'mcp-session-id': sid }, body: PING })).status).toBe(200);

    // A 5xx from the transport ends the session.
    const real = StreamableHTTPServerTransport.prototype.handleRequest;
    vi.spyOn(StreamableHTTPServerTransport.prototype, 'handleRequest').mockImplementation(async function (this: StreamableHTTPServerTransport, req, res, body) {
      if ((req as IncomingMessage).headers['x-fail']) { (res as unknown as { writeHead: (s: number) => { end: () => void } }).writeHead(500).end(); return; }
      return real.call(this, req, res, body);
    });
    expect((await send(port, { headers: { 'mcp-session-id': sid, 'x-fail': '1' }, body: PING })).status).toBe(500);
    // Mutation: drop the per-request status check -> the session survives.
    await vi.waitFor(async () => expect((await send(port, { headers: { 'mcp-session-id': sid }, body: PING })).status).toBe(404));
  });
});

describe('close paths against a GET whose client stopped reading (probe 13)', () => {
  /** A session with a GET stream that has stopped reading and ~4 MB queued. */
  async function stalled(port: number, sessionServers: McpServer[], sid: string, https = false): Promise<void> {
    const req = (https ? httpsRequest : request)({
      host: '127.0.0.1', port, path: '/mcp', method: 'GET', rejectUnauthorized: false,
      headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': '2025-06-18' }
    } as never, res => { res.pause(); res.socket.pause(); });
    open.add(req);
    req.on('error', () => {});
    req.end();
    await vi.waitFor(() => expect(sessionServers.length).toBeGreaterThan(0));
    await new Promise(resolve => setTimeout(resolve, 200));
    const big = 'x'.repeat(64 * 1024);
    // Not awaited one by one: against a peer that has stopped reading, a send can wait on
    // backpressure indefinitely, which once hung this helper before the path under test ran.
    for (let i = 0; i < 64; i++) void sessionServers.at(-1)!.server.notification({ method: 'notifications/message', params: { level: 'info', data: big } }).catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  const timed = async (p: Promise<unknown>) => { const t0 = Date.now(); await p; return Date.now() - t0; };

  it('handler.close() destroys the stalled GET and resolves within about 5 s', async () => {
    const r = await rig({}, { serverOptions: { capabilities: { logging: {} } } });
    const sid = await session(r);
    await stalled(r.port, r.sessionServers, sid);
    // Mutation: the routine calls only transport.close() -> never resolves (probe 13A).
    expect(await timed(r.handler.close())).toBeLessThan(7_000);
    expect(r.handler.sessionCount).toBe(0);
  }, 15_000);

  it('DELETE ends the session and the stalled GET is destroyed within about 5 s', async () => {
    const r = await rig({}, { serverOptions: { capabilities: { logging: {} } } });
    const sid = await session(r);
    await stalled(r.port, r.sessionServers, sid);
    expect((await send(r.port, { method: 'DELETE', headers: { 'mcp-session-id': sid } })).status).toBe(200);
    expect(r.handler.sessionCount).toBe(0);
    // Observed server-side: http.close() resolves only once every connection has ended,
    // the stalled GET's included. (A paused client socket never reads the server's FIN, so
    // its own 'close' event says nothing.) handler.close() alone would resolve either way:
    // the session is already gone. Mutation: no destroy() fallback -> never resolves.
    r.http.closeIdleConnections();
    expect(await timed(new Promise<void>(resolve => r.http.close(() => resolve())))).toBeLessThan(8_000);
  }, 15_000);

  for (const kind of ['http', 'https'] as const) {
    it(`create${kind === 'http' ? 'SecureHttp' : 'SecureHttps'}Server(...).close() closes sessions first and resolves`, async () => {
      const dir = mkdtempSync(path.join(tmpdir(), 'mss-close-'));
      try {
        const server = new SecureMcpServer({ name: 'c', version: '1' }, { enableLogging: false, capabilities: { logging: {} }, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL'] });
        const sessionServers: McpServer[] = [];
        const create = server._createSessionServer.bind(server);
        vi.spyOn(server, '_createSessionServer').mockImplementation(() => { const s = create(); sessionServers.push(s); return s; });
        let listener: Server;
        if (kind === 'https') {
          execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
            '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
          listener = createSecureHttpsServer(server, { key: readFileSync(path.join(dir, 'k.pem')), cert: readFileSync(path.join(dir, 'c.pem')) });
        } else {
          listener = createSecureHttpServer(server);
        }
        await new Promise<void>(resolve => listener.listen(0, '127.0.0.1', resolve));
        const addr = listener.address();
        const port = typeof addr === 'object' && addr ? addr.port : 0;
        const post = (body: unknown, sid?: string) => new Promise<IncomingMessage>((resolve, reject) => {
          const q = (kind === 'https' ? httpsRequest : request)({ host: '127.0.0.1', port, path: '/mcp', method: 'POST', rejectUnauthorized: false,
            headers: { 'content-type': 'application/json', accept: ACCEPT, 'mcp-protocol-version': '2025-06-18', ...(sid ? { 'mcp-session-id': sid } : {}) } } as never,
          res => { res.resume(); resolve(res); });
          open.add(q);
          q.on('error', reject);
          q.end(JSON.stringify(body));
        });
        const sid = (await post(INIT())).headers['mcp-session-id'] as string;
        await post({ jsonrpc: '2.0', method: 'notifications/initialized' }, sid);
        await stalled(port, sessionServers, sid, kind === 'https');
        // Mutation: wrap only the HTTP factory -> the HTTPS close never resolves;
        // close the registry from a 'close'-event listener -> never resolves.
        const elapsed = await timed(new Promise<void>(resolve => listener.close(() => resolve())));
        expect(elapsed).toBeLessThan(7_000);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }, 20_000);
  }
});

describe('notifications bypass chaining (D19): an id-less request-shaped message does no request work', () => {
  // D19 exempts messages without an `id` from Layer 4 chaining. That is safe only because
  // the SDK routes by id (protocol.js: isJSONRPCRequest vs isJSONRPCNotification) and an
  // id-less message reaches notification handlers only, so an id-less tools/call is
  // dropped. If an SDK release ever dispatched it as a request, D19 would become a chaining
  // bypass: these tests are what would say so (probe 21). paranoid enforces chaining, and
  // tools/call straight after initialize has no rule, so the control with an id is refused.
  // A fresh object per send: over the in-memory transport the server receives the sender's
  // object itself, so anything that writes to it would leak into the next test.
  const idless = () => ({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'a', arguments: {} } });

  it('over stdio: the tool does not run; the control with an id is refused by chaining', async () => {
    const ran: string[] = [];
    const server = new SecureMcpServer({ name: 'd19', version: '1' }, {
      securityLevel: 'paranoid', automationDetection: { enabled: false }, toolRegistry: [{ name: 'a', sideEffects: 'none' }]
    });
    server.tool('a', async () => { ran.push('a'); return { content: [] }; });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: 'c', version: '1' });
    try {
      await client.connect(clientTransport);
      await clientTransport.send(idless() as never);
      await new Promise(resolve => setTimeout(resolve, 100));
      // Mutation: dispatch id-less messages as requests (give them an id) -> the tool runs.
      expect(ran).toEqual([]);
      // The control must be refused by chaining, not by another paranoid check (Layer 3's
      // automation timing refused it on the first draft, which proved nothing about D19).
      await expect(client.callTool({ name: 'a', arguments: {} })).rejects.toMatchObject({ data: { layer: 'CHAIN_VIOLATION' } });
      expect(ran).toEqual([]);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it('over HTTP: 202 and the tool does not run; the control with an id is refused by chaining', async () => {
    const ran: string[] = [];
    const r = await rig({}, {
      serverOptions: { securityLevel: 'paranoid', automationDetection: { enabled: false } },
      setup: s => { s.tool('a', async () => { ran.push('a'); return { content: [] }; }); }
    });
    const sid = await session(r);
    const reply = await send(r.port, { headers: { 'mcp-session-id': sid }, body: idless() });
    await new Promise(resolve => setTimeout(resolve, 100));
    // Mutation: dispatch id-less messages as requests (give them an id) -> the tool runs.
    expect(reply.status).toBe(202);
    expect(ran).toEqual([]);
    const control = await send(r.port, { headers: { 'mcp-session-id': sid }, body: { ...idless(), id: 5 } });
    expect(control.status).toBe(400);
    expect(JSON.stringify(control.json)).toContain('CHAIN_VIOLATION');
    expect(ran).toEqual([]);
  });
});

describe('two handlers on one server', () => {
  it('both attach; a registration after either throws; closing one does not unfreeze the server', async () => {
    const server = new SecureMcpServer({ name: 'two', version: '1' }, { enableLogging: false, silenceWarnings: ['MCP_SECURE_SERVER_HTTP_EXPERIMENTAL', 'MCP_SECURE_SERVER_LATE_REGISTRATION'] });
    server.tool('a', async () => ({ content: [] }));
    const one = createSecureHttpHandler(server);
    const two = createSecureHttpHandler(server);
    expect(() => server.tool('late', async () => ({ content: [] }))).toThrow(LateRegistrationError);
    await one.close();
    // Mutation: unfreeze on handler.close() -> this registration succeeds.
    expect(() => server.tool('later', async () => ({ content: [] }))).toThrow(LateRegistrationError);
    await two.close();
    expect(server._httpRegistries.size).toBe(0);
  });
});
