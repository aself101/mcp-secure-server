/**
 * SessionRegistry (spec http-transport-per-session v0.4.3, section B; checklist Phase 2).
 *
 * Driven through a real node:http server whose handler calls the registry directly — the
 * request flow (Origin, lockout, pipeline for non-initialize requests) is Phase 3a's, so
 * nothing here asserts on it. Raw node:http requests, not the SDK client, so the fake
 * timers below (Date, setTimeout, setInterval) touch the registry and the SDK server only.
 * Each test names the mutation that must make it fail; they were run when it was written.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { createServer, request } from 'node:http';
import type { Server, IncomingMessage, ServerResponse, ClientRequest } from 'node:http';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SessionRegistry, type SessionRegistryOptions } from '../../../src/security/transport/session-registry.js';

type Admit = (id: string, res: ServerResponse) => Promise<boolean>;
interface Harness {
  registry: SessionRegistry; port: number; server: Server;
  released: string[]; toolSignals: AbortSignal[];
  admit: { fn: Admit };
}

const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } };
const INITIALIZED = { jsonrpc: '2.0', method: 'notifications/initialized' };
const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

let harness: Harness | null = null;
const sockets = new Set<ClientRequest>();

async function start(options: SessionRegistryOptions = {}): Promise<Harness> {
  const released: string[] = [];
  const toolSignals: AbortSignal[] = [];
  const admit = { fn: (async () => true) as Admit };
  const registry = new SessionRegistry({
    createSessionServer: () => {
      const s = new McpServer({ name: 'reg', version: '1' }, { capabilities: { logging: {} } });
      s.tool('slow', async (extra) => {
        toolSignals.push(extra.signal);
        await new Promise(resolve => extra.signal.addEventListener('abort', resolve));
        return { content: [] };
      });
      return s;
    },
    releaseSession: id => { released.push(id); },
    refuse: (res, status, message, headers) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }).end(JSON.stringify({ error: message })); }
  }, options);
  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
    const sid = req.headers['mcp-session-id'] as string | undefined;
    const key = (req.headers['x-key'] as string | undefined) ?? 'k';
    try {
      if (sid) {
        if (!(await registry.handle(sid, req, res, body))) res.writeHead(404).end();
      } else {
        await registry.initialize(req, res, body, key, id => admit.fn(id, res));
      }
    } catch {
      if (!res.headersSent) res.writeHead(500).end();
    }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  harness = { registry, server, released, toolSignals, admit, port: typeof addr === 'object' && addr ? addr.port : 0 };
  return harness;
}

afterEach(async () => {
  vi.useRealTimers();
  for (const s of sockets) s.destroy();
  sockets.clear();
  if (harness) {
    harness.server.closeAllConnections();
    await harness.registry.close();
    await new Promise<void>(resolve => harness!.server.close(() => resolve()));
    harness = null;
  }
});

interface Reply { status: number; headers: IncomingMessage['headers']; text: string }
function post(h: Harness, body: unknown, opts: { sid?: string; key?: string; accept?: string } = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const q = request({
      host: '127.0.0.1', port: h.port, method: 'POST', path: '/mcp',
      headers: {
        'content-type': 'application/json',
        accept: opts.accept ?? 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-06-18',
        ...(opts.sid ? { 'mcp-session-id': opts.sid } : {}),
        ...(opts.key ? { 'x-key': opts.key } : {})
      }
    }, res => {
      let text = '';
      res.on('data', c => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text }));
    });
    sockets.add(q);
    q.on('error', reject);
    q.end(JSON.stringify(body));
  });
}
function del(h: Harness, sid: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const q = request({ host: '127.0.0.1', port: h.port, method: 'DELETE', path: '/mcp', headers: { 'mcp-session-id': sid, 'mcp-protocol-version': '2025-06-18' } },
      res => { res.resume(); res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, text: '' })); });
    sockets.add(q);
    q.on('error', reject);
    q.end();
  });
}
/** Open a GET stream; `paused` stops reading (a peer that stopped reading). */
function openGet(h: Harness, sid: string, paused = false): Promise<{ status: number; req: ClientRequest; ended: Promise<void> }> {
  return new Promise((resolve, reject) => {
    const q = request({ host: '127.0.0.1', port: h.port, method: 'GET', path: '/mcp', headers: { accept: 'text/event-stream', 'mcp-session-id': sid, 'mcp-protocol-version': '2025-06-18' } }, res => {
      const ended = new Promise<void>(done => { res.on('close', () => done()); res.on('end', () => done()); });
      if (paused) { res.pause(); res.socket.pause(); } else res.resume();
      resolve({ status: res.statusCode ?? 0, req: q, ended });
    });
    sockets.add(q);
    q.on('error', () => {});
    q.on('error', reject);
    q.end();
  });
}
async function session(h: Harness, key = 'k'): Promise<string> {
  const r = await post(h, INIT, { key });
  expect(r.status).toBe(200);
  const sid = r.headers['mcp-session-id'] as string;
  expect((await post(h, INITIALIZED, { sid, key })).status).toBe(202);
  return sid;
}
const entries = (h: Harness) => (h.registry as unknown as { sessions: Map<string, { inFlight: number; state: string; mcpServer?: McpServer }> }).sessions;
const io = (ms = 20) => new Promise(resolve => setImmediate(() => setTimeout(resolve, ms)));
function fakeTime() { vi.useFakeTimers({ toFake: ['Date', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval'], now: Date.now() }); }
/**
 * Let socket I/O run without leaving fake time: setImmediate is not faked, and switching to
 * real timers would discard the registry's fake sweep interval (which once made a "not swept
 * yet" assertion pass vacuously). With `stepMs`, fake time also advances between checks.
 */
async function settle(cond: () => boolean, stepMs = 0, max = 400): Promise<void> {
  for (let i = 0; i < max && !cond(); i++) {
    if (stepMs) await vi.advanceTimersByTimeAsync(stepMs);
    await new Promise(resolve => setImmediate(resolve));
  }
  expect(cond()).toBe(true);
}
const inFlight = (h: Harness, sid: string) => entries(h).get(sid)!.inFlight;

describe('reservation and release', () => {
  it('admits one of N concurrent initializes at cap-1', async () => {
    const h = await start({ maxHttpSessionsPerClient: 3 });
    await session(h); await session(h);
    let release!: () => void;
    const gate = new Promise<void>(r => { release = r; });
    const admitted: string[] = [];
    h.admit.fn = async id => { admitted.push(id); await gate; return true; };
    // Mutation: check the cap without reserving -> all four reach admit.
    const replies = Promise.all([0, 1, 2, 3].map(() => post(h, INIT)));
    await io();
    expect(admitted).toHaveLength(1);
    release();
    const statuses = (await replies).map(r => r.status).sort();
    expect(statuses).toEqual([200, 503, 503, 503]);
  });

  it('releases the slot on pipeline reject, pipeline throw, a 406 and a callback failure', async () => {
    const h = await start();
    // Mutation: release only on pipeline reject -> each other case leaves an entry.
    h.admit.fn = async (_id, res) => { res.writeHead(403).end(); return false; }; // the pipeline refused
    expect((await post(h, INIT)).status).toBe(403);
    expect(h.registry.sessionCount).toBe(0);

    h.admit.fn = async () => { throw new Error('pipeline threw'); };
    expect((await post(h, INIT)).status).toBe(500);
    expect(h.registry.sessionCount).toBe(0);

    h.admit.fn = async () => true;
    expect((await post(h, INIT, { accept: 'application/json' })).status).toBe(406);
    await io();
    expect(h.registry.sessionCount).toBe(0);

    const holds = vi.spyOn(h.registry as unknown as { holds: () => boolean }, 'holds');
    holds.mockImplementationOnce(() => true).mockImplementationOnce(() => true).mockImplementationOnce(() => false);
    expect((await post(h, INIT)).status).toBe(404); // reclaimed before the SDK's callback: no internal text
    await io();
    expect(h.registry.sessionCount).toBe(0);
  });

  it('reclaims a reservation whose pipeline never settles within 60-90 s', async () => {
    fakeTime();
    const h = await start();
    h.admit.fn = () => new Promise<boolean>(() => {});
    void post(h, INIT).catch(() => {});
    await vi.waitFor(() => expect(h.registry.sessionCount).toBe(1));
    await vi.advanceTimersByTimeAsync(59_000);
    expect(h.registry.sessionCount).toBe(1);
    // Mutation: the sweep skips reserved entries -> still 1.
    await vi.advanceTimersByTimeAsync(31_000);
    expect(h.registry.sessionCount).toBe(0);
  });

  it('close() during a reservation leaves no session when the pipeline settles', async () => {
    const h = await start();
    let release!: (v: boolean) => void;
    h.admit.fn = () => new Promise<boolean>(r => { release = r; });
    const reply = post(h, INIT);
    await io();
    const closed = h.registry.close();
    // Mutation: close() ignores reserved entries -> a session appears.
    release(true);
    expect((await reply).status).toBe(503);
    await closed;
    expect(h.registry.sessionCount).toBe(0);
    expect((await post(h, INIT)).status).toBe(503);
  });
});

describe('caps', () => {
  it('refuses at the global cap with scope "sessions" and leaves live sessions answering', async () => {
    const h = await start({ maxHttpSessions: 2 });
    const a = await session(h, 'a'); await session(h, 'b');
    const r = await post(h, INIT, { key: 'c' });
    expect(r.status).toBe(503);
    expect(r.headers['x-ratelimit-scope']).toBe('sessions');
    expect(r.headers['retry-after']).toBeDefined();
    expect((await post(h, LIST, { sid: a, key: 'a' })).status).toBe(200);
  });

  it('per-key cap: evicts the key\'s own session idle 60 s, never another key\'s nor a fresher one', async () => {
    fakeTime();
    const h = await start({ maxHttpSessionsPerClient: 2 });
    const other = await session(h, 'other');
    const old = await session(h, 'k');
    await vi.advanceTimersByTimeAsync(61_000);
    const fresh = await session(h, 'k');
    // Mutation: evict the globally oldest -> 'other' goes.
    const third = await post(h, INIT, { key: 'k' });
    expect(third.status).toBe(200);
    expect(h.registry.has(old)).toBe(false);
    expect(h.registry.has(other)).toBe(true);
    expect(h.registry.has(fresh)).toBe(true);
    // Now both of k's are fresher than 60 s: 503 with the per-key scope.
    // Mutation: one 503 body for both caps -> the scope assertion fails.
    const fourth = await post(h, INIT, { key: 'k' });
    expect(fourth.status).toBe(503);
    expect(fourth.headers['x-ratelimit-scope']).toBe('client-sessions');
    expect(fourth.text).toContain('trustProxy');
  });

  it('per-key cap with every session holding a GET: 503 every time, and the sessions still answer', async () => {
    fakeTime();
    const h = await start({ maxHttpSessionsPerClient: 2 });
    const s1 = await session(h); const s2 = await session(h);
    await openGet(h, s1); await openGet(h, s2);
    await vi.advanceTimersByTimeAsync(120_000);
    for (let i = 0; i < 20; i++) {
      const r = await post(h, INIT);
      expect(r.status).toBe(503);
    }
    expect((await post(h, LIST, { sid: s1 })).status).toBe(200);
    expect((await post(h, LIST, { sid: s2 })).status).toBe(200);
  });

  it('makes a session that never opened a GET evictable after 60 s idle', async () => {
    fakeTime();
    const h = await start({ maxHttpSessionsPerClient: 1 });
    const abandoned = await session(h);
    // Mutation: count a session with no GET as in flight -> never evictable (503).
    await vi.advanceTimersByTimeAsync(61_000);
    expect((await post(h, INIT)).status).toBe(200);
    expect(h.registry.has(abandoned)).toBe(false);
  });
});

describe('in-flight accounting and idle', () => {
  it('keeps a session with an open GET past the TTL; a client abort brings inFlight to exactly 0', async () => {
    fakeTime();
    const h = await start({ httpSessionIdleTtlMs: 60_000 });
    const sid = await session(h);
    const get = await openGet(h, sid);
    // Mutation: ignore inFlight in the sweep -> evicted.
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    expect(h.registry.has(sid)).toBe(true);
    get.req.destroy();
    // Mutation: drop the close trigger -> stays 1; decrement on both triggers -> -1.
    await settle(() => inFlight(h, sid) <= 0);
    await settle(() => true, 0, 20);
    expect(inFlight(h, sid)).toBe(0);
  });

  it('releases inFlight on the response close when handleRequest never settles', async () => {
    // On SDK 1.30 handleRequest settles when its response ends (probe 17), so the close
    // trigger is defence in depth; this stands in for a transport that does not settle.
    const h = await start();
    const sid = await session(h);
    const transport = (entries(h).get(sid) as unknown as { transport: { handleRequest: (...a: unknown[]) => Promise<void> } }).transport;
    const real = transport.handleRequest.bind(transport);
    transport.handleRequest = (...args: unknown[]) => { void real(...args); return new Promise<void>(() => {}); };
    const get = await openGet(h, sid);
    expect(inFlight(h, sid)).toBe(1);
    get.req.destroy();
    // Mutation: drop the close trigger -> stays 1.
    await settle(() => inFlight(h, sid) === 0);
  });

  it('does not sweep a GET that outlived the TTL until a full TTL after it dropped', async () => {
    fakeTime();
    const h = await start({ httpSessionIdleTtlMs: 60_000 });
    const sid = await session(h);
    const get = await openGet(h, sid);
    await vi.advanceTimersByTimeAsync(10 * 60_000);
    get.req.destroy();
    await settle(() => inFlight(h, sid) === 0);
    // Mutation: stamp lastSeenAt at entry only -> swept on the next tick.
    await vi.advanceTimersByTimeAsync(31_000);
    expect(h.registry.has(sid)).toBe(true);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(h.registry.has(sid)).toBe(false);
  });

  it('aborting a POST mid-tool releases inFlight at once; D7 can then evict and the tool is aborted', async () => {
    fakeTime();
    const h = await start({ maxHttpSessionsPerClient: 1 });
    const sid = await session(h);
    const call = post(h, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'slow', arguments: {} } }, { sid });
    call.catch(() => {});
    await vi.waitFor(() => expect(h.toolSignals).toHaveLength(1));
    for (const s of sockets) s.destroy();
    await settle(() => inFlight(h, sid) === 0);
    expect(h.toolSignals[0]!.aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(61_000);
    expect((await post(h, INIT)).status).toBe(200);
    expect(h.registry.has(sid)).toBe(false);
    await vi.waitFor(() => expect(h.toolSignals[0]!.aborted).toBe(true));
  });
});

describe('GET stream age', () => {
  it('closes a GET at 30 minutes; the session survives and inFlight returns to 0', async () => {
    fakeTime();
    const h = await start({ httpSessionIdleTtlMs: 60 * 60_000 });
    const sid = await session(h);
    const get = await openGet(h, sid);
    // Mutation: no stream-age timer -> the stream stays open.
    let ended = false; void get.ended.then(() => { ended = true; });
    await vi.advanceTimersByTimeAsync(30 * 60_000 - 1_000);
    await settle(() => true, 0, 50);
    expect(ended).toBe(false);
    await settle(() => ended, 100);
    expect(h.registry.has(sid)).toBe(true);
    await settle(() => inFlight(h, sid) === 0);
  });

  it('gives a reopened stream its own 30 minutes; a 409 GET leaves the open stream\'s age alone', async () => {
    fakeTime();
    const h = await start({ httpSessionIdleTtlMs: 60 * 60_000 });
    const sid = await session(h);
    const first = await openGet(h, sid);
    await vi.advanceTimersByTimeAsync(20 * 60_000);
    const refused = await openGet(h, sid);
    expect(refused.status).toBe(409);
    // Mutation: one timer per session, reset on every GET -> the 409 resets it to 30 min from now.
    let firstEnded = false; void first.ended.then(() => { firstEnded = true; });
    await vi.advanceTimersByTimeAsync(10 * 60_000 - 2_000);
    await settle(() => true, 0, 50);
    expect(firstEnded).toBe(false);
    await settle(() => firstEnded, 100); // closes at 30 min from ITS open, not 30 min from the 409
    await settle(() => inFlight(h, sid) === 0);
    const second = await openGet(h, sid);
    expect(second.status).toBe(200);
    let ended = false; void second.ended.then(() => { ended = true; });
    await vi.advanceTimersByTimeAsync(29 * 60_000);
    await settle(() => true, 0, 50);
    expect(ended).toBe(false);
    await settle(() => ended, 500); // its own 30 minutes
  });

  it('destroys a GET whose peer stopped reading, 5 s after the stream-age close', async () => {
    fakeTime();
    const h = await start({ httpSessionIdleTtlMs: 60 * 60_000 });
    const sid = await session(h);
    await openGet(h, sid, true);
    const big = 'x'.repeat(64 * 1024);
    const server = entries(h).get(sid)!.mcpServer!;
    for (let i = 0; i < 64; i++) await server.server.notification({ method: 'notifications/message', params: { level: 'info', data: big } }).catch(() => {});
    await vi.advanceTimersByTimeAsync(30 * 60_000 + 1_000);
    await settle(() => true, 0, 50);
    expect(inFlight(h, sid)).toBe(1);
    // Mutation: drop the destroy() fallback -> inFlight stays 1.
    await vi.advanceTimersByTimeAsync(5_000);
    await settle(() => inFlight(h, sid) === 0);
  });
});

describe('removal', () => {
  it('removes on DELETE once, and on a transport close once', async () => {
    const h = await start();
    const a = await session(h);
    expect((await del(h, a)).status).toBe(200);
    await io();
    expect(h.registry.has(a)).toBe(false);
    // Mutation: non-idempotent removal -> releaseSession runs twice (onsessionclosed + onclose).
    expect(h.released.filter(id => id === a)).toHaveLength(1);
    const b = await session(h);
    await entries(h).get(b)!.mcpServer!.close(); // the transport closes without a DELETE
    // Mutation: remove only on onsessionclosed -> b stays.
    expect(h.registry.has(b)).toBe(false);
    expect(h.released.filter(id => id === b)).toHaveLength(1);
  });

  it('DELETE during an in-flight tool call fires its AbortSignal', async () => {
    const h = await start();
    const sid = await session(h);
    void post(h, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'slow', arguments: {} } }, { sid }).catch(() => {});
    await vi.waitFor(() => expect(h.toolSignals).toHaveLength(1));
    // Mutation: assign onclose after connect -> the signal never fires.
    expect((await del(h, sid)).status).toBe(200);
    await vi.waitFor(() => expect(h.toolSignals[0]!.aborted).toBe(true));
  });

  it('close() resolves once every GET has closed, a stalled one included', async () => {
    const h = await start();
    const sid = await session(h);
    await openGet(h, sid, true);
    const server = entries(h).get(sid)!.mcpServer!;
    const big = 'x'.repeat(64 * 1024);
    for (let i = 0; i < 64; i++) await server.server.notification({ method: 'notifications/message', params: { level: 'info', data: big } }).catch(() => {});
    const t0 = Date.now();
    await h.registry.close();
    expect(Date.now() - t0).toBeLessThan(7_000);
    expect(h.registry.sessionCount).toBe(0);
  }, 15_000);
});
