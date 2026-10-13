/**
 * Per-session bookkeeping for the HTTP transport (spec http-transport-per-session v0.4.3,
 * section B): one McpServer + one stateful StreamableHTTPServerTransport per MCP session,
 * server-issued ids, caps, idle eviction, GET stream age, and one close routine for every
 * path that ends a session. HTTP request policy (Origin, lockout, the pipeline for
 * non-initialize requests) lives in the request flow, not here.
 *
 * Through 0.0.27 the handler shared one stateless SDK transport, which the SDK refuses to
 * reuse: every request after the first answered 500 (issue 4bf30630).
 */

import { createHash, randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/** Session bounds (D1). Distinct from Layer 4's `maxSessions` / `sessionTtlMs`, which bound chaining state. */
export interface SessionRegistryOptions {
  /** Reserved + live sessions on this handler (default 1000). */
  maxHttpSessions?: number;
  /** Reserved + live sessions per rate-limit key (default 10). */
  maxHttpSessionsPerClient?: number;
  /** A live session with no request in flight is closed after this long (default 30 min). */
  httpSessionIdleTtlMs?: number;
}

/** What the handler supplies. */
export interface SessionRegistryDeps {
  /** A fresh McpServer carrying the frozen registration set. */
  createSessionServer(): McpServer;
  /** Layer 4: drop the chaining state of an ended session (idempotent). */
  releaseSession?(sessionId: string): void;
  /** Write a refusal (503) with the handler's security headers. */
  refuse(res: ServerResponse, status: number, message: string, headers: Record<string, string>): void;
  /** Info-level log line; session ids arrive redacted. */
  log?(message: string): void;
  /** Called once when the registry has closed, so the server can forget it. */
  onClosed?(): void;
}

interface OpenGet { res: ServerResponse; ageTimer: NodeJS.Timeout; closed: boolean }

interface SessionEntry {
  readonly id: string;
  readonly clientKey: string;
  state: 'reserved' | 'live';
  mcpServer?: McpServer;
  transport?: StreamableHTTPServerTransport;
  reservedAt: number;
  createdAt?: number;
  lastSeenAt: number;
  inFlight: number;
  openGets: Set<OpenGet>;
  detached: boolean;
  settling?: Promise<void>;
}

const SWEEP_INTERVAL_MS = 30_000;
const RESERVATION_RECLAIM_MS = 60_000;
const EVICTABLE_IDLE_MS = 60_000;
const STREAM_MAX_AGE_MS = 30 * 60_000;
const DESTROY_GRACE_MS = 5_000;

/** The 12-hex-character form session ids take in logs; a raw id is a bearer credential. */
export function redactSessionId(id: string): string {
  return createHash('sha256').update(id).digest('hex').slice(0, 12);
}

function positiveInteger(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${name} must be a positive integer (got ${String(value)})`);
  }
  return value;
}

/** One handler's sessions. */
export class SessionRegistry {
  private readonly sessions = new Map<string, SessionEntry>();
  private readonly maxSessions: number;
  private readonly maxPerClient: number;
  private readonly idleTtlMs: number;
  private readonly sweepTimer: NodeJS.Timeout;
  private closing: Promise<void> | null = null;

  constructor(private readonly deps: SessionRegistryDeps, options: SessionRegistryOptions = {}) {
    this.maxSessions = positiveInteger('maxHttpSessions', options.maxHttpSessions ?? 1000);
    this.maxPerClient = positiveInteger('maxHttpSessionsPerClient', options.maxHttpSessionsPerClient ?? 10);
    this.idleTtlMs = positiveInteger('httpSessionIdleTtlMs', options.httpSessionIdleTtlMs ?? 30 * 60_000);
    this.sweepTimer = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    this.sweepTimer.unref();
  }

  /** Reserved + live sessions. */
  get sessionCount(): number { return this.sessions.size; }

  /** Whether `id` names a live session. */
  has(id: string): boolean { return this.sessions.get(id)?.state === 'live'; }

  /**
   * A POST `initialize` without a session header. The slot is reserved before any await;
   * `admit(id)` runs the pipeline with the reserved id and returns false after writing its
   * own refusal. Whatever happens, an entry that is not live when this returns is released.
   */
  async initialize(
    req: IncomingMessage, res: ServerResponse, body: unknown, clientKey: string,
    admit: (sessionId: string) => Promise<boolean>
  ): Promise<void> {
    const entry = this.reserve(res, clientKey);
    if (!entry) return;
    try {
      if (!(await admit(entry.id))) return;
      if (!this.holds(entry)) return this.refuseReclaimed(res);
      const server = this.deps.createSessionServer();
      entry.mcpServer = server;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => entry.id,
        onsessioninitialized: id => this.onInitialized(id, entry),
        onsessionclosed: () => this.detach(entry)
      });
      entry.transport = transport;
      // Before connect: Protocol.connect chains only handlers that already exist.
      transport.onclose = () => { this.detach(entry); void this.settleStreams(entry); };
      server.server.onerror = error =>
        this.deps.log?.(`HTTP session ${redactSessionId(entry.id)}: ${error instanceof Error ? error.message : String(error)}`);
      await server.connect(transport);
      if (!this.holds(entry)) return this.refuseReclaimed(res);
      await this.track(entry, req, res, () => transport.handleRequest(req, res, body), true);
    } finally {
      if (entry.state !== 'live') void this.closeSession(entry);
    }
  }

  /** A request on a known session. Returns false if `id` is not a live session (the caller answers 404). */
  async handle(id: string, req: IncomingMessage, res: ServerResponse, body?: unknown): Promise<boolean> {
    const entry = this.sessions.get(id);
    if (!entry || entry.state !== 'live' || !entry.transport) return false;
    const transport = entry.transport;
    if (req.method === 'GET') this.trackGet(entry, res);
    await this.track(entry, req, res, () => transport.handleRequest(req, res, body), false);
    // The stateful SDK answers 500 only when the transport itself failed (tool errors are
    // 200 isError), so a 5xx ends the session; its other in-flight calls are aborted.
    if (res.statusCode >= 500) void this.closeSession(entry);
    return true;
  }

  /** Refuse new sessions, release reservations, close every live session; resolves when every GET has closed. */
  close(): Promise<void> {
    if (this.closing) return this.closing;
    clearInterval(this.sweepTimer);
    this.closing = Promise.all([...this.sessions.values()].map(entry => this.closeSession(entry)))
      .then(() => { this.deps.onClosed?.(); });
    return this.closing;
  }

  private holds(entry: SessionEntry): boolean {
    return !entry.detached && this.sessions.get(entry.id) === entry;
  }

  /** Cap check and reservation in one synchronous step (B, D7). */
  private reserve(res: ServerResponse, clientKey: string): SessionEntry | null {
    if (this.closing) {
      this.deps.refuse(res, 503, 'Server is shutting down', { 'X-RateLimit-Scope': 'sessions', 'Retry-After': '60' });
      return null;
    }
    if (this.sessions.size >= this.maxSessions) {
      this.deps.refuse(res, 503, 'Too many sessions', { 'X-RateLimit-Scope': 'sessions', 'Retry-After': '60' });
      return null;
    }
    const now = Date.now();
    const own = [...this.sessions.values()].filter(e => e.clientKey === clientKey);
    if (own.length >= this.maxPerClient) {
      const victim = own
        .filter(e => e.state === 'live' && e.inFlight === 0 && now - e.lastSeenAt >= EVICTABLE_IDLE_MS)
        .sort((a, b) => a.lastSeenAt - b.lastSeenAt)[0];
      if (!victim) {
        this.deps.refuse(res, 503,
          'Too many sessions for this client. If many users reach this server through one proxy or NAT, ' +
          'they share one key: list the proxy in trustProxy rather than raising maxHttpSessionsPerClient.',
          { 'X-RateLimit-Scope': 'client-sessions', 'Retry-After': '60' });
        return null;
      }
      void this.closeSession(victim); // detaches synchronously, so the slot is free now
    }
    const entry: SessionEntry = {
      id: randomUUID(), clientKey, state: 'reserved', reservedAt: now, lastSeenAt: now,
      inFlight: 1, openGets: new Set(), detached: false
    };
    this.sessions.set(entry.id, entry);
    return entry;
  }

  /** Awaited by the SDK before it processes `initialize`. Never throws. */
  private onInitialized(id: string, entry: SessionEntry): void {
    try {
      if (id !== entry.id || !this.holds(entry)) {
        // Reclaimed after handleRequest started: the client sees 404, no internal text.
        this.deps.log?.(`HTTP session ${redactSessionId(id)} was reclaimed before it initialized`);
        void entry.transport?.close();
        return;
      }
      entry.createdAt = Date.now();
      entry.state = 'live';
    } catch (error) {
      this.deps.log?.(`HTTP session ${redactSessionId(id)} failed to initialize: ${String(error)}`);
      void entry.transport?.close();
    }
  }

  private refuseReclaimed(res: ServerResponse): void {
    if (!res.headersSent) {
      this.deps.refuse(res, 503, 'Session reservation expired', { 'X-RateLimit-Scope': 'sessions', 'Retry-After': '1' });
    }
  }

  /** Count a request from entry until the first of handleRequest settling or the response closing. */
  private async track(
    entry: SessionEntry, _req: IncomingMessage, res: ServerResponse, run: () => Promise<void>, counted: boolean
  ): Promise<void> {
    if (!counted) entry.inFlight += 1;
    entry.lastSeenAt = Date.now();
    let released = false;
    const release = (): void => {
      if (released) return;
      released = true;
      entry.inFlight -= 1;
      entry.lastSeenAt = Date.now();
    };
    res.once('close', release);
    try { await run(); } finally { release(); }
  }

  /**
   * A timer per GET response (D13): at 30 minutes the transport's standalone stream is
   * closed, and the response destroyed if it has not closed 5 s later. A GET the SDK
   * refuses (409) closes at once and clears its own timer, so it cannot touch the open
   * stream's age.
   */
  private trackGet(entry: SessionEntry, res: ServerResponse): void {
    const get: OpenGet = {
      res, closed: false,
      ageTimer: setTimeout(() => {
        if (get.closed) return;
        entry.transport?.closeStandaloneSSEStream();
        this.destroyAfterGrace(get);
      }, STREAM_MAX_AGE_MS)
    };
    get.ageTimer.unref();
    entry.openGets.add(get);
    res.once('close', () => {
      get.closed = true;
      clearTimeout(get.ageTimer);
      entry.openGets.delete(get);
    });
  }

  private destroyAfterGrace(get: OpenGet): void {
    setTimeout(() => { if (!get.closed) get.res.destroy(); }, DESTROY_GRACE_MS).unref();
  }

  /** Remove from the map and release Layer 4 state, once. */
  private detach(entry: SessionEntry): void {
    if (entry.detached) return;
    entry.detached = true;
    if (this.sessions.get(entry.id) === entry) this.sessions.delete(entry.id);
    this.deps.releaseSession?.(entry.id);
  }

  /**
   * Every open GET settles: no SDK close settles a GET whose peer stopped reading
   * (probe 13A/B), so each is destroyed if it has not closed 5 s later.
   */
  private settleStreams(entry: SessionEntry): Promise<void> {
    entry.settling ??= Promise.all([...entry.openGets].map(get => new Promise<void>(resolve => {
      if (get.closed) return resolve();
      get.res.once('close', () => resolve());
      clearTimeout(get.ageTimer);
      this.destroyAfterGrace(get);
    }))).then(() => {});
    return entry.settling;
  }

  /** The one close routine: DELETE aside, every path that ends a session comes here. */
  private async closeSession(entry: SessionEntry): Promise<void> {
    this.detach(entry);
    const streams = this.settleStreams(entry);
    try { await entry.mcpServer?.close(); } catch { /* closing is best effort; streams still settle */ }
    await streams;
  }

  private sweep(): void {
    const now = Date.now();
    for (const entry of [...this.sessions.values()]) {
      const expired = entry.state === 'reserved'
        ? now - entry.reservedAt > RESERVATION_RECLAIM_MS
        : entry.inFlight === 0 && now - entry.lastSeenAt > this.idleTtlMs;
      if (expired) void this.closeSession(entry);
    }
  }
}
