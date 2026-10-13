/**
 * Operation log and freeze for SecureMcpServer registrations (spec
 * http-transport-per-session, section A).
 *
 * Every registration call, `registerCapabilities`, and every call or field write
 * through a returned handle is applied to the primary McpServer first and appended
 * to one chronological log only if it returned without throwing. A session server
 * is built by replaying that log, in order, through its own SDK handles, which
 * reproduces the primary exactly — SDK handle defects included (issue 7f3ec293;
 * probe 12). Nothing here models identity: it records what was called.
 *
 * The freeze makes the registration set immutable once an HTTP handler is
 * attached, so every session serves the set in force at attach and nothing has to
 * reach a live session after it is built.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WARNING_CODES, type WarningChannel } from './warnings.js';

/** The registration methods routed through the log. */
export type RegistrationMethod =
  'tool' | 'registerTool' | 'resource' | 'registerResource' | 'prompt' | 'registerPrompt';

/** A tool's current name, read by its Layer 5 wrapper when the tool runs. */
export interface NameRef { name: string }

type AnyFn = (...args: unknown[]) => unknown;

type Entry =
  | { kind: 'register'; method: RegistrationMethod; args: unknown[] }
  | { kind: 'call'; target: number; method: string; args: unknown[] }
  | { kind: 'set'; target: number; prop: PropertyKey; value: unknown }
  | { kind: 'capabilities'; capabilities: unknown };

interface Slot { handle: unknown; ref: NameRef | undefined; name: string | undefined }

const HANDLE_METHODS = new Set<PropertyKey>(['update', 'enable', 'disable', 'remove']);

/**
 * Thrown by any registration, `registerCapabilities`, or handle call or write once
 * an HTTP handler is attached to the server. `registrationName` is the name the
 * call targeted (the field is not `name`, which `Error` reserves for the class).
 */
export class LateRegistrationError extends Error {
  readonly method: string;
  readonly registrationName: string | undefined;

  constructor(method: string, registrationName: string | undefined) {
    const target = registrationName === undefined ? '' : ` (${JSON.stringify(registrationName)})`;
    super(
      `${method}${target} was called after an HTTP handler was attached; registrations are frozen ` +
      'from then on, so every HTTP session serves the same set. Register everything before creating ' +
      'the handler. A handle toggled at runtime (dynamic tools) cannot be used once a handler is ' +
      'attached; such a server stays on stdio. A kill switch belongs in the tool\'s callback (check a ' +
      'flag and return an error): a disable() or remove() that throws leaves the tool callable, and ' +
      'catching this error does not change that. Registrations made through server.server, ' +
      'server.mcpServer or server.experimental reach stdio only, never HTTP sessions, so they are ' +
      'not a way around the freeze.'
    );
    this.name = 'LateRegistrationError';
    this.method = method;
    this.registrationName = registrationName;
  }
}

/** What the owning server supplies. */
export interface RegistrationLogHooks {
  /** Wrap a tool callback for Layer 5; the wrapper reads `ref.name` at call time. */
  wrapTool(ref: NameRef, callback: unknown): unknown;
  /** The server's warning channel: late registrations (counted) and escape-hatch use. */
  warnings: WarningChannel;
}

const ESCAPE_HATCH_MESSAGE =
  'server.server, server.mcpServer or server.experimental was used on a server with an HTTP handler ' +
  'attached. If you installed handlers or registrations through them, they reach stdio only, never ' +
  'HTTP sessions.';

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

/** The log, its replay, and the freeze. One per SecureMcpServer. */
export class RegistrationLog {
  private readonly entries: Entry[] = [];
  private readonly slots: Slot[] = [];
  private frozen = false;
  private escapeHatchRead = false;

  constructor(
    private readonly primary: McpServer,
    private readonly serverInfo: ConstructorParameters<typeof McpServer>[0],
    private readonly serverOptions: ConstructorParameters<typeof McpServer>[1],
    private readonly hooks: RegistrationLogHooks
  ) {}

  /** Whether registrations are frozen. */
  get isFrozen(): boolean { return this.frozen; }

  /** Freeze registrations permanently; reports an escape-hatch read made before it. Idempotent. */
  freeze(): void {
    if (this.frozen) return;
    this.frozen = true;
    if (this.escapeHatchRead) this.hooks.warnings.once(WARNING_CODES.ESCAPE_HATCH, ESCAPE_HATCH_MESSAGE);
  }

  /**
   * Note a read of an escape-hatch getter: reported at the freeze if it came before
   * it (setup done first through a getter never reaches a session), else at once.
   */
  noteEscapeHatch(): void {
    if (this.frozen) this.hooks.warnings.once(WARNING_CODES.ESCAPE_HATCH, ESCAPE_HATCH_MESSAGE);
    else this.escapeHatchRead = true;
  }

  /** Apply a registration to the primary, record it, and return a logging handle. */
  register(method: RegistrationMethod, args: unknown[]): unknown {
    const name = typeof args[0] === 'string' ? args[0] : undefined;
    this.assertOpen(method, name);
    let applied = args;
    let ref: NameRef | undefined;
    if (method === 'tool' || method === 'registerTool') {
      ref = { name: name ?? '' };
      applied = this.wrapToolArgs(method, args, ref);
    }
    const handle = (this.primary[method] as AnyFn)(...applied);
    this.entries.push({ kind: 'register', method, args: applied });
    this.slots.push({ handle, ref, name });
    return this.loggingHandle(this.slots.length - 1);
  }

  /** Apply `registerCapabilities` to the primary and record it (it returns nothing). */
  registerCapabilities(capabilities: unknown): void {
    this.assertOpen('registerCapabilities', undefined);
    (this.primary.server.registerCapabilities as AnyFn)(capabilities);
    this.entries.push({ kind: 'capabilities', capabilities });
  }

  /** Build a fresh McpServer and replay the log through its own handles. */
  createSessionServer(): McpServer {
    const server = new McpServer(this.serverInfo, this.serverOptions);
    const handles: unknown[] = [];
    for (const entry of this.entries) {
      switch (entry.kind) {
        case 'register':
          handles.push((server[entry.method] as AnyFn)(...entry.args));
          break;
        case 'call':
          (handles[entry.target] as Record<string, AnyFn>)[entry.method]!(...entry.args);
          break;
        case 'set':
          (handles[entry.target] as Record<PropertyKey, unknown>)[entry.prop] = entry.value;
          break;
        case 'capabilities':
          (server.server.registerCapabilities as AnyFn)(entry.capabilities);
          break;
      }
    }
    return server;
  }

  private assertOpen(method: string, name: string | undefined): void {
    if (!this.frozen) return;
    this.hooks.warnings.counted(WARNING_CODES.LATE_REGISTRATION, `${method}:${name ?? ''}`, count =>
      `${method}${name === undefined ? '' : ` "${name}"`} was refused: registrations are frozen once an ` +
      `HTTP handler is attached (LateRegistrationError; ${count} so far). A runtime toggle inside a ` +
      'tool reaches its client only as a tool error.');
    throw new LateRegistrationError(method, name);
  }

  /** Replace the tool callback with its Layer 5 wrapper; a non-function (task handler) passes. */
  private wrapToolArgs(method: 'tool' | 'registerTool', args: unknown[], ref: NameRef): unknown[] {
    const index = method === 'registerTool'
      ? (typeof args[2] === 'function' ? 2 : -1)
      : args.findIndex((arg, i) => i > 0 && typeof arg === 'function');
    if (index === -1) return args;
    const applied = [...args];
    applied[index] = this.hooks.wrapTool(ref, args[index]);
    return applied;
  }

  /** A handle with the SDK handle's shape whose methods and field writes are logged. */
  private loggingHandle(position: number): unknown {
    const { handle } = this.slots[position]!;
    if (handle === null || (typeof handle !== 'object' && typeof handle !== 'function')) return handle;
    return new Proxy(handle as object, {
      get: (target, prop) => {
        const value = Reflect.get(target, prop, target);
        if (typeof value === 'function' && HANDLE_METHODS.has(prop)) {
          return (...args: unknown[]) => this.call(position, String(prop), args);
        }
        return value;
      },
      set: (target, prop, value) => {
        this.assertOpen(`set ${String(prop)}`, this.slots[position]!.name);
        Reflect.set(target, prop, value, target);
        this.entries.push({ kind: 'set', target: position, prop, value });
        return true;
      }
    });
  }

  private call(position: number, method: string, args: unknown[]): unknown {
    const slot = this.slots[position]!;
    this.assertOpen(method, slot.name);
    const update = method === 'update' && isRecord(args[0]) ? args[0] : undefined;
    let applied = args;
    if (update && slot.ref && typeof update.callback === 'function') {
      applied = [{ ...update, callback: this.hooks.wrapTool(slot.ref, update.callback) }, ...args.slice(1)];
    }
    const result = (slot.handle as Record<string, AnyFn>)[method]!(...applied);
    this.entries.push({ kind: 'call', target: position, method, args: applied });
    if (update && typeof update.name === 'string' && update.name) {
      slot.name = update.name;
      if (slot.ref) slot.ref.name = update.name;
    }
    return result;
  }
}
