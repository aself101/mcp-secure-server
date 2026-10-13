/**
 * The package's warning channel (spec http-transport-per-session D18).
 *
 * One sink per server. Silencing takes naming each code: there is deliberately no
 * "off" value, because a single switch lets the noisiest warning (the experimental
 * label, which fires in every test that builds a handler) silence the ones that
 * matter (a late registration, an exposed listener). Not the security logger, which
 * is null unless logging is enabled — a warning routed there reaches nobody by default.
 */

/** Every code the package emits. */
export const WARNING_CODES = {
  HTTP_EXPERIMENTAL: 'MCP_SECURE_SERVER_HTTP_EXPERIMENTAL',
  LATE_REGISTRATION: 'MCP_SECURE_SERVER_LATE_REGISTRATION',
  ESCAPE_HATCH: 'MCP_SECURE_SERVER_ESCAPE_HATCH',
  HTTP_EXPOSED: 'MCP_SECURE_SERVER_HTTP_EXPOSED',
  HTTP_LOGGING: 'MCP_SECURE_SERVER_HTTP_LOGGING',
  TRUST_PROXY: 'MCP_SECURE_SERVER_TRUST_PROXY'
} as const;

/** A warning code. */
export type WarningCode = typeof WARNING_CODES[keyof typeof WARNING_CODES];

/** Receives every warning not silenced. */
export type WarningHandler = (message: string, code: WarningCode) => void;

/** Warning options on `SecureMcpServer`. */
export interface WarningOptions {
  /** Where warnings go (default: `process.emitWarning(message, { code })`). */
  onWarning?: WarningHandler;
  /** Codes to drop, each named. An unknown code throws at construction. */
  silenceWarnings?: readonly WarningCode[];
}

const KNOWN = new Set<string>(Object.values(WARNING_CODES));
const processReported = new Set<string>();

const defaultSink: WarningHandler = (message, code) => process.emitWarning(message, { code });

/** True for 1, 10, 100, 1000, … */
function isPowerOfTen(n: number): boolean {
  while (n >= 10 && n % 10 === 0) n /= 10;
  return n === 1;
}

/** One server's warning sink, with its once-only and counted bookkeeping. */
export class WarningChannel {
  private readonly sink: WarningHandler;
  private readonly silenced: ReadonlySet<string>;
  private readonly reported = new Set<string>();
  private readonly counts = new Map<string, number>();

  constructor(options: WarningOptions = {}) {
    if (options.onWarning !== undefined && typeof options.onWarning !== 'function') {
      throw new TypeError(
        'onWarning must be a function. To drop specific warnings, name their codes in silenceWarnings.'
      );
    }
    const silence = options.silenceWarnings ?? [];
    if (!Array.isArray(silence)) {
      throw new TypeError('silenceWarnings must be an array of warning codes.');
    }
    for (const code of silence) {
      if (!KNOWN.has(code)) {
        throw new TypeError(
          `silenceWarnings: unknown code ${JSON.stringify(code)}. Known codes: ${[...KNOWN].join(', ')}.`
        );
      }
    }
    this.sink = options.onWarning ?? defaultSink;
    this.silenced = new Set(silence);
  }

  /** Deliver a warning unless its code is silenced. Returns whether it was delivered. */
  emit(code: WarningCode, message: string): boolean {
    if (this.silenced.has(code)) return false;
    this.sink(message, code);
    return true;
  }

  /** Deliver once per `key` (default: the code) for this server. */
  once(code: WarningCode, message: string, key: string = code): void {
    if (this.reported.has(key)) return;
    this.reported.add(key);
    this.emit(code, message);
  }

  /**
   * Count occurrences per `key`; deliver at the 1st, 10th, 100th … with the count, so a
   * failure that recurs on every call does not read as a one-off.
   */
  counted(code: WarningCode, key: string, message: (count: number) => string): void {
    const count = (this.counts.get(key) ?? 0) + 1;
    this.counts.set(key, count);
    if (isPowerOfTen(count)) this.emit(code, message(count));
  }

  /** Deliver once per process; marked only when actually delivered. */
  oncePerProcess(code: WarningCode, message: string): void {
    if (processReported.has(code)) return;
    if (this.emit(code, message)) processReported.add(code);
  }
}

/** @internal Test hook: forget the once-per-process state. */
export function _resetProcessWarnings(): void {
  processReported.clear();
}
