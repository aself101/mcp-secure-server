/**
 * Origin and Host validation, and the exposure warning (spec http-transport-per-session
 * v0.4.3, section D; D12, D15, D16).
 * @module http-origin
 */

import type { IncomingMessage } from 'node:http';

/** Validated Origin/Host policy for one handler. */
export interface OriginPolicy {
  /** Exact serialized origins a browser client may send. */
  readonly origins: ReadonlySet<string>;
  /** Exact Host values accepted, lowercase; null = no Host check. */
  readonly hosts: ReadonlySet<string> | null;
}

/**
 * Validate `allowedOrigins` / `allowedHosts` at construction. An origin must be in
 * serialized form — `scheme://host[:port]`, lowercase, no path, no trailing slash, no
 * default port — so a typo throws rather than silently never matching. `"null"` is
 * refused (D15): it is the origin of every sandboxed frame and opaque-origin document on
 * every site. `allowedHosts: []` is refused: it would refuse every request.
 */
export function createOriginPolicy(allowedOrigins: unknown, allowedHosts: unknown): OriginPolicy {
  const origins = allowedOrigins ?? [];
  if (!Array.isArray(origins)) throw new TypeError('allowedOrigins must be an array of origins.');
  for (const entry of origins) {
    if (entry === 'null') {
      throw new TypeError(
        'allowedOrigins cannot list "null": it is the origin of every sandboxed frame and opaque-origin ' +
        'document on every site. Serve the page from a real origin, or call the server from a non-browser ' +
        'client (for Electron, the main process), which sends no Origin.'
      );
    }
    if (typeof entry !== 'string' || serializeOrigin(entry) !== entry) {
      throw new TypeError(
        `allowedOrigins entry ${JSON.stringify(entry)} is not a serialized origin. Use the exact form a ` +
        'browser sends: scheme://host[:port], lowercase, no path, no trailing slash, no default port ' +
        '(for example "https://app.example.com" or "http://localhost:5173").'
      );
    }
  }
  if (allowedHosts === undefined) return { origins: new Set(origins as string[]), hosts: null };
  if (!Array.isArray(allowedHosts) || allowedHosts.length === 0 || !allowedHosts.every(h => typeof h === 'string' && h)) {
    throw new TypeError('allowedHosts must be a non-empty array of Host values (for example ["127.0.0.1:3000", "localhost:3000"]); omit it for no Host check.');
  }
  return { origins: new Set(origins as string[]), hosts: new Set(allowedHosts.map(h => (h as string).toLowerCase())) };
}

/** `scheme://host[:port]` as a browser serializes it, or null if `value` is not an origin. */
function serializeOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== '' && url.pathname !== '/') return null;
    // URL.origin is "null" for non-special schemes (chrome-extension://, app://), whose
    // origins browsers still send in this form; build it from the parts instead.
    return `${url.protocol}//${url.host}`;
  } catch {
    return null;
  }
}

/** The reason to refuse with 403, or null to proceed. Not charged, not metered. */
export function checkOriginAndHost(req: IncomingMessage, policy: OriginPolicy): string | null {
  const origin = req.headers.origin;
  if (origin !== undefined && !policy.origins.has(origin)) {
    return 'Origin not allowed; list it in allowedOrigins';
  }
  if (policy.hosts) {
    const host = req.headers.host?.toLowerCase();
    if (!host || !policy.hosts.has(host)) return 'Host not allowed; list it in allowedHosts';
  }
  return null;
}

const LOOPBACK_V4 = /^127\./;

/** True for 127.0.0.0/8, ::1 and ::ffff:127.0.0.0/104. */
export function isLoopbackAddress(address: string): boolean {
  return LOOPBACK_V4.test(address) || address === '::1' || /^::ffff:127\./i.test(address);
}

/**
 * The address the request's listener is bound to (`0.0.0.0` / `::` for every
 * interface). Probe 15: `req.socket.server` is the listener on node:http and node:https;
 * the connection's `localAddress` is the fallback, which says 127.0.0.1 for a server
 * bound to every interface but reached over loopback.
 */
export function boundAddress(req: IncomingMessage): string | undefined {
  const socket = req.socket as (typeof req.socket & { server?: { address?: () => unknown } }) | undefined;
  const addr = socket?.server?.address?.();
  if (addr && typeof addr === 'object' && 'address' in addr && typeof addr.address === 'string') return addr.address;
  return socket?.localAddress;
}

/** The exposure warning's text (D16). */
export function exposureMessage(address: string): string {
  return `This MCP HTTP handler is listening on ${address}, which is reachable beyond this machine, and the ` +
    'transport has no authentication: any client that can reach the port can create a session and call tools. ' +
    'allowedOrigins and allowedHosts do not restrict non-browser clients. For local use, bind 127.0.0.1. In a ' +
    'container, where binding 0.0.0.0 is required, publish the port on the host\'s loopback. If the exposure ' +
    'is intended and authentication sits in front, silence MCP_SECURE_SERVER_HTTP_EXPOSED.';
}
