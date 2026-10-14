/**
 * Client address resolution for per-IP rate limits.
 *
 * Every per-client limit in the HTTP transport keys on the string this module
 * returns, so the module's one job is that a client cannot choose that string.
 * Until 0.0.26 the leftmost X-Forwarded-For entry (then X-Real-IP) was trusted
 * unconditionally and any client could pick a fresh key per request. The
 * review of the first fix (tracker mcp-secure-server security-fix-review #14)
 * shaped what follows:
 *
 * - A hop count alone cannot tell whether a request came through the proxy,
 *   so `trustProxy` also takes a list of trusted proxy addresses/CIDRs, walked
 *   right to left from the socket peer, stopping at the first untrusted hop.
 * - When the chain is shorter than the hop count, the socket peer is used, not
 *   the leftmost (client-written) entry.
 * - Addresses are normalized (ports, brackets, zone ids, IPv4-mapped IPv6)
 *   and must parse as IPs; anything else falls back to the nearest trusted hop.
 * - IPv6 addresses are keyed by their /64, the smallest block a client is
 *   routinely allocated; keying the full address let one client rotate keys.
 * - Misconfiguration warns once per resolver, and only in conditions that
 *   raising `trustProxy` cannot silence.
 *
 * X-Real-IP is never read: it has no hop structure, so a proxy that sets it
 * cannot be told apart from one that passes the client's value through.
 */

import { BlockList, isIP } from 'node:net';

/** Hop count, or trusted proxy addresses / CIDRs / named ranges. */
export type TrustProxy = number | readonly string[];

/** Client IP resolution options */
export interface ClientIpOptions {
  /**
   * Which forwarding hops to trust (default: 0 = none; the socket peer is the
   * client and X-Forwarded-For is ignored).
   * - number N: the Nth X-Forwarded-For entry from the right, counting the
   *   entry appended by the proxy nearest this server (the rightmost) as 1.
   * - string[]: your proxies' addresses or CIDRs (or the named ranges
   *   'loopback', 'linklocal', 'uniquelocal'). The client is the first
   *   address, walking right to left from the socket peer, that is not in the
   *   list. Every listed address is treated as a proxy: a request FROM a listed
   *   address is keyed on the entries it sends, so list only your proxies.
   *   Named ranges are safe only when no client connects from them.
   */
  trustProxy?: TrustProxy;
}

/** Options for createClientIpResolver */
export interface ClientIpResolverOptions extends ClientIpOptions {
  /** Receives one-time misconfiguration warnings (default: process.emitWarning). Pass `false` to silence. */
  onWarning?: ((message: string) => void) | false;
}

/** Minimal request shape the resolver reads */
export interface ClientIpRequest {
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
}

/** Resolves the rate-limit key for a request */
export type ClientIpResolver = (req: ClientIpRequest) => string;

const WARNING_CODE = 'MCP_SECURE_SERVER_TRUST_PROXY';

const TRUST_PROXY_HELP =
  'Example:\n' +
  "  server.createHttpServer({ trustProxy: ['10.0.0.12'] }); // your proxy's address\n\n" +
  'See: https://github.com/aself101/mcp-secure-server#client-ip-and-trustproxy';

const NAMED_RANGES = new Map<string, readonly string[]>([
  ['loopback', ['127.0.0.0/8', '::1/128']],
  ['linklocal', ['169.254.0.0/16', 'fe80::/10']],
  ['uniquelocal', ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7']]
]);

const PRIVATE_PEERS = compileList(['loopback', 'linklocal', 'uniquelocal']);

type CompiledTrust = { kind: 'hops'; hops: number } | { kind: 'list'; list: BlockList };

/**
 * Validates and compiles a trustProxy value, throwing TypeError on anything
 * else. `true` is rejected by name: in Express it means "trust every hop",
 * the leftmost-entry behaviour this option exists to remove.
 * @param trustProxy - Candidate value
 * @returns Compiled trust configuration
 */
function compileTrust(trustProxy: unknown = 0): CompiledTrust {
  if (Array.isArray(trustProxy)) return { kind: 'list', list: compileList(trustProxy) };
  if (typeof trustProxy === 'number' && Number.isSafeInteger(trustProxy) && trustProxy >= 0) {
    return { kind: 'hops', hops: trustProxy };
  }
  const reason = trustProxy === true
    ? '`true` is not accepted: it would trust a client-supplied X-Forwarded-For entry. List your proxy addresses instead.'
    : typeof trustProxy === 'number'
      ? 'a hop count must be a whole number of 0 or more.'
      : 'expected a hop count (number) or an array of trusted proxy addresses.';
  throw new TypeError(`Invalid trustProxy (got ${describe(trustProxy)}): ${reason}\n\n${TRUST_PROXY_HELP}`);
}

/**
 * Renders an invalid option value for an error message.
 * @param value - Rejected value
 * @returns Short description
 */
function describe(value: unknown): string {
  if (typeof value === 'string') return JSON.stringify(value);
  if (value !== null && typeof value === 'object') return 'an object';
  return String(value);
}

/**
 * Builds a BlockList from addresses, CIDRs and named ranges.
 * @param entries - Trusted proxy specifications
 * @returns BlockList matching every trusted address
 */
function compileList(entries: readonly unknown[]): BlockList {
  const list = new BlockList();
  for (const entry of entries) {
    if (typeof entry !== 'string') {
      throw new TypeError(`Invalid trustProxy entry (got ${describe(entry)}): entries must be strings.\n\n${TRUST_PROXY_HELP}`);
    }
    const named = NAMED_RANGES.get(entry);
    for (const spec of named ?? [entry]) addSpec(list, spec);
  }
  return list;
}

/**
 * Adds one address or CIDR to a BlockList, rejecting anything that does not parse.
 * @param list - Target list
 * @param spec - Address or CIDR
 */
function addSpec(list: BlockList, spec: string): void {
  const [address, prefixText, extra] = spec.split('/');
  const family = isIP(address ?? '');
  const prefix = prefixText === undefined ? undefined : Number(prefixText);
  const maxPrefix = family === 4 ? 32 : 128;
  if (family === 0 || extra !== undefined ||
      (prefix !== undefined && (!/^\d+$/.test(prefixText ?? '') || prefix > maxPrefix))) {
    throw new TypeError(
      `Invalid trustProxy entry ${JSON.stringify(spec)}: not an IP address, a CIDR (e.g. '10.0.0.0/8'), or a named range ` +
      `(${[...NAMED_RANGES.keys()].join(', ')}).\n\n${TRUST_PROXY_HELP}`
    );
  }
  const type = family === 4 ? 'ipv4' : 'ipv6';
  if (prefix === undefined) list.addAddress(address!, type);
  else list.addSubnet(address!, prefix, type);
}

/**
 * Normalizes an address as written by a socket or proxy: strips brackets,
 * ports and zone ids, unwraps IPv4-mapped IPv6, and rejects non-IPs.
 * @param raw - Address text
 * @returns Canonical address, or null if it is not an IP
 */
export function normalizeAddress(raw: string): string | null {
  let value = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(value);
  if (bracketed) value = bracketed[1]!;
  else if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(value)) value = value.slice(0, value.lastIndexOf(':'));
  const zone = value.indexOf('%');
  if (zone !== -1) value = value.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1]!;
  return isIP(value) === 0 ? null : value.toLowerCase();
}

/**
 * Rate-limit key for a normalized address: IPv4 as-is, IPv6 as its /64.
 * @param address - Normalized address
 * @returns Key string
 */
export function rateLimitKey(address: string): string {
  if (isIP(address) !== 6) return address;
  return `${expandIpv6(address).slice(0, 4).join(':')}::/64`;
}

/**
 * Expands a valid IPv6 address into eight lowercase hextets without leading zeros.
 * @param address - Valid IPv6 address
 * @returns Eight hextets
 */
function expandIpv6(address: string): string[] {
  let text = address;
  const dotted = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [a, b, c, d] = dotted.slice(1).map(Number) as [number, number, number, number];
    text = `${text.slice(0, dotted.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const split = text.split('::');
  const left = split[0] ? split[0].split(':') : [];
  const right = split.length > 1 && split[1] ? split[1].split(':') : [];
  const fill = split.length > 1 ? new Array<string>(8 - left.length - right.length).fill('0') : [];
  return [...left, ...fill, ...right].map(group => parseInt(group, 16).toString(16));
}

/**
 * Yields comma-separated entries from the right, skipping empties, without
 * splitting the whole header up front.
 * @param text - Joined X-Forwarded-For value
 */
function* entriesFromRight(text: string): Generator<string> {
  let end = text.length;
  while (end > 0) {
    const start = text.lastIndexOf(',', end - 1);
    const entry = text.slice(start + 1, end).trim();
    if (entry) yield entry;
    end = start === -1 ? 0 : start;
  }
}

/**
 * Checks whether a normalized address is in a BlockList.
 * @param list - Trusted addresses
 * @param address - Normalized address
 * @returns true if trusted
 */
function inList(list: BlockList, address: string): boolean {
  return list.check(address, isIP(address) === 6 ? 'ipv6' : 'ipv4');
}

/**
 * Creates a client IP resolver. `trustProxy` is validated here, at
 * construction, so a bad value fails at startup rather than on a request.
 * @param options - Proxy trust configuration and warning sink
 * @returns Resolver returning the rate-limit key for a request
 * @example
 * ```typescript
 * const clientIp = createClientIpResolver({ trustProxy: ['10.0.0.0/8'] });
 * // peer 10.0.0.1, X-Forwarded-For: "spoofed, 203.0.113.7"  -> '203.0.113.7'
 * // peer 203.0.113.50 (bypassed the proxy), any header        -> '203.0.113.50'
 * // peer 2001:db8::5                                          -> '2001:db8:0:0::/64'
 * const key = clientIp(req);
 * ```
 */
export function createClientIpResolver(options: ClientIpResolverOptions = {}): ClientIpResolver {
  const trust = compileTrust(options.trustProxy);
  const sink = options.onWarning === false
    ? () => {}
    : options.onWarning ?? ((message: string) => process.emitWarning(message, { code: WARNING_CODE }));
  const warned = new Set<string>();
  const warn = (kind: string, message: string): void => {
    if (warned.has(kind)) return;
    warned.add(kind);
    sink(message);
  };

  return (req) => {
    const peer = normalizeAddress(req.socket?.remoteAddress ?? '');
    if (peer === null) return 'unknown';
    const header = req.headers['x-forwarded-for'];
    const forwarded = Array.isArray(header) ? header.join(',') : header ?? '';
    const peerTrusted = trust.kind === 'hops' ? trust.hops > 0 : inList(trust.list, peer);

    if (!peerTrusted) {
      if (forwarded && inList(PRIVATE_PEERS, peer)) {
        warn('ignored', `X-Forwarded-For arrived from ${peer}, a private address that trustProxy does not trust, ` +
          'so every client behind it shares one rate-limit key: one per-key HTTP session cap (10 concurrent SDK clients ' +
          'by default), one pool for idle-session eviction, one GET/DELETE limit and one error lockout. ' +
          'If that address is your reverse proxy, configure trustProxy.');
      }
      return rateLimitKey(peer);
    }

    let current = peer;
    let seen = 0;
    for (const entry of entriesFromRight(forwarded)) {
      const address = normalizeAddress(entry);
      if (address === null) {
        warn('invalid', 'A trusted proxy forwarded an X-Forwarded-For entry that is not an IP address; ' +
          'the request is keyed on the proxy address instead.');
        return rateLimitKey(current);
      }
      seen++;
      if (trust.kind === 'hops' ? seen === trust.hops : !inList(trust.list, address)) return rateLimitKey(address);
      current = address;
    }

    warn('short', trust.kind === 'hops'
      ? `A request carried fewer X-Forwarded-For entries than trustProxy (${trust.hops}) hops; it is keyed on the socket peer. ` +
        'Either trustProxy exceeds the number of proxies that append to X-Forwarded-For, or a request reached this server without passing through them.'
      : 'A request from a trusted proxy carried no untrusted X-Forwarded-For entry; it is keyed on the last trusted hop. ' +
        'The proxy may not be appending to X-Forwarded-For.');
    return rateLimitKey(trust.kind === 'hops' ? peer : current);
  };
}

/**
 * Resolve the rate-limit key for one request. Validates `trustProxy` on every
 * call and never warns; long-lived handlers should build a resolver once with
 * createClientIpResolver instead.
 * @param req - HTTP request with headers and socket
 * @param options - Proxy trust configuration
 * @returns Rate-limit key, or 'unknown' when the socket has no address
 */
export function getClientIp(req: ClientIpRequest, options: ClientIpOptions = {}): string {
  return createClientIpResolver({ ...options, onWarning: false })(req);
}
