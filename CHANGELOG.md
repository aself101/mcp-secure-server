# Changelog

All notable changes to this project will be documented in this file.

This project uses manual versioning with the `-security` suffix during the initial release phase.

**Entry format, deliberate:** each release is one dated `## [version]` heading with a flat list of
bullets, each bullet leading with its kind in bold (**Security**, **Fix**, **Behaviour change**,
**Types**, **cookbook (…)**). There is no `[Unreleased]` section — the next version's heading is
written when the version is bumped, and changes accumulate under it until publish. This differs from
Keep a Changelog's grouped `### Added / Changed / Fixed` layout; the one release that used those
groups (0.0.21-security) is left as written.

> **Note:** This package was previously developed under versions 0.7.x - 1.0.x but was blocked on npm due to namespace restrictions. GitHub Support unblocked the package and published 0.0.1-security as the initial release. All future versions will build from this baseline. For historical development context, see the [commit history](https://github.com/aself101/mcp-secure-server/commits/main).

## [0.1.0-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.1.0-security) (unreleased)

Per-session HTTP transport (spec `http-transport-per-session` v0.4.3, issue 4bf30630). Entries are
added phase by phase; the HTTP transport itself is still the 0.0.27 one until the session registry
lands, so read this heading as work in progress until it is dated.

- **Fix: the HTTP transport serves more than one request** (issue 4bf30630). Through 0.0.27 the
  handler shared one stateless SDK transport, which the SDK (>= 1.26) refuses to reuse: every
  request after the first answered 500 until restart, and a concurrent client could hang. Each MCP
  session now gets its own `McpServer` and stateful `StreamableHTTPServerTransport`, with a
  server-issued `Mcp-Session-Id`. Every earlier HTTP test sent one request to a fresh server, so
  none could see it; `test/integration/http-sessions.test.ts` drives two SDK clients at once.
- **Behaviour change: HTTP clients must send `Mcp-Session-Id` after `initialize`.** A header-less
  request other than a single `initialize` POST is a 400 before the security pipeline — charged to
  the error lockout only when the body is not well-formed JSON-RPC, since clients probe header-less
  before initializing (Claude Code sends `server/discover`); a session id the server did not issue is a 404 —
  always, never a 429, without consulting the lockout. The pipeline's `context.sessionId` is the
  server-issued id; it was the raw client-chosen header, or `'stateless'`. SDK clients already
  behave this way. Hosts must re-initialize on 404 and discard the old id.
- **Behaviour change: `Origin` is validated** (MCP 2025-11-25 MUST). A request whose `Origin` is not
  in the new `allowedOrigins` option (default `[]`) gets 403 with a JSON-RPC error; one without
  `Origin` (non-browser clients) is allowed. Browser, Electron, extension and webview clients must
  be listed. `"null"` and malformed entries throw at construction. `allowedHosts` adds an optional
  Host check (`[]` throws).
- **Behaviour change: the error lockout only ever refuses malformed requests.** Until 0.1.0 it was
  also consulted on every GET and DELETE, so a client that had probed could not open its own
  stream; a well-formed request now never consults it.
- **Behaviour change: `sessionlessRequestsPerMinute` / `PerHour` meter GET and DELETE on known
  sessions** (their meaning — GET/DELETE per client — is unchanged; the name predates sessions).
  Header-less GET/DELETE are 400s instead.
- **Behaviour change: JSON-RPC batch bodies get 400** (`-32600`), removed from MCP in 2025-06-18;
  Layer 1 already refused them.
- **Added: session bounds.** `maxHttpSessions` (1000), `maxHttpSessionsPerClient` (10) and
  `httpSessionIdleTtlMs` (30 min). At the per-client cap the client's own session idle for 60 s is
  evicted, else 503 (`X-RateLimit-Scope: client-sessions`; the global cap says `sessions`). GET
  streams are closed after 30 minutes (the session survives; the TypeScript SDK client reopens).
- **Added: `createSecureHttpHandler` returns a `SessionHttpHandler`** with `close()` and
  `sessionCount`; both server factories' `close()` now closes the sessions first (a GET whose
  client stopped reading is destroyed after 5 s). Call `handler.close()` before `server.close()`
  when building your own server. `createSecureHttpHandler` throws on a server without
  `_createSessionServer` (any `SecureMcpServer` from 0.1.0 has it).
- **Added: `MCP_SECURE_SERVER_HTTP_EXPOSED`**, once per handler when its listener is bound beyond
  loopback (`0.0.0.0` included): the transport has no authentication. Silenced only by naming it.
  The `trustProxy` warning now goes to the server's `onWarning` sink.
- **Removed: `HttpTransportManager`** (internal, never exported).
- **Behaviour change: `sendLoggingMessage(params, sessionId)` reaches that HTTP session only**
  (a tool has the id as `extra.sessionId`), filtered by that session's `logging/setLevel`. Without a
  matching session it goes to the stdio connection as before; with neither it is a no-op that
  reports `MCP_SECURE_SERVER_HTTP_LOGGING` once. It never broadcasts to every HTTP session, since
  sessions may belong to different users.
- **Added: `getClientCapabilities(sessionId?)` / `getClientVersion(sessionId?)`** answer for that
  HTTP session's client; without an id, the stdio client (undefined on an HTTP-only server).
- **Fix: `shutdown()` closes every attached HTTP handler's sessions** before the primary, so an
  HTTP server can close even with a GET stream whose client stopped reading.
- **Behaviour change (stdio too): notifications bypass Layer 4 method chaining.** Under
  `enforceChaining` (on in the `paranoid` preset) notifications — `notifications/initialized`,
  `cancelled`, `progress`, `roots/list_changed` — are neither checked against chaining rules nor
  recorded as the previous method. The default rules named no notification, so every one was
  denied: over stdio silently (a refused notification gets no response), so a `paranoid` server
  never received `notifications/initialized` or any cancellation while its handshake looked fine;
  over HTTP as a failed SDK `connect`. A custom chaining rule that names a notification no longer
  has any effect (none found in the UluOps workspace, 2026-10-13). Chaining governs request
  sequences; notifications interleave anywhere, and a cancellation must always arrive.
- **Behaviour change: registrations freeze when an HTTP handler is attached.** After
  `createSecureHttpHandler(server)` (or either server factory) returns, every registration method,
  `registerCapabilities`, and every call or field write through a returned handle throws
  `LateRegistrationError` — on that server object, **stdio included**. Every HTTP session must serve
  the same registration set, and the freeze is what makes that true without fanning changes out to
  live sessions. Register everything before creating the handler. What stops working: dynamic tools
  (adding or toggling handles at runtime) and kill switches built on `disable()` / `remove()` on a
  server with a handler attached — a kill switch belongs in the tool's callback, and catching the
  error leaves the tool callable. A handler constructor that throws on a bad option leaves the
  server unfrozen.
- **Behaviour change (stdio too): Layer 5 sees a renamed tool's current name.** The response
  wrapper captured the name a tool was created with, and the SDK's `update({ name })` does not
  rewrap, so after a rename every Layer 5 validator and `RESPONSE_BLOCKED` log saw the old name and
  applied its policy (probe 13C). The wrapper now reads the name each time the tool runs. A
  callback installed through `update({ callback })` is wrapped too. The SDK's own handle defect
  (a renamed tool survives `remove()`) is unchanged — issue 7f3ec293.
- **Behaviour change (stdio too): tool handlers receive every argument the SDK passes.** The
  wrapper called `handler(args)` and dropped the SDK's `extra`; for a tool without an input schema
  the SDK calls `handler(extra)`, so such tools received `extra` as their only argument while
  Layer 5 received `extra` — request headers included — as `arguments`. Handlers now get
  `(args, extra)` or `(extra)` exactly as the SDK sends them, and Layer 5's `arguments` is `args`,
  or `{}` for a schema-less tool. The type of the field did not change; its meaning did.
- **Added: one warning channel per server.** `SecureMcpServer` options `onWarning(message, code)`
  (default `process.emitWarning(message, { code })`) and `silenceWarnings` (codes named one by one;
  an unknown code throws). There is deliberately no option that silences everything. Codes so far:
  `MCP_SECURE_SERVER_HTTP_EXPERIMENTAL` (once per process when a handler is created: no
  authentication, bearer session ids, Layer 3 shared by every client),
  `MCP_SECURE_SERVER_LATE_REGISTRATION` (counted: reported at the 1st, 10th, 100th … refusal), and
  `MCP_SECURE_SERVER_ESCAPE_HATCH` (`server.server`, `server.mcpServer` or `server.experimental`
  used on a server with a handler attached — what they install reaches stdio only). Not the
  security logger, which is null unless logging is enabled.
- **Types:** `LateRegistrationError` (fields `method`, `registrationName`), `WarningCode` and
  `WarningHandler` are exported from the package root and `./server`.

## [0.0.27-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.27-security) (2026-10-13)

- **Known issue, documented: the HTTP transport is experimental.** With
  `@modelcontextprotocol/sdk` >= 1.26 (this package requires `^1.30.0`, since 0.0.21), the HTTP
  transport answers only the **first** request per process; every later request returns 500 until
  restart. `HttpTransportManager` shares one stateless SDK transport across requests, the SDK
  refuses to reuse a stateless transport ("Stateless transport cannot be reused across
  requests"), and recovery cannot reconnect because an `McpServer` accepts one transport at a
  time. Every HTTP test sent a single request to a fresh server, so nothing caught it; the stdio
  transport is unaffected. The fix needs a design change (a server per request or per session)
  and is not in this release. README, cookbook and SECURITY.md now say so. Found by a
  wittgenstein-analyst reading of "session teardown" (consumer-validate run #16) and confirmed
  by a runtime probe.
- **Docs, Security: `trustProxy` guidance corrected.** 0.0.26 recommended
  `trustProxy: ['uniquelocal']` and said a request reaching the app directly "is keyed on its own
  address, however many entries it forges". That holds only for addresses **not** in the list:
  every listed address is treated as a proxy, so a client connecting *from* a listed range —
  any intranet, VPN or container client under `'uniquelocal'` — is keyed on the `X-Forwarded-For`
  entries it sends. Examples, error help text and JSDoc now use your proxies' exact addresses;
  SECURITY.md adds assumption 7 (no client connects from a trusted-proxy address) and 8 (the
  listener has a TCP peer). The code is unchanged — this is how address-list trust works; the
  docs claimed more than it gives.
- **Docs: other corrections from the same analysis.**
  - `context.sessionId` is not an identity (client-chosen over HTTP, `undefined` over stdio); the
    README's context-store auth example keyed on it and now keys on an identity your own auth
    verified.
  - SECURITY.md offered the Layer 5 per-client limit as the mitigation for the process-wide
    Layer 3/4 budgets; Layer 5 runs after they count the request, so it cannot.
  - The resolved client value is a rate-limit key (IPv4, IPv6 `/64`, or `'unknown'`), not an
    address: not for allow/deny lists or geolocation. The advanced-validation geofencing and
    egress examples now say what context they actually receive.
  - The upgrade warning fires only for a proxy with a **private** address; an undercounted hop
    count is silent. The /64 is not one client either way (/56–/48 holders, NAT).
  - `maxSessions` is a sweep threshold, not a maximum; the Layer 5 rate limit is per client
    **and per method**; the hop count counts from the proxy *nearest* the server; pipeline 429s
    carry no `X-RateLimit-Scope`; the HTTP Utilities example now counts only client-specific
    transport rejections (not pipeline 429s, which can be process-wide); a Unix-socket listener
    keys every request `'unknown'`.
- **Fix: clearer errors.** An unknown base-policy reference names the valid base policies;
  `database-server` on Node < 22.13 names the requirement instead of throwing
  `ERR_UNKNOWN_BUILTIN_MODULE`; `npm run test:cookbook` without a cookbook install says to run
  `cd cookbook && npm install` instead of 13 `TS2307`s.
- **Fix, Types: `contextual.maxContextEntries` is accepted by `SecureMcpServerOptions`.** 0.0.26
  documented it (README Layer 5 configuration) and Layer 5 honoured it at runtime, but TypeScript
  rejected it with TS2353: `SecureMcpServerOptions.contextual` is typed from a second,
  hand-maintained copy of the Layer 5 options (`src/types/layers.ts`), and the field was added only
  to the builder's `ContextualConfig`. JavaScript callers were unaffected.
  - **Why not merge the two copies:** the public type makes every sub-option field optional
    (`rateLimiting: { enabled: true, limit: 2 }` is valid); the builder's types require them.
    Collapsing onto the builder's would narrow the public contract and break TypeScript callers
    that omit fields. Instead, `test/types/server-options.ts` derives a parity check — any key of
    the builder's config missing from the public options fails `check:types` — and pins the README
    Layer 5 example and the `trustProxy` shapes against the published declarations. It failed
    against 0.0.26's declarations naming `maxContextEntries`.
- **Behaviour change (release process): the cookbook gates releases.** `prepublishOnly` now ends
  with `npm run test:cookbook` (each example's typecheck, then every example's tests via
  `cookbook/vitest.config.ts` projects). The cookbook had run nowhere since `d8af9ef` (2025-12)
  excluded it from the root suite — CI's root `npm ci` never installed its dependencies — and
  CI itself was removed in `acd35f1`; the last record of it running was a hand run for 0.0.24.
  Publishing now needs `cookbook/node_modules` installed (`cd cookbook && npm install`). It stays
  out of the root vitest config for the same reason it was excluded.
- **cookbook (all):** one npm workspace with one lockfile. Ten examples carried their own
  lockfiles — nine last touched 2025-12-18, tool-policies-server's 2026-01-06 — out of step with
  their manifests (zod ^3 locked where
  ^4 was declared; vitest pinned at or below 4.1.10, inside GHSA-5xrq-8626-4rwp); every example
  now uses vitest ^4.1.11.
- **cookbook (database-server):** ported from `better-sqlite3` to Node's built-in `node:sqlite`
  (Node >= 22.13). The native module was installed nowhere in the workspace, so the example and
  its 43 tests could not load; `db.transaction()` is replaced by a small BEGIN/COMMIT/ROLLBACK
  helper. The `examples/` scripts are ported too.
- **cookbook (api-wrapper-server):** the ten tests that call live public APIs run only with
  `COOKBOOK_LIVE=1`, so the release gate is deterministic offline. Three of them previously
  passed offline only because a failed fetch produced the error shape they assert.
- **cookbook (http-server, multi-endpoint-server):** tests for the 0.0.26 client-IP behaviour —
  per-client lockout behind a trusted proxy, a rotating `X-Forwarded-For` unable to dodge the
  lockout by default, and a shared `trustProxy` across handlers. All three fail against a build
  that keys on the leftmost forwarded entry.

## [0.0.26-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.26-security) (2026-10-13)

- **Security, behaviour change: per-client HTTP rate limits no longer trust client-supplied
  forwarding headers.** `getClientIp()` returned the leftmost `X-Forwarded-For` entry, else
  `X-Real-IP`, else the socket address — unconditionally. Both headers are written by the
  client, so changing either per request gave every request a fresh rate-limit key and no
  per-IP limit ever fired: the error lockout (405/400/415/408), the endpoint listener's 404
  lockout, and the GET/DELETE `sessionlessRequests*` ceilings — the only per-client control on
  SSE stream opens and session teardown. A client already locked out could keep going by adding
  the header. Message validation (Layers 1–5) was not affected. Reported privately
  (2026-10-12); reproduced against the published 0.0.25-security: 40 bad requests with a
  rotating header returned 40× 405 where a fixed address hit 429 after 20.
  - **New option `trustProxy`** on `createSecureHttpHandler`, `createSecureHttpServer`,
    `createSecureHttpsServer` and `SecureMcpServer#createHttpServer`:
    - `0` (default): the key is the socket peer; both headers are ignored.
    - an array of trusted proxy addresses, CIDRs, or `'loopback'` / `'linklocal'` /
      `'uniquelocal'`: walk `X-Forwarded-For` right to left from the peer and key on the first
      untrusted address. A request that reaches the server directly is keyed on its own address.
      This is the recommended form.
    - a hop count `N`: the Nth entry from the right. A request with fewer entries is keyed on
      the peer.
  - **Who must act:** every deployment behind a reverse proxy, load balancer or CDN. Until
    `trustProxy` is set, all clients behind the proxy share **one** budget — 60 GET/DELETE per
    minute, and a 20-errors-per-minute lockout, for everyone together — so ordinary combined
    traffic can hit 429 with no misbehaving client. Where the proxy tier has several nodes or
    edge addresses, the sharing is per node, so throttling is intermittent rather than total.
    Fail-closed on purpose; the fix is configuration, not raising the limits.
  - **The proxy must append to `X-Forwarded-For`.** A proxy that sets only `X-Real-IP`, or
    passes the client's `X-Forwarded-For` through unchanged, records no address the server can
    trust: with `trustProxy` unset its clients share the proxy's budget, and with `trustProxy`
    set the forwarded address is client-chosen. Reconfigure the proxy (nginx:
    `$proxy_add_x_forwarded_for`) before setting `trustProxy`.
  - **`X-Real-IP` is no longer read at any setting.** It has no hop structure, so a proxy that
    sets it cannot be told apart from one that passes the client's value through.
  - **Keys are normalized and IPv6 is keyed by /64.** Ports and brackets are stripped,
    IPv4-mapped IPv6 is treated as IPv4, a forwarded entry that is not an IP falls back to the
    nearest trusted hop, and IPv6 addresses key on their /64 — a single client routinely holds a
    whole /64, so per-address keys let it rotate freely. Clients sharing a /64 now share a budget.
  - **Misconfiguration is visible.** A one-time Node warning (code
    `MCP_SECURE_SERVER_TRUST_PROXY`) fires when a private-range peer sends untrusted
    `X-Forwarded-For`, when a request carries fewer entries than the hop count, or when a
    trusted proxy forwards none. The conditions were chosen so that raising `trustProxy` cannot
    silence them — a warning that any higher value quiets would reward over-trusting. Per-IP
    429s now carry `X-RateLimit-Scope: errors | sessionless | not-found` and are logged with
    their key when security logging is on.
  - **Validated at construction.** `trustProxy: true` (Express's "trust every hop") and malformed
    values or entries throw `TypeError` when the handler is created — each message names the
    specific problem, lists the valid named ranges, and links the README section — as do non-positive or
    non-integer `sessionlessRequestsPerMinute` / `sessionlessRequestsPerHour` (`NaN` or
    `Infinity` silently disabled the ceiling).
- **Security, behaviour change: the opt-in Layer 5 rate limit keys on the client address over
  HTTP.** It keyed on `Mcp-Session-Id`, but the HTTP transport is stateless (it never issues
  session ids) and the pipeline runs before the SDK, so the header was entirely client-chosen: a
  client could rotate it for a fresh budget, or exhaust the shared `'stateless'` key and block
  every header-less client. The HTTP handler now passes the resolved address as `clientId`, and
  `contextual.rateLimiting` keys on `clientId` before `sessionId`. Stdio is unchanged. Layer 4
  method-chaining state still keys on the header (recorded in SECURITY.md).
- **Fix: aborted request bodies are charged to the client that sent them.** The client address
  was read at the error site, after the body had been awaited; a client that reset mid-body no
  longer reported a peer and was charged to a shared `'unknown'` key. The address is now resolved
  once at request entry.
- **Fix: `ErrorRateLimiter` caps tracked clients** (`maxTrackedClients`, default 10,000, oldest
  evicted). Its maps grew without bound for up to two hours per key.
- **Fix: the Layer 5 context store is bounded** (`contextual.maxContextEntries`, default 10,000).
  Expired entries were deleted only when read again, so keys never re-read — one per client per
  method under `contextual.rateLimiting` — stayed for the life of the process. When full, the store
  now sweeps expired entries, then evicts the oldest.
- **Fix: the endpoint listener logs the error behind a 500** instead of discarding it.
- **API:** new `createClientIpResolver({ trustProxy, onWarning })` — build once, validated at
  construction; the HTTP factories use it. **`getClientIp` changes meaning without changing
  signature:** `getClientIp(req)` now returns the socket peer where it returned the forwarded
  address, and `getClientIp(req, { trustProxy })` re-validates on every call, so a bad value
  throws per request. Custom handlers should build a resolver with the same `trustProxy` they
  give the factory. Code that used `getClientIp` for an address allowlist behind a proxy now
  sees the proxy's address.
- **Types:** `TrustProxy`, `ClientIpOptions`, `ClientIpResolverOptions`, `ClientIpResolver`,
  `ClientIpRequest`; `HttpHandlerOptions.trustProxy`; `ErrorRateLimiterOptions.maxTrackedClients`.
- **cookbook (http-server, multi-endpoint-server):** "Behind a Reverse Proxy" sections showing
  `trustProxy`; the multi-endpoint example notes that every handler needs the same value.
- **Docs:** `SECURITY.md`'s reporting link pointed at GitHub Security Advisories while private
  vulnerability reporting was disabled on the repository, so it returned 404 and reporters had
  no private channel. Reporting is now enabled (2026-10-12); the link is unchanged.
- **Corrections to this release's first draft** (`62c9a5e`, reviewed before publish — tracker
  `mcp-secure-server` security-fix-review #14):
  - It offered a hop count only, and clamped to the **leftmost** (client-written) entry when a
    request carried fewer entries than the count, so "set it high to be safe" restored the
    bypass with no visible symptom. Replaced by the address-list form and peer fallback above.
  - Its changelog told operators whose proxy sets only `X-Real-IP` that they fail safe, then told
    them to set the hop count — which, with a pass-through proxy, recreates the bypass. Rewritten
    as the "proxy must append" item above.
  - Its `SECURITY.md` invariant ("an address the client cannot choose") was false for IPv6; it
    now names its assumptions and the /64 keying.
  - Its tests left the error-lockout and HTTPS `trustProxy` wiring uncovered: removing either
    left the suite green (mutation probes). Both are now pinned, along with the aborted-body key,
    the `clientId` passthrough and the Layer 5 key.
  - **Considered and rejected:** capping the hop count at a small maximum. Any cap is arbitrary,
    and padding the header defeats every value above the real hop count; the address list closes
    that, and the short-chain warning flags it.

## [0.0.25-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.25-security) (2026-09-24)

- **Fix, behaviour change: every call-shaped Layer 2 pattern is now anchored against word
  suffixes.** 20 patterns that begin with a function name followed by `\s*\(` had no leading
  anchor, so the name matched as the *end* of another word: `malfunction(` hit Function
  Constructor, `asleep(` hit SLEEP, `codeexec(` hit EXEC Command. Anchored:
  `sql.commandExecution` (EXEC, EXECUTE — both ALWAYS_CHECK, so this false positive reached
  STORAGE-level tools), `xss.jsExecution` (eval, Function, setTimeout, setInterval,
  requestAnimationFrame), `sql.fileOperations` / `sql.timeBasedAttacks` (LOAD_FILE, PG_SLEEP,
  BENCHMARK, SLEEP), `script.pythonInjection` / `script.nodeInjection` (`__import__`, require,
  getattr/setattr/delattr/hasattr), and the CSS `expression(` / `url(javascript:` / `url(vbscript:`
  patterns.
  - **Anchor form, deliberate:** a letter lookbehind `(?<![A-Za-z])`, not `\b`. `\b` also
    refuses a digit or underscore before the name, which opens a known evasion: MySQL
    versioned comments put digits directly before the function (`/*!50000SLEEP(5)*/`), and
    `\bsleep\(` does not match that payload; neither does it match `pg_sleep(`. Only a
    preceding *letter* makes the name a word suffix. Both evasion forms are pinned by tests.
    The two `command.executionWrappers` patterns anchored with `\b` in 0.0.20 (System Call,
    Exec Call) are left as they were.
  - **Why the whole class:** the 0.0.20 fix anchored `system(`/`exec(` in
    `command.executionWrappers` and missed the identical `exec(` in `sql.commandExecution` —
    the instance was fixed, the class was not. A derived invariant test now enumerates every
    pattern whose source begins with an identifier and `\s*\(` (24 today) and fails if any is
    unanchored; it failed against the prior code naming these 18 plus the 2 SQL exec patterns.
  - Provenance: OBSERVED as a class via a repair-mapping review of this layer (kintsugi-explorer,
    2026-09-24; tracker issue `8157271f`). A related live rejection that day — `@uluops/ops-mcp`
    refusing an `update_run` whose text quoted an `exec(` call — was a consumer policy gap
    (`recommendations` not in that tool's `relaxedFields`), not this package: relaxed fields are
    not pattern-scanned, as documented. The ALWAYS_CHECK held decision for execution categories
    (0.0.19) stands.

## [0.0.24-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.24-security) (2026-09-23)

- **Types, behaviour change at compile time: registration methods carry `McpServer`'s own types.**
  `tool`, `registerTool`, `resource`, `registerResource`, `prompt` and `registerPrompt` were
  declared `(name: string, ...rest: unknown[]) => unknown`, which erased the SDK's overloads and
  `ToolCallback<Args>` inference: handler arguments were implicitly `any`, so the README quick start
  failed `tsc --strict` (TS7031) while running fine, contradicting "register tools exactly like
  McpServer". They are now typed as `McpServer['tool']` etc. — derived from the SDK, so a new SDK
  overload is picked up rather than dropped — and `server` / `sendLoggingMessage` are typed from the
  SDK as well (were `unknown`). Runtime behaviour is unchanged. Consequences for TypeScript
  consumers, both measured:
  - Handler arguments are inferred from the Zod schema, and a handler whose return type is not a
    valid `CallToolResult` is now a compile error. A result declared as an `interface` fails (no
    implicit index signature); declare it with `type`. Twenty cookbook tool results were converted.
  - With **two copies of `zod`** (an app on Zod 3 beside the SDK's Zod 4, say), `tsc` on files that
    call `server.tool()` can exhaust memory — measured 55 s / 4.4 GB on a cookbook server, identical
    to plain `McpServer` (0.3 s / 330 MB with a single copy). The old `unknown` signatures hid this
    cost along with the types. Align on one Zod version (`npm ls zod`). Chosen deliberately over
    keeping the erased types or hand-writing lighter overloads, which would drift from the SDK.
- **New `npm run check:types`**, run by `prepublishOnly`: compiles a fixture against the package's
  own declarations and fails if registration inference regresses (unused `@ts-expect-error`
  directives trip when arguments degrade to `any`). Control: against 0.0.23-security's
  declarations it reports 7 errors.
- **JSDoc on every public `SecureMcpServer` member**, including which handlers are wrapped for
  Layer 5 response validation (`tool`, `registerTool`) and which are not (`resource`, `prompt`,
  their `register*` forms); `@returns` on the byte-size helpers.
- **Cookbook: Zod 3 → Zod 4** (`^4.1.13`, matching the framework) in the workspace root and all
  eleven servers; `database-server`'s issue formatter migrated to Zod 4 issue shapes (`origin`,
  `invalid_value`, `invalid_format`) with its messages unchanged, and `advanced-validation-server`'s
  `z.record()` given its now-required key schema. The whole cookbook typechecks against this release
  except seven pre-existing, unrelated errors (`image-gen-server/src/index-debug.ts` transport
  typings; `better-sqlite3` types not installed). Workspace tests: image-gen 46, kenpom 12, nba 14.
- **Cookbook: every `maxArgsSize` re-derived now that 0.0.23 enforces it** (64 caps, 10 servers —
  the follow-up 0.0.23's upgrade note asked consumers for and the cookbook had not done). Each cap
  was checked against the largest schema-valid payload, with free-text / name / path fields counted
  at 3 bytes per character, and the generated worst cases were fed through this branch's own
  `validateToolCall` (0 mismatches with the arithmetic; exactly-at-cap passes, one byte over fails).
  Before: OK 31, UNBOUNDED 21, TIGHT 11, **REFUSES-VALID 1** (`cli-wrapper/git-status`: cap 1024,
  valid ASCII worst case 1576 B). After: OK 62, UNBOUNDED 2 (the deliberately open `z.record`
  payloads of `api-call` and `debug-database`, whose caps are the intended sole bound). Fourteen caps
  raised to the 3-byte worst case plus headroom; unbounded fields got a schema `.max()` or regex
  (kenpom team/conference/date, nba season/name/gameId, monitoring timestamps (`.max(40)`, since
  the handler's `Date.parse` accepts forms `.datetime()` would refuse) and alert channels,
  tool-policies category/args/filter) rather than a larger cap. `write-log` and `save-note` promised
  10,240 / 50,000-character strings that the `standard` preset's Layer 1 `maxStringLength` (5,000
  characters) refuses before the schema runs — both schemas now say 5,000, with the reason inline, so
  each tool has one ceiling. nba game IDs are now format-checked by the schema (`^\d{10}$`), which
  replaces the handler's error for non-10-digit IDs with the schema's own message. Tests: repo 1290;
  cookbook kenpom 12, nba 14, image-gen 46, filesystem 57, tool-policies 48, monitoring 31,
  api-wrapper 34, cli-wrapper 94 (database-server's suite needs `better-sqlite3`, not installed).
- Dev lockfile resolves `zod` 4.6.5 (range unchanged, `^4.1.13`).
- **Refusals name the fix.** Three Layer 4 refusal reasons now end with what governs them — unknown
  method → the `methodSpec` option (with the exact `shape` entry to add), oversized arguments → the
  tool's `maxArgsSize` and the unit (UTF-8 bytes of the JSON arguments), non-object arguments → send
  a JSON object. The previous text is kept as the prefix, so code matching on it still matches. The
  reason reaches clients in `error.data.reason` (the top-level `message` stays the sanitized generic),
  as the `maxMessageSize` refusal's already did.
- **UTF-8 limits verified end to end** (they were unit-tested only): a stdio server with
  `maxArgsSize: 100` passes 40 ASCII characters (51 B) and 25 CJK characters (86 B) and refuses 40 CJK
  characters — 51 JSON characters but 131 UTF-8 bytes, which a character count would have let through.
- **Docs:** 151 unlabelled code fences tagged (all diagrams, trees and tool transcripts → `text`);
  the fifteen cookbook `examples/*.md` linked from their servers' READMEs (they were reachable from
  nothing); AGENTS.md and CLAUDE.md no longer point at a `docs/` directory and `docs/AI-preferences.md` that are in no commit, nor at a
  nonexistent `test/performance`; badges regenerated from a real run (1293 tests, 93.8% lines); this
  file's entry format is stated at the top.

## [0.0.23-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.23-security) (2026-09-22)

- **Security, behaviour change: `maxArgsSize` is enforced whether or not `argsShape` is set.** The
  per-tool cap is documented as standalone ("Max argument size in bytes"), but the check sat inside
  the `argsShape` branch of `validateToolCall`, so a tool that declared only `maxArgsSize` was never
  size-checked. All 66 declarations in this repository's cookbook had that shape, so any server that
  followed the examples had inert caps. Such servers now reject oversized arguments with
  `ARGS_EGRESS_LIMIT`; review your caps before upgrading. A `maxArgsSize` of `0` is now a cap of zero
  bytes rather than "unset". Found by the security review of the image-gen cookbook update.
- **Security, behaviour change: every size limit is measured in UTF-8 bytes, as documented.**
  `maxMessageSize` (Layer 1), `maxParamBytes` and the pre-regex input bound (Layer 2),
  `suspiciousMessageSize` (Layer 3), `maxArgsSize` and the `maxEgressBytes` estimate (Layer 4) each
  measured `JSON.stringify(...).length` — UTF-16 units — under-counting non-ASCII payloads by up to
  3x: 9,000 CJK characters measured ~9,100 against a real ~27,000 bytes and passed a 9,192-byte
  limit at every layer. One shared function now backs every enforcing check and the sizes reported
  in logs and security stats. Non-ASCII traffic near a limit may now be rejected where it passed;
  ASCII traffic measures the same. `maxStringLength`, `maxPathLength` and `maxUriLength` are
  character limits and are unchanged. Found across three rounds of pre-release review — each fix
  first covered only the sites named, until a repository-wide sweep.
- **Security, behaviour change: tool-call `arguments` / `args` must be a plain object.** Layer 4
  replaced any other value with `undefined`, so the contract check measured `{}` (2 bytes) and a
  payload sent as an array, string or number passed any `maxArgsSize` — a bypass of the fix above,
  found by its own pre-release review. Such calls are now refused with `INVALID_TOOL_ARGUMENTS` for
  every tool. MCP defines `arguments` as an object and the SDK's `CallToolRequestSchema` rejects
  anything else, so no valid call is affected; an absent `arguments` is still allowed.
- **Fix: `resources/templates/list` is allowed by default.** Layer 4's default method allowlist had
  carried `resources/list` and `resources/read` but never `resources/templates/list` since the first
  commit, so every `ResourceTemplate` a server registered was undiscoverable — the listing request
  was refused with `INVALID_MCP_METHOD` (-32602). Nothing recorded the omission as a decision; it
  surfaced when `@uluops/ops-mcp` registered its first real template. It is a read-only listing, the
  same risk class as `resources/list`. The default chaining rules gain `initialize →
  resources/templates/list` and `resources/templates/list → resources/read`, so servers that set
  `enforceChaining: true` can use templates too.
- **Behaviour change: a `methodSpec` override merges per method instead of replacing the
  allowlist.** The option was spread at the `methodSpec` level (`{ ...defaults.methodSpec,
  ...options.methodSpec }`), so an override carrying `shape` — the only field — replaced the entire
  default allowlist: passing `{ shape: { 'completion/complete': {} } }` to add one method made
  `tools/call`, `tools/list` and every other default method `INVALID_MCP_METHOD`. An override entry
  now adds a method or replaces that method's definition; methods it does not name keep their
  defaults; and `null` removes a default method, which keeps narrowing possible as an explicit act.
  The option type is the new `MethodSpecOverride`, exported from the package entry together with
  `SideEffectType` (the `ChainingRule` side-effect union, previously unreachable). No test, doc or cookbook example
  relied on the replacing behaviour; a consumer that did — deliberately passing a complete shape to
  narrow the allowlist — should now list the methods to drop as `null`.
- **Not changed, recorded:** `resources/subscribe` / `resources/unsubscribe`, `completion/complete`
  and `logging/setLevel` are in this package's own `McpMethod` type but remain outside the default
  allowlist. `subscribe` creates server-side session state and deserves its own decision; the other
  two are low-risk and can be allowed per server with a `methodSpec` override.
- **cookbook (image-gen-server):** caps re-derived now that they are enforced. `generate-image`
  rises from 5,000 to 8,192 bytes (its schema allows a 2,000-character prompt, up to 6 KB of
  UTF-8); the five image-taking tools rise from 10,000 to 49,152 bytes, just under the `standard`
  preset's 50 KB message limit — the only limit that applied before, so ~20 KB data URIs that
  worked keep working. A data URI's temporary file is named by its bytes, not its label.
- **cookbook (kenpom-server):** `kenpom-api` pinned to `^2.0.3` instead of `"*"`.
- **cookbook (image-gen-server):** move to the current image libraries — `bfl-api` 1.7.1 → 2.0.2,
  `stability-ai-api` 0.4.0 → 1.0.1, `openai-image-api` 2.0.0 → 3.1.0 — and replace the `"*"`
  ranges with carets, since `"*"` both left the lockfile on bfl-api 1.7.1 (which polled a
  moderated request until its 300 s timeout) and would admit a breaking major on a fresh install.
  The cookbook lockfile is resynced too: `npm ci` had been failing since 0.0.22-security.
- **cookbook (image-gen-server), OpenAI:** GPT Image models (`gpt-image-2.5-flare` by default)
  replace DALL-E, which openai-image-api 3.x no longer offers. `edit-image` now edits the image it
  is given — the adapter ignored it and generated a new image — and the **`create-variation` tool is
  removed**: it only ever routed to OpenAI, whose 3.x API has no variations endpoint, so it could
  only fail.
- **cookbook (image-gen-server):** provider result URLs and URL inputs are downloaded through
  stability-ai-api's SSRF-guarded `urlToBuffer` (HTTPS only, private/metadata addresses refused at
  check and connect time, 50 MB cap) instead of a bare `fetch`; saved files and returned image
  blocks take their MIME type and extension from the bytes rather than assuming PNG. The
  Stability adapter is typed against the library and sends `sd3-large` as `sd3.5-large`, which
  Stability re-routes it to server-side since 2025-04-17.
- **cookbook (image-gen-server), behaviour change:** image inputs must be an https URL or a base64
  data URI, as the tool schemas always said. Bare local paths reached the Stability and Ideogram
  libraries (and, with the OpenAI edit fix above, OpenAI's), which open any readable image on disk
  and upload it — a way to exfiltrate local images through an MCP caller. Every provider now gets a
  temporary file from `withImageFile`, which refuses paths; data URIs are size-capped (50 MB, as
  URLs) before decoding. The unused, unguarded `downloadImage` helper is removed. Found by the
  pre-merge security review.
- **cookbook:** `vitest` 4.1.11 across the three workspaces (critical advisory GHSA-5xrq-8626-4rwp in
  <=4.1.10), and `image-gen-server`'s stale second lockfile removed. Two critical advisories remain,
  `request` and `form-data` 2.x, both via `kenpom-api` → `cloudscraper`; they need a kenpom-api change.

## [0.0.22-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.22-security) (2026-09-19)

- Preserve nested union field paths in serialized Zod 3/4 tool-input diagnostics.
  Select the uniquely deeper branch; ambiguous or malformed unions retain their
  original message. SDK 1.30 may flatten branches before this sanitizer runs;
  schema-specific messages or an upstream formatter fix are still needed there.
- Document the staged installation tag and the SDK boundary in README; replace
  the quick-start evaluator with numeric addition.
- Release validation: 1,264 tests; 93.76% line and 87.78% branch coverage.
  No runtime dependency or security-policy changes from 0.0.21-security.

## [0.0.21-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.21-security) (2026-09-10)

Thirty-one of the 95 issues from the first ship-pipeline run against this package (tracker run
`ad7c956e`, project `misc/npm-packages/mcp-secure-server/src`, run #1 — security-analyst 39/100),
in two tranches on one day: the five verified criticals, then the next ten by severity. Every
critical was reproduced by execution against `dist/` before it was fixed, and each fix carries a
test that fails on the 0.0.20 code. Three of the five sat in paths the 1199-test suite could not
see, for the same reason each time: the suite never ran the artifact consumers receive.


### Security


- **layer2-content / hash-utils:** the content-validation cache key did not identify content.
  `hashObject` used `JSON.stringify(obj, Object.keys(obj).sort())`, and a replacer *array* is a
  key whitelist applied at every depth, not a sort — so `params.arguments.*` was dropped from the
  hash, and the key (method + 32-bit string hash + string length) collided for any two calls to
  the same tool with same-length arguments. The cache stores the *canonicalized text* Layer 2
  scans, so a collision handed the validator the other message's text. **Reproduced: a
  path-traversal payload blocked cold was ALLOWED after one same-length benign call warmed the
  cache** — a two-request bypass of every injection/traversal pattern for any tool. Now SHA-256
  over canonical JSON (keys sorted at every depth, array order preserved); the 32-bit hash is
  gone too, since collisions in it are findable in ~65K tries. Regression test drives the exact
  warm-cache sequence through `ContentValidationLayer`.
- **http-server:** GET (SSE open) and DELETE (session teardown) had **no control at all** — not
  even the error lockout applied, so an IP already throttled for probing could open streams and
  tear down sessions without limit. The message pipeline cannot run on them (no body), so they
  are now gated by the error lockout and by new per-IP ceilings `sessionlessRequestsPerMinute`
  (60) / `sessionlessRequestsPerHour` (600). On every method, `Mcp-Session-Id` must be visible
  ASCII ≤256 bytes (MCP spec) or the request is 400'd before the SDK or the pipeline sees it.
- **patterns:** ReDoS in the three `crlf.responseSplitting` patterns and in `Extended Dot
  Traversal`. The former were `A.*A.*B` with A = a CRLF token: every A occurrence branched two
  greedy `.*`, and `.test()` retried from every start — 1K chars 9 ms, 4K 300 ms, 8K ~2 s, 20K
  27 s, single-threaded, inside Layer 2's 2 MB cap. No regex rewrite is linear (a tempered dot is
  still quadratic over start positions, and quadratic at 2 MB is minutes), so they are now
  one-pass scanners (`linear-matchers.ts`) exposed through the same `test`/`lastIndex` shape the
  pattern loops already call; `AttackPattern.pattern` widens to `RegExp | ContentMatcher`
  (additive). Their equivalence to the old regexes is not asserted in prose — a test compares
  them against the old regexes on 3000 random strings each, and it caught a real divergence in
  the first draft (JS `.` excludes `\r`, U+2028, U+2029, not just `\n`). `Extended Dot Traversal`
  stays a RegExp with `(?:^|[^.])` pinning the run start, which makes in-run starts O(1). All
  four now clear 2 MB of pathological input in under 10 ms; a control test proves the old regex
  is super-linear so the timing assertions can fail.


- **layer5-contextual / response-validator — `failOnError` now defaults to `true`.** A custom,
  OAuth or rate-limit validator that *threw* was logged at debug level and the request
  proceeded to `createSuccessResult()`; a throwing response validator returned the raw tool
  output, silently when the logger was null (the default). Layers 1–4 fail closed on exception,
  so a throwing authorization check was the one place in the pipeline that admitted. Now
  `VALIDATOR_ERROR` blocks; `failOnError: false` is the explicit opt-out for advisory
  validators. **Behaviour change for consumers whose validators throw** — the eight tests that
  encoded the old "graceful degradation" were rewritten, and opt-out coverage added. Same edit
  replaces `(error as Error).message` on these consumer-supplied callbacks with
  `getErrorMessage()` (a validator throwing `null` crashed the layer), and `priority || 100`
  with `?? 100` (priority `0` meant "unset", not "first").
- **http-server / mcp-secure-server — one pipeline-context builder.** The stdio path
  (`transport-validator`) and the HTTP path each assembled their own `PipelineContext`; only
  stdio's carried `policy`, `logger`, `verbose`. Layer 4 reads `context.policy ?? {}`, so over
  HTTP every `sideEffects: 'write' | 'network'` tool was denied regardless of `defaultPolicy` —
  the README showed write tools on the transport where they could never run. Fourth instance
  of the "option accepted, silently dropped" class (0.0.17, 0.0.19). Both paths now call
  `SecureMcpServer._createPipelineContext()`; an integration test asserts a `defaultPolicy`-
  allowed write tool is not refused over HTTP, with a default-policy control, and a parity test
  compares the option-derived fields of the stdio and HTTP contexts for the same server.
  `TransportValidatorDependencies.createContext` is a new optional hook (additive).
- **error-sanitizer — LOW-severity `[SECURITY]` lines went to stdout.** On the stdio transport
  stdout is the JSON-RPC channel; a `tools/call` argument that merely mentioned `.gitconfig`
  emitted a non-JSON line ahead of the error response and the client's ReadBuffer threw. Every
  severity now goes to stderr when no logger is configured.
- **error-sanitizer — redaction shares detection's credential list.** `redact()` feeds
  `error.data.reason`, which is sent to the client, and its hand-rolled list lacked Google,
  Slack, `github_pat_` and the AWS secret key while the 32+-alnum fallback redacted only
  all-hex runs. `CREDENTIAL_PATTERNS` (new export from `patterns/overflow-validation`) is now the
  single source for both `secrets.common` (detection) and `redactCredentials()`; a test keyed by
  pattern name proves each shape is detected AND removed, and fails if a shape is added without
  a sample. The generic fallback now redacts any 32+ alphanumeric run (`****TOKEN****`; hex keeps
  `****HEX_KEY****`). Pre-existing placeholders keep their spelling; `****GOOGLE_API_KEY****`,
  `****SLACK_TOKEN****`, `****AWS_SECRET****` are new.
- **transport-validator — `requestIdByJsonrpcId` never pruned.** With logging on it grew one
  entry per unique JSON-RPC id for the life of the process. Its only reader is the same
  `get`/`set` (a retried id reuses its internal id) and nothing here sees the response that
  would retire an entry, so it is now a bounded FIFO window (`REQUEST_ID_MAP_MAX` = 10,000).
- **dependencies:** `@modelcontextprotocol/sdk` ^1.25.2 → ^1.30.0 (cross-client data leak,
  1.10.0–1.25.3) and `minimatch` ^10.1.1 → ^10.2.6 (ReDoS, 10.0.0–10.2.2) — both runtime.
  Dev: `vitest`/`@vitest/coverage-v8` ^3.2.4 → ^4.1.11 (arbitrary file read via the UI server;
  4.x chosen over 5.0.0 because 5 requires `@types/node` ≥22 and this package declares ^20),
  `ws` → ^8.21.3, plus `npm audit fix` for the transitive rest. `npm audit`: 23 → 0. One test
  needed a vitest-4 migration (`vi.fn()` implementations used with `new` must be constructable).

### Fixes

- **http-server:** `createSecureHttpsServer` threw `ReferenceError: require is not defined` on
  every call since 0.0.17 — `require('node:https')` in a module this package ships as ESM. It
  passed the suite because vitest supplies a `require` shim to `src/`; nothing imported `dist/`.
  Now a static import. The documented "recommended for production" TLS path works for the first
  time.
- **http-server:** the HTTP/HTTPS listeners were `async` callbacks whose promise Node discards,
  with `new URL(req.url, \`http://${req.headers.host}\`)` outside any try — `Host: a^b` threw,
  the rejection was unhandled, and under Node's default policy the process exited. One
  unauthenticated request. The URL is now parsed against a constant base (the Host header never
  contributed to endpoint matching) and the listener body is fully wrapped; both factories share
  one `createEndpointListener`, which also removes their duplicated routing block.
- **security-logger / log-formatters / validation-pipeline:** with `enableLogging: true`, a
  `POST` body of `null` crashed the process: Layer 1 correctly blocked it, then the unawaited
  `logSecurityDecision` dereferenced `message.method` in a prelude that sat outside its `try`.
  Three independent fixes, any one sufficient: the formatter is null-safe (and no longer reports
  `NaN%` block rate on a first request), the logger's prelude is inside the try, and every
  fire-and-forget call site goes through `safeLogDecision()`, which also contains a
  consumer-supplied logger that throws synchronously or rejects.

### Changed

- **secure-transport — no more double assertions.** `_handleMessage` now keeps the SDK's
  `JSONRPCMessage` and forwards that same object; the internal `McpMessage` view is a plain
  widening that needs no cast. `security-logger`'s stream/transport probes use type predicates.
  `src/` now contains zero `as unknown as`.

### Documentation

- README's Quick Start registered `calculator` with `server.tool()` but not with Layer 4, and
  its troubleshooting section said omitting `toolRegistry` "allows all tools". Neither was
  true: omission installs the three built-in `debug-*` tools and Layer 4 denies everything else
  (`TOOL_NOT_ALLOWED`). Quick Start now carries the `toolRegistry` entry; the false claim is
  replaced with the fail-closed truth and a Layer 4 test pins it. *Open design question, not
  decided here: should `server.tool()` / `registerTool()` register the tool with Layer 4?*
- README documents `failOnError`'s new default and the opt-out.
- README corrections found by the same run: the Session-ID table claimed `Mcp-Session-Id` scoped
  Layer 3 rate limits and Layer 4 quotas (both are process-global; it feeds chaining state and log
  correlation only); `@modelcontextprotocol/sdk` and `zod` were listed as *peer* dependencies (all
  four are regular dependencies); the test badge and coverage figures were hand-maintained and
  stale (1191/86% → 1250/93%); "all logging disabled by default" now says what is actually quiet
  (the file logger) and what is not (one `[SECURITY]` line to stderr per block).

### Tests

- **wrap-transport.test.js** drives `SecureMcpServer` through `connect()` and asserts on what
  the client receives (a ping result; a sanitized error with no echoed payload) instead of
  calling the private `_wrapTransport` and comparing private-field identity.
- **dist-smoke (integration):** a separate `node` process imports the compiled `dist/` and
  exercises the four entry points, the TLS path with an ephemeral `openssl` cert, and the two
  crash inputs above. This is the only instrument in the suite that can see the ESM/CJS class;
  run against the 0.0.20 build it fails 3 of 4. `prepublishOnly` already runs build before test,
  so it gates every publish.

### Known, not fixed here

The same run leaves 64 issues open. The ones an operator should know before relying on this
release: **Layer 3 rate limits and Layer 4 quotas are process-global, not per client** — one
busy client exhausts every client's budget, and the automation-timing detector (Layer 3) fires on
exactly the regular cadence an LLM agent loop produces; the audit log files are created
`mode: 0o666`; resource-policy denials echo the resolved absolute path / hostname to the client in
`error.data.reason`; client→server *responses* (sampling/elicitation results) bypass all five
layers; the `paranoid` preset's default chaining rules deny the standard client handshake after a
`ping`, and its `quotas.default.maxCallsPerMinute` keys are read by nothing; `resource()` /
`prompt()` handlers are not wrapped with response validation; the HTTP body parser decodes per
chunk (multi-byte UTF-8 split across a chunk boundary becomes U+FFFD) and size caps count UTF-16
code units, not bytes; tool policies are process-global, so two `SecureMcpServer` instances share
the last-loaded set.

## [0.0.20-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.20-security) (2026-08-23)

### Features

- **error-sanitizer:** rewrite the MCP SDK's raw tool-input validation dump into readable per-field prose. The SDK validates `inputSchema` *before* any tool handler runs, so this one error surface — the one a first-time caller hits most — bypassed every server-side error envelope. Two SDK generations, two shapes, and two delivery channels are handled:
  - **Older SDKs** throw a `-32602` protocol error whose message embeds the raw Zod issue array (`Invalid arguments for tool X: [{"code":"invalid_type",...}]`).
  - **Current SDKs** *catch their own McpError inside the tools/call handler* and wrap it into a CallToolResult (`{content, isError: true}`), with the issues formatted as `Required at project` lines — so the dump leaves the server as a JSON-RPC **result**, not an error, and no error-response hook ever sees it. Discovered live: a unit-tested error-branch fix passed 1196 tests and still missed the real path until the stdio E2E ran.
  `sanitizeOutgoingError()` now handles both: `-32602` error responses get their message rewritten in place (preserving `code`, `id`, and `error.data`), and isError tool results carrying the SDK's message get their content text rewritten (`Invalid arguments for tool X — project: Required; workflow_type: Required. Fix the named field(s) and retry…`). Anything that does not match the SDK's shapes — handler-level Zod errors, ordinary tool results, non-Zod `-32602`s — passes through byte-identical. New public methods `rewriteSdkValidationMessage(message)` and `rewriteToolErrorResult(result)` carry the parsing so consumers can unit-test the rewrites directly.
  - Provenance: OBSERVED in the 2026-08-21 LLM-client cold-call sweep of both UluOps MCP servers (tracker finding T3): the schema layer answered in raw Zod while the domain layer answered in a designed envelope — "both are recoverable, but only one teaches."

## [0.0.19-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.19-security) (2026-07-17)

### Features

- **layer1-structure:** cap provenance in limit-rejection diagnostics. A caller rejected at a Layer 1 limit faces up to four stacked ceilings (`maxStringLength`, `maxMessageSize`, `maxParamCount`, and the per-tool `maxArgsSize` from the ToolSpec registry) but the old messages named only a number — leaving the caller to isolate which ceiling fired by trial and error, and to wonder why a tool advertising a 2MB `maxArgsSize` rejected a 140KB string. Each rejection now names the configured cap that fired and its relationship to the neighboring ceilings:
  - `STRING_LIMIT_EXCEEDED` names the **offending field path** (`String parameter too long at 'raw_markdown': …`) and states that `maxStringLength` is a per-string cap separate from (and possibly lower than) the tool's `maxArgsSize`. New `extractStringsWithPaths()` helper on `ValidationLayerBase` carries key paths (never values — no data leakage) through nested objects and arrays.
  - `SIZE_LIMIT_EXCEEDED` names the `maxMessageSize` envelope cap.
  - `PARAM_LIMIT_EXCEEDED` names the `maxParamCount` cap.
  - Provenance: heidegger-analyst equipment analysis on ops-uluops-mcp (run #9, OBSTINATE-1/CONCEALMENT-2) — an OBSERVED production block where the caller could not tell from the message whether to split the payload, drop the field, or that the ToolSpec limit was a red herring.
- **layer2-content:** configurable `maxParamBytes` for the Layer 2 serialized-parameter cap. The 50000-byte cap in `validateParameters()` was hardcoded, so it silently preempted every larger ceiling around it — a tool advertising `maxArgsSize: 2MB` (Layer 4) behind a `maxMessageSize: 500KB` envelope (Layer 1) still rejected any params payload over 50KB with `OVERSIZED_PARAMS`. This is the third cap in the same series as `maxParamCount` and `maxStringLength` (0.0.17-security), now threaded identically: server option → preset → `ContentValidationLayer`. Default remains 50000 (behavior-preserving); keep at or below `maxMessageSize`.
  - Provenance: OBSERVED production block — ops-uluops-mcp `save_run` with 46 recommendations + per-agent analysis summaries (51384 bytes) rejected despite a 2MB per-tool `maxArgsSize`, forcing a save/update split.

### Fixes

- **patterns:** `command.shellAccess` patterns now require invocation context instead of matching bare mentions. `shellAccess` is an `ALWAYS_CHECK` category — it runs even for STORAGE-level tools with `relaxedFields` — so its patterns must indicate shell *access*, not shell *vocabulary*. Bare-substring matching (`/powershell/`, `/cmd\.exe/`, `/\/bin\/sh/`) bypassed the entire security-level architecture for any stored prose that mentioned a shell:
  - `PowerShell`: now requires an invocation flag or `/c` (`powershell -enc …`, `pwsh -c …`); prose like "PowerShell users" no longer matches. Encoded-command abuse remains separately covered by the CRITICAL `PowerShell EncodedCommand` pattern.
  - `Command Prompt`: now requires `/c` or `/k` (`cmd.exe /c del …`); "the installer spawns cmd.exe" no longer matches. Also matches `cmd /c` without the `.exe` suffix (previously missed).
  - `Shell Access`: now excludes shebang lines (`#!/bin/sh`) and covers `/bin/bash|dash|zsh`; non-shebang invocations (`nc … -e /bin/sh`) still flag CRITICAL.
  - Provenance: OBSERVED production block — ops-uluops-mcp `save_run` (STORAGE level, `relaxedFields` configured) rejected a positional-sweep analysis payload with "Command injection detected: PowerShell" because a finding described degraded ergonomics *for PowerShell users*.
  - Held decision: `command.shellAccess` stays in `ALWAYS_CHECK` (not demoted to QUERY/EXECUTION). Contextualized patterns kill the prose-mention FP class, but stored content quoting a *complete* shell invocation (e.g. a reverse-shell example in a security report) is still rejected at STORAGE level — accepted for now; revisit if it bites (README Layer 2 notes document the limitation and the `relaxedFields` escape hatch).

### Fixes (release-gate remediation, 2026-07-17)

Pre-promote validation (dx-validator 88 / public-interface-validator 85 / release-readiness 89, tracker run #5) surfaced a type-surface split and several silent-failure/doc-accuracy issues:

- **types:** `SecurityOptions` is now a deprecated alias of `SecureMcpServerOptions`. It was a second, independent interface that had drifted from the real constructor options (missing `securityLevel`, the size caps, `contentValidation`, and everything since 0.0.17) while the README recommended it for type-safe configuration. Aliasing removes the copy so the two can never diverge again; the README example now uses `SecureMcpServerOptions`.
- **types/factory:** `chainingDefaultAction` added to `SecureMcpServerOptions` and actually plumbed to the semantics layer — previously it was accepted structurally but silently dropped (never passed by the pipeline factory).
- **server:** unrecognized `securityLevel` now throws naming the valid presets. Previously `resolvePreset()` returned `undefined` and optional chaining silently fell back to hardcoded defaults — a server booting with a security configuration the caller never chose.
- **config:** `registerToolPolicy()` rejects invalid security levels with the valid values named. Previously stored silently; the bogus level fell through to EXECUTION behavior at lookup time.
- **config:** Zod error formatting is union-aware — an invalid inline `tools.<name>.level` now reports `tools.my_tool.level: Invalid option: expected one of "EXECUTION"|…` instead of `tools.my_tool: Invalid input` (the union with base-policy reference strings swallowed the enum diagnostic).
- **package:** `./server` and `./transport` subpath exports carry `types` conditions (previously untyped under `moduleResolution: node16`/`nodenext`); dead `CHANGELOG.md` entry removed from `.npmignore` (files-field whitelist already shipped it).

### Documentation

- README now documents the four stacked size ceilings (`maxMessageSize` → `maxStringLength` → `maxParamBytes` → `suspiciousMessageSize`) and that `suspiciousMessageSize` is a hard block, not a log-only flag — raising one cap alone moves the rejection to the next ceiling; large-payload tools must raise all four together.
- Corrected: `maxMethodLength` removed from configuration blocks (never existed as an option; the method-name limit is a fixed 100 chars, and the documented "256" contradicted actual enforcement); `getSecurityStats()` return-shape comment now matches `SecurityStats` (`{ server, behaviorLayer?, logger? }`, not the old flat counters); `ValidationResult` documented with its real required fields plus a note for TypeScript authors of custom Layer 5 validators; `createSecureHttpsServer` gets a usage example (previously the README steered readers to hand-rolled `node:https`); subpath imports and the `ErrorRateLimiter`/`getClientIp` composition pattern documented; the 0.0.6 entry's preset names corrected (`strict`/`permissive` never existed in code).

## [0.0.18-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.18-security) (2026-06-21)

### Fixes

- **security-logger:** never crash the host on an unwritable log directory; make the log directory configurable.
  - `SecurityLogger` hardcoded its log directory to the cwd-relative `'logs'` in five places and ignored all configuration. When launched with a non-writable working directory — notably MCP hosts such as Claude Desktop, which spawn servers with `cwd="/"` — the constructor's `mkdirSync('logs')` threw and crashed the host process during startup. This directly contradicted the module's own stated design principle ("logging infrastructure must NEVER crash the application").
  - The directory is now resolved once, in order: `logDir` option → `LOG_DIR` env var → `<cwd>/logs` (relative values are resolved against cwd; blank/whitespace values fall through). All paths — transports, mkdir, fsync, stats, report, verify — derive from this single absolute directory.
  - Directory and stream creation are now non-fatal. A failed `mkdir`, a `logDir` that resolves to an existing non-directory (`statSync().isDirectory()` check), or a stream that fails to open all degrade to silent no-op logging (`silent: true`, zero transports) instead of throwing. A late asynchronous write failure (disk full, perms revoked) is captured rather than swallowed.

### Features

- **security-logger:** `logDir` option on `SecureMcpServerOptions` (and the internal `SecurityLoggerOptions`), plus `LOG_DIR` env-var support.
- **security-logger:** observable degradation (visibility valve). Because the logger no longer crashes on failure, it now signals the degraded state instead of going silently dark — important for a security *audit* logger where missing records have forensic/compliance consequences. On degradation it writes a one-time warning to **stderr**, and `getStats()` (surfaced via `getSecurityStats().logger` and `getVerboseSecurityReport()`) now reports `fileLoggingAvailable`, `writeErrors`, and `lastWriteError` reflecting actual runtime state rather than configuration intent.

### Notes

- **Behavior change:** operators who relied on a startup crash as the "audit logging is broken" signal must now check `fileLoggingAvailable` (or watch stderr). This is the intended trade — a crashed security host is a worse failure than a degraded-but-observable one.
- Default behavior is unchanged for consumers whose working directory is writable: logs still land in `<cwd>/logs`.

## [0.0.17-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.17-security) (2026-06-12)

### Fixes

- **pipeline-factory:** thread `maxStringLength` from server options into Layer 1 — the option existed but was unreachable.
  - `StructureValidationLayer` has accepted a `maxStringLength` constructor option since its inception (`layer1-structure.ts` resolves `options.maxStringLength ?? LIMITS.STRING_LENGTH_MAX`), and the option is declared on the Layer 1 options type. But `createValidationPipeline()` hardcoded `maxStringLength: LIMITS.STRING_LENGTH_MAX` when constructing the layer — unlike `maxMessageSize` and `maxParamCount` on the adjacent lines, which both resolve through the `options ?? preset ?? LIMITS` fallback chain. The result: every consumer was pinned to the 5,000-char per-string cap regardless of configuration, and the knob silently absorbed any attempt to set it.
  - Production hit: an `update_run` call against the uluops-tracker MCP client carrying a 9,213-char `raw_markdown` report was rejected at Layer 1 with `String parameter too long: 9213 chars (max: 5000)` — while the tool's declared Zod schema allows 100,000 chars for that field. The consumer's `maxMessageSize: 500KB` override was honored; the string cap could not be. The schema/enforcement mismatch is the diagnostic signature of this bug: any server whose tools legitimately accept long text payloads (report markdown, document bodies) hits the hardcoded floor with no recourse.
  - Fix mirrors the sibling options exactly: `maxStringLength` added to `SecureMcpServerOptions` and `PresetConfiguration` (optional — no preset values changed), and the factory now resolves `options.maxStringLength ?? preset?.maxStringLength ?? LIMITS.STRING_LENGTH_MAX`. Default behavior is unchanged for all existing consumers.
  - Interaction note, now documented on the option's JSDoc: `maxMessageSize` must leave envelope headroom above `maxStringLength` — the JSON-RPC message wrapping a long string is larger than the string itself, and the message-size check fires first. Raising the string cap without raising the message cap moves the rejection, not the limit.
  - Regression coverage: new `test/unit/utils/pipeline-factory.test.js` exercises the threading directly (default still rejects at 5,000; override accepted; raised limit still enforces), plus layer-level boundary tests for raised and lowered values in `test/unit/layers/layer1-structure.test.js`.

## [0.0.16-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.16-security) (2026-06-11)

### Fixes

- **pattern-detection:** anchor the `System Call` and `Exec Call` execution-wrapper regexes so they no longer match identifier/word substrings (false positive surfaced by the substring `filesystem (` in benign prose).
  - Both `command.executionWrappers` patterns used an unanchored leading token: `system\s*\(` (`System Call`) and `exec\s*\(` (`Exec Call`). Because there was no left word boundary, any word ending in those letters followed by `(` satisfied the pattern — `filesystem (`, `subsystem(`, `ecosystem(` all matched `System Call`. This is the same class as the 0.0.15-security `top`/`whoami` fix, applied to the `\bcmd\s*\(` shape.
  - Production hit: a `mcp__uluops-tracker__save_run` / `update_run` call whose recommendation text contained `"... a foreign harness filesystem (codex skills dir)"` was rejected by the COMMAND_INJECTION layer with `System Call` (CRITICAL) before reaching the tracker. The substring `filesystem (` was the only trigger — rewording it to `disk` let an otherwise-identical payload through, which was the diagnostic giveaway.
  - New form prepends a `\b` word boundary: `\bsystem\s*\(` and `\bexec\s*\(`. Still fires on every real call invocation (`system("rm -rf /")`, `exec("ls")`, `; system(`, ` exec (`) but rejects suffix substrings (`filesystem (`, `subsystem(`, `codeexec(`). Regression coverage added in `test/unit/layers/patterns.test.js` covering both false-positive prevention and true-positive preservation.

## [0.0.15-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.15-security) (2026-06-07)

### Fixes

- **pattern-detection:** tighten `top` and `whoami` regexes so they no longer match identifier substrings (false positive surfaced via `topPerformers` field on a real MCP tool call)
  - Both `command.systemInfo` patterns previously used `\b<cmd>\s*` (`\btop\s*`, `\bwhoami\s*`). The `\s*` quantifier matches zero whitespace, so the patterns were satisfied by every identifier beginning with those letters: `topPerformers`, `topology`, `topic`, `topical`, `whoamiHandler`, `whoamiCheck`, etc. Camel-case API field names are particularly exposed because they reliably begin with a word boundary.
  - Production hit: Codex calling `get_ecosystem_overview({ fields: ["topPerformers"] })` against `@uluops/registry-mcp` was rejected by the COMMAND_INJECTION layer with `Top Process Monitor` before it could reach the registry's subscription-tier check. Every other `fields` value reached the intended 403 — the field name was the only one tripping the guard, which was the diagnostic giveaway.
  - New form is the bidirectional `\b<cmd>\b` — continues to fire on every real shell invocation (`top`, `top -o cpu`, `top | head`, `top; ls`, `whoami`, `whoami | grep root`, `whoami; cat /etc/passwd` — all terminate the command word with a non-word character or end-of-string) but rejects identifier substrings cleanly. Symmetric regression coverage added in `test/unit/layers/pattern-detection-level-filtering.test.js` covers both false-positive prevention and true-positive preservation.

## [0.0.14-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.14-security) (2026-04-29)

### Fixes

- **pattern-detection:** fix sub-category level filtering — EXECUTION_ONLY patterns no longer run at STORAGE/QUERY level
  - `shouldCheckConfig()` used an any-match strategy: if any sub-category of an attack config was in `ALWAYS_CHECK_CATEGORIES`, all sub-categories ran. This meant `command.systemInfo` (matches common words like "top", "env", "whoami") ran at STORAGE level because its sibling `command.shellAccess` is always-check.
  - Added `filterCategoriesForLevel()` that filters per-subcategory before pattern detection. At STORAGE level, `Command injection` now only checks `command.shellAccess` and `command.executionWrappers` — not `command.systemInfo`, `command.basicInjection`, `command.networkOperations`, or `command.fileOperations`.

- **pattern-detection:** fix stateful regex `g` flag causing intermittent false positives/negatives
  - Pattern regexes use the `g` flag on `const` objects. `RegExp.prototype.test()` with `g` updates `.lastIndex`, so repeated calls on the same regex alternate between matching and not-matching when the content differs across calls.
  - Added `pattern.lastIndex = 0` reset before every `.test()` call in `detectPatternCategories()` and `containsMaliciousContent()`.

### Why

The coarse-grained filtering caused false positives on STORAGE-level tools (issue trackers, documentation storage) when payload content contained common English words that happen to match EXECUTION_ONLY command patterns. The word "top" in an analytics summary triggered "Command injection detected: Top Process Monitor" on a `save_run` call. The security level system was designed to prevent exactly this — STORAGE tools should only check critical patterns (shell access, deserialization, XSS) not patterns that match ordinary language.

The regex statefulness bug could cause the same pattern to intermittently match or not match across sequential validation calls, producing unreproducible false positives and false negatives.

## [0.0.10-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.10-security) (2026-04-08)

### Fixes

- **sanitizer:** preserve `-32602` (Invalid params) Zod validation details in outgoing errors
  - Tool input validation errors describe the caller's input mistakes (field paths, expected types), not internal implementation state
  - Previously these were stripped and replaced with randomized generic messages ("Request validation failed" / "Invalid request format"), making errors undiagnosable
  - Non-`-32602` Zod errors (e.g., internal `-32603` errors) are still sanitized to prevent implementation leaks

### Why

When an MCP client sends invalid parameters to a tool, the Zod validation error contains exactly the information needed to fix the request: which field failed, what was expected, and what was received. The outgoing sanitizer was treating these as information leakage and replacing them with generic messages. AI agents using MCP tools would retry the same failing call with no way to self-correct. Input validation errors are part of the tool's public contract, not internal state.

## [0.0.9-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.9-security) (2026-04-05)

### Features

- **sanitizer:** include `reason` and `layer` fields in sanitized error response data
  - `createSanitizedErrorResponse` now surfaces the redacted validation reason and violation type in the JSON-RPC error `data` field, giving MCP clients actionable diagnostics instead of opaque generic messages
  - `sanitizeOutgoingError` includes reason and layer when sanitizing Zod validation patterns in outgoing responses
  - All credential/PII redaction is preserved — only the reason string (which describes the validation failure) is surfaced
- **types:** `JsonRpcErrorResponse` data type extended with optional `reason` and `layer` fields

### Why

Previously, when the security pipeline blocked a request, MCP clients received one of three randomly-selected generic messages ("Request validation failed", "Invalid request format", "Request could not be processed") with no indication of what failed or why. AI agents using MCP tools had zero diagnostic information to self-correct, leading to repeated retries of the same failing call. The `reason` field now provides the specific validation failure while maintaining the security posture.

## [0.0.7-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.7-security) (2026-03-15)

### Improvements

- Version bump for npm publish with updated dependencies

## [0.0.6-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.6-security) (2026-01-22)

### Features

- **server:** add `capabilities` option for custom MCP server capabilities
- **security:** add security presets (`basic`, `standard`, `paranoid`) for easier configuration *(this entry originally read `strict`/`permissive` — names the shipped code never had; the presets were born as `basic`/`standard`/`paranoid`/`custom`. Corrected 2026-07-17.)*
- **security:** add context-aware tool validation with security levels
- **config:** add config-driven tool policies for per-tool security rules
- **config:** add minimatch patterns for flexible path matching in policies
- **cookbook:** add `tool-policies-server` example with context-aware security levels
- **cookbook:** add `securityLevel` presets to all server examples

### Improvements

- Enhanced error logging with better context for debugging
- Improved test coverage across all security layers
- Enhanced configuration inheritance for nested options

## [0.0.1-security](https://github.com/aself101/mcp-secure-server/releases/tag/v0.0.1-security) (2026-01-02)

Initial npm release after namespace unblock.

### Features

- **5-Layer Security Pipeline** - Defense-in-depth validation architecture
  - Layer 1: Structure validation (JSON-RPC format, size limits, encoding)
  - Layer 2: Content validation (injection, XSS, path traversal, prototype pollution)
  - Layer 3: Behavior validation (rate limiting, burst detection, timing analysis)
  - Layer 4: Semantics validation (tool contracts, resource policies, quotas)
  - Layer 5: Contextual validation (custom validators, domain restrictions, OAuth)

- **SecureMcpServer** - Drop-in replacement for McpServer with built-in security
- **HTTP Transport** - `createSecureHttpServer()` and `createSecureHttpHandler()` for HTTP deployments
- **Configurable Options** - 20+ security parameters including `maxParamCount`, rate limits, quotas
- **Error Sanitization** - Prevents information leakage with credential redaction
- **TypeScript Support** - Full type definitions with strict mode, type guards included

### Security

- Comprehensive attack pattern detection (SQLi, XSS, command injection, SSRF, XXE, etc.)
- Context-aware sensitive file detection to prevent false positives
- Production-ready error handling with correlation IDs

### Documentation

- 11 cookbook examples demonstrating real-world usage patterns
- Complete API reference with TypeScript examples
- Claude Desktop integration guide
