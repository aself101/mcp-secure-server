# Changelog

All notable changes to this project will be documented in this file.

This project uses manual versioning with the `-security` suffix during the initial release phase.

> **Note:** This package was previously developed under versions 0.7.x - 1.0.x but was blocked on npm due to namespace restrictions. GitHub Support unblocked the package and published 0.0.1-security as the initial release. All future versions will build from this baseline. For historical development context, see the [commit history](https://github.com/aself101/mcp-secure-server/commits/main).

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
