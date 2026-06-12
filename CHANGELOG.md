# Changelog

All notable changes to this project will be documented in this file.

This project uses manual versioning with the `-security` suffix during the initial release phase.

> **Note:** This package was previously developed under versions 0.7.x - 1.0.x but was blocked on npm due to namespace restrictions. GitHub Support unblocked the package and published 0.0.1-security as the initial release. All future versions will build from this baseline. For historical development context, see the [commit history](https://github.com/aself101/mcp-secure-server/commits/main).

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
- **security:** add security presets (`strict`, `standard`, `permissive`) for easier configuration
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
