# Changelog

All notable changes to this project will be documented in this file.

This project uses manual versioning with the `-security` suffix during the initial release phase.

> **Note:** This package was previously developed under versions 0.7.x - 1.0.x but was blocked on npm due to namespace restrictions. GitHub Support unblocked the package and published 0.0.1-security as the initial release. All future versions will build from this baseline. For historical development context, see the [commit history](https://github.com/aself101/mcp-secure-server/commits/main).

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
