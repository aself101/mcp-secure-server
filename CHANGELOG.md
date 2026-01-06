## [1.4.0](https://github.com/aself101/mcp-secure-server/compare/v1.3.0...v1.4.0) (2026-01-06)

### Features

* **config:** add config-driven tool policies v2 ([5b54ea7](https://github.com/aself101/mcp-secure-server/commit/5b54ea720672106ce257e5f95b17c4d5d6eb590f))

## [1.3.0](https://github.com/aself101/mcp-secure-server/compare/v1.2.0...v1.3.0) (2026-01-06)

### Features

* **cookbook:** add tool-policies-server example with context-aware security levels ([57c1f49](https://github.com/aself101/mcp-secure-server/commit/57c1f4994ad1dee4a798a57a32b84e3e1e1911bf))

## [1.2.0](https://github.com/aself101/mcp-secure-server/compare/v1.1.0...v1.2.0) (2026-01-06)

### Features

* **security:** add context-aware tool validation with security levels ([db64aaa](https://github.com/aself101/mcp-secure-server/commit/db64aaa7191e6dbdb2c4fec3ad52cac84c7d1f9f))

# Changelog

All notable changes to this project will be documented in this file.

This project uses [Semantic Versioning](https://semver.org/) and [Conventional Commits](https://www.conventionalcommits.org/).

> **Note:** This package was previously developed under versions 0.7.x - 1.0.x but was blocked on npm due to namespace restrictions. GitHub Support unblocked the package and published 0.0.1-security as the initial release. All future versions will build from this baseline. For historical development context, see the [commit history](https://github.com/aself101/mcp-secure-server/commits/main).

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
