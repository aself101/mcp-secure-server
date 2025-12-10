# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Security Framework - a universal security-by-default middleware for Model Context Protocol (MCP) servers. Provides multi-layered defense against traditional attacks and AI-driven threats. Works like helmet for Express - wrapping any MCP server with comprehensive security validation.

## Commands

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:performance
npm run test:coverage

# Watch mode for development
npm run test:watch

# Start test server (for Claude Desktop integration)
npm run minimal-server
```

Run a single test file:
```bash
npx vitest run test/unit/utils/canonical.test.js
```

## Architecture

### Security Layer System

The framework uses a 5-layer validation pipeline:

```
Request → Layer 1 (Structure) → Layer 2 (Content) → Layer 3 (Behavior) → Layer 4 (Semantics) → Layer 5 (Contextual) → MCP Server
```

1. **Layer 1 - Structure** (`layer1-structure.js`): JSON-RPC format validation, request size limits, encoding validation
2. **Layer 2 - Content** (`layer2-content.js`): Pattern detection for path traversal, command injection, SQL injection, XSS, buffer overflow, CRLF injection
3. **Layer 3 - Behavior** (`layer3-behavior.js`): Rate limiting, burst detection, request pattern analysis
4. **Layer 4 - Semantics** (`layer4-semantics.js`): Tool contract enforcement, resource access policies, quota management
5. **Layer 5 - Contextual** (`layer5-contextual.js`): Custom validators, domain restrictions, OAuth validation, response filtering

### Key Components

- `ValidationPipeline` (`src/security/utils/validation-pipeline.js`): Orchestrates sequential layer execution
- `SecureMcpServer` (`src/security/mcp-secure-server.js`): Unified secure server with 5-layer validation
- `ContextualValidationLayer` (`src/security/layers/layer5-contextual.js`): Extensible Layer 5 for custom validators
- Attack patterns defined in `src/security/layers/layer-utils/content/dangerous-patterns.js`

### Entry Points

- Main export: `src/index.js` exports `SecureMcpServer`, `SecureTransport`, and Layer 5 utilities
- Test server: `test-server/minimal-test-server.js` demonstrates Claude Desktop integration

## Code Conventions

### Architectural Principles (from docs/AI-preferences.md)

- Files should not exceed 300 lines; split into separate concerns if needed
- Separation of concerns: each module has single, well-defined responsibility
- Reuse existing functions; avoid redundant code
- Self-explanatory code without comments (only JSDoc at function head)
- Synchronous, deterministic operations preferred over async complexity
- Apply optimizations only to proven bottlenecks with measurable impact
- Robust error handling without over-engineering

### Project-Specific Patterns

- All validation layers extend `ValidationLayerBase` from `src/security/layers/validation-layer-base.js`
- Layers must implement `validate(message, context)` returning `{ passed, allowed, severity, reason, violationType }`
- Use `ErrorSanitizer` for all error responses to prevent information leakage
- Content validation uses configuration-driven attack patterns (not hardcoded regex)

## Testing

- Test framework: Vitest
- Setup file: `test/setup/global-setup.js`
- Path aliases: `@` → `./src`, `@tests` → `./test`
- Test timeout: 10000ms

## Claude Desktop Integration

Add to Claude Desktop config:
```json
{
  "mcpServers": {
    "secure-test": {
      "command": "node",
      "args": ["test-server/minimal-test-server.js"],
      "cwd": "/path/to/mcp-security"
    }
  }
}
```

Test tools: `debug-calculator`, `debug-file-reader`, `debug-echo`, `debug-database`, `debug-http`, `debug-parser`, `debug-image`
