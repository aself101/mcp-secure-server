# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Security Framework - a secure-by-default MCP server built on the official SDK with 5-layer validation. Provides defense-in-depth against traditional attacks and AI-driven threats.

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

# Type-level guards against built declarations (build first)
npm run check:types

# Cookbook examples: one workspace (`cd cookbook && npm install` once); gates releases via prepublishOnly
npm run test:cookbook
COOKBOOK_LIVE=1 npm run test:cookbook   # include tests that call live public APIs

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

```text
Request → Layer 1 (Structure) → Layer 2 (Content) → Layer 3 (Behavior) → Layer 4 (Semantics) → Layer 5 (Contextual) → MCP Server
```

1. **Layer 1 - Structure** (`layer1-structure.ts`): JSON-RPC format validation, request size limits, encoding validation
2. **Layer 2 - Content** (`layer2-content.ts`): Pattern detection for path traversal, command injection, SQL injection, XSS, buffer overflow, CRLF injection
3. **Layer 3 - Behavior** (`layer3-behavior.ts`): Rate limiting, burst detection, request pattern analysis
4. **Layer 4 - Semantics** (`layer4-semantics.ts`): Tool contract enforcement, resource access policies, quota management
5. **Layer 5 - Contextual** (`layer5-contextual.ts`): Custom validators, domain restrictions, OAuth validation, response filtering

### Key Components

- `ValidationPipeline` (`src/security/utils/validation-pipeline.ts`): Orchestrates sequential layer execution
- `SecureMcpServer` (`src/security/mcp-secure-server.ts`): Unified secure server with 5-layer validation
- `ContextualValidationLayer` (`src/security/layers/layer5-contextual.ts`): Extensible Layer 5 for custom validators
- Attack patterns defined in `src/security/layers/layer-utils/content/dangerous-patterns.ts`

### Entry Points

- Main export: `src/index.ts` exports `SecureMcpServer`, `SecureTransport`, and Layer 5 utilities
- Test server: `cookbook/minimal-server/minimal-test-server.ts` demonstrates Claude Desktop integration

## Code Conventions

### Architectural Principles

(Previously attributed to `docs/AI-preferences.md`, a file that is not in this repository or its history; these bullets are the canonical copy.)

- Files should not exceed 300 lines; split into separate concerns if needed
- Separation of concerns: each module has single, well-defined responsibility
- Reuse existing functions; avoid redundant code
- Self-explanatory code without comments (only JSDoc at function head)
- Synchronous, deterministic operations preferred over async complexity
- Apply optimizations only to proven bottlenecks with measurable impact
- Robust error handling without over-engineering

### Project-Specific Patterns

- All validation layers extend `ValidationLayerBase` from `src/security/layers/validation-layer-base.ts`
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
      "args": ["tsx", "cookbook/minimal-server/minimal-test-server.ts"],
      "cwd": "/path/to/mcp-security"
    }
  }
}
```

Test tools: `debug-calculator`, `debug-file-reader`, `debug-echo`, `debug-database`, `debug-http`, `debug-parser`, `debug-image`
