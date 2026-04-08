# MCP Security Framework

[![npm version](https://img.shields.io/npm/v/mcp-secure-server.svg)](https://www.npmjs.com/package/mcp-secure-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-1116%20passing-brightgreen)](test/)
[![Coverage](https://img.shields.io/badge/coverage-86%25-brightgreen)](test/)

A secure-by-default MCP server built on the official SDK with 5-layer validation. Provides defense-in-depth against traditional attacks and AI-driven threats.

This framework implements defense-in-depth security with zero configuration required, protecting MCP servers from path traversal, command injection, SQL injection, XSS, prototype pollution, SSRF, and 20+ additional attack vectors.

## Quick Start

### Installation

```bash
npm install mcp-secure-server
```

### Basic Usage

```typescript
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// Create secure server with a security preset
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  { securityLevel: 'standard' }  // 'basic' | 'standard' | 'paranoid' | 'custom'
);

// Register tools exactly like McpServer
server.tool('calculator', 'Basic calculator', {
  expression: z.string()
}, async ({ expression }) => {
  // Security framework automatically blocks malicious inputs
  // NOTE: eval() used for demo only - use a safe math parser in production
  return { content: [{ type: 'text', text: `Result: ${eval(expression)}` }] };
});

// Connect - transport is automatically wrapped with security
const transport = new StdioServerTransport();
await server.connect(transport);
```

### Security Presets

Choose your security level with a single option:

```typescript
// Development: relaxed limits, minimal validation
const devServer = new SecureMcpServer(
  { name: 'dev', version: '1.0.0' },
  { securityLevel: 'basic' }
);

// Production: balanced security (default)
const prodServer = new SecureMcpServer(
  { name: 'prod', version: '1.0.0' },
  { securityLevel: 'standard' }
);

// High-security: maximum protection
const secureServer = new SecureMcpServer(
  { name: 'secure', version: '1.0.0' },
  { securityLevel: 'paranoid' }
);

// Custom: override specific values within a preset
const customServer = new SecureMcpServer(
  { name: 'custom', version: '1.0.0' },
  {
    securityLevel: 'standard',
    maxRequestsPerMinute: 60  // Override just this value
  }
);
```

| Preset | Use Case | Message Size | Rate Limit | Burst | Automation Detection |
|--------|----------|--------------|------------|-------|---------------------|
| `basic` | Development, testing | 100KB | 120/min | 30/10s | Disabled |
| `standard` | Production (default) | 50KB | 30/min | 10/10s | Enabled |
| `paranoid` | High-risk, compliance | 25KB | 15/min | 5/5s | Enabled (strict) |
| `custom` | Full control | You decide | You decide | You decide | You decide |

### Programmatic Preset Access

Access preset configurations programmatically for dynamic configuration, validation, or custom tooling:

```typescript
import {
  SECURITY_PRESETS,
  resolvePreset,
  getDefaultPreset,
  isValidPreset
} from 'mcp-secure-server';

// Get the default preset name
const defaultName = getDefaultPreset();  // 'standard'

// Validate user input
const userInput = 'paranoid';
if (isValidPreset(userInput)) {
  const config = resolvePreset(userInput);
  console.log(config.maxMessageSize);      // 25600
  console.log(config.maxRequestsPerMinute); // 15
}

// Iterate all presets for documentation or UI
for (const [name, config] of Object.entries(SECURITY_PRESETS)) {
  console.log(`${name}: ${config.maxRequestsPerMinute} req/min`);
}

// Build dynamic configuration
function createServer(env: string) {
  const level = env === 'production' ? 'paranoid' : 'basic';
  return new SecureMcpServer(
    { name: 'dynamic', version: '1.0.0' },
    { securityLevel: level }
  );
}
```

### With Logging (Opt-in)

```typescript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    securityLevel: 'standard',
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
- [Tool Policies Configuration](#tool-policies-configuration)
- [API Reference](#api-reference)
- [HTTP Transport](#http-transport)
- [Layer 5 Customization](#layer-5-customization)
- [Security Features](#security-features)
- [Attack Coverage](#attack-coverage)
- [Error Handling](#error-handling)
- [Claude Desktop Integration](#claude-desktop-integration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Cookbook Examples](#cookbook-examples)

## Cookbook Examples

Example MCP servers demonstrating the security framework. Each server includes input validation and attack prevention.

| Server | Description | Tools | Auth |
|--------|-------------|-------|------|
| [advanced-validation-server](cookbook/advanced-validation-server) | Layer 5 custom validators (PII detection, geofencing, business hours, egress tracking) | Financial query, batch process, export data, API call | None |
| [api-wrapper-server](cookbook/api-wrapper-server) | Safe REST API wrapping with domain restrictions and rate limiting | Weather, currency conversion, news headlines | None |
| [cli-wrapper-server](cookbook/cli-wrapper-server) | Safe CLI tool wrapping with command injection prevention | Git status, image resize, PDF metadata, video encode | None |
| [database-server](cookbook/database-server) | Secure database operations with SQL injection prevention | User queries, order creation, report generation | None |
| [filesystem-server](cookbook/filesystem-server) | Protected file system access with path traversal prevention | Read files, list directories, search files | None |
| [http-server](cookbook/http-server) | Simple HTTP transport with `createHttpServer()` | Calculator, echo | None |
| [image-gen-server](cookbook/image-gen-server) | Unified image generation across 5 providers (BFL, Google, Ideogram, OpenAI, Stability) | Generate, edit, upscale, describe images | API keys |
| [kenpom-server](cookbook/kenpom-server) | College basketball analytics and efficiency ratings | Ratings, schedules, scouting reports, player stats | KenPom login |
| [monitoring-server](cookbook/monitoring-server) | Observability with metrics, audit logging, and alerts | Security metrics, audit log, alerts, Prometheus export | None |
| [multi-endpoint-server](cookbook/multi-endpoint-server) | Multiple HTTP endpoints with `createSecureHttpHandler()` | Admin (list-users, system-stats), Public (health, status) | None |
| [nba-server](cookbook/nba-server) | NBA stats, live scores, and player data | Player stats, box scores, live scoreboard | None |
| [transaction-server](cookbook/transaction-server) | Method chaining enforcement for secure transaction workflows | Session, accounts, prepare/confirm/execute transactions | None |

See the [cookbook README](cookbook/README.md) for setup instructions and detailed documentation.

## Overview

The MCP Security Framework acts as a universal wrapper for any MCP server, providing comprehensive security validation through a multi-layered architecture. It implements:

- **5-Layer Defense Pipeline** - Structure, Content, Behavior, Semantics, and Contextual validation
- **Zero Configuration** - Security enabled by default with sensible defaults
- **Universal Compatibility** - Works with any MCP server using @modelcontextprotocol/sdk
- **Extensible Layer 5** - Add custom validators, domain restrictions, OAuth validation
- **Tested** - 1116 tests with 86% coverage
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
  maxParamCount: 100,         // Maximum recursive parameter count (set to Infinity to disable)
  maxMethodLength: 256        // Maximum method name length
}
```

### Layer 2 - Content Validation

Detects and blocks malicious content patterns in request parameters.

**Protections:** Path traversal, command injection, SQL/NoSQL injection, XSS, prototype pollution, XML entity attacks (XXE), CRLF injection, SSRF, CSV injection, LOLBins, GraphQL introspection, deserialization attacks, JNDI/Log4Shell, buffer overflow patterns, and more.

See [SECURITY.md](https://github.com/aself101/mcp-secure-server/blob/main/SECURITY.md#attack-vectors) for the complete list of 200+ attack patterns with examples.

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
- Burst detection (configurable time window)
- Automation detection via timing analysis
- Large message flagging

**Configuration:**
```typescript
{
  maxRequestsPerMinute: 30,   // Rate limit per minute
  maxRequestsPerHour: 500,    // Rate limit per hour
  burstThreshold: 10,         // Max requests in burst window
  burstWindowMs: 10000,       // Burst detection window in ms (default: 10s)
  suspiciousMessageSize: 20000, // Flag messages larger than this (bytes)
  automationDetection: {
    enabled: true,            // Enable timing-based automation detection
    sampleSize: 5,            // Number of requests to analyze
    maxVariance: 50,          // Max timing variance (ms) before flagging
    minInterval: 100,         // Min avg interval (ms) to flag as automation
    maxInterval: 2000         // Max avg interval (ms) to flag as automation
  }
}
```

**Automation Detection:** Analyzes request timing patterns to detect automated scripts. When enabled, it monitors the variance in request intervals - suspiciously consistent timing (low variance) indicates automation rather than human interaction.

### Layer 4 - Semantic Validation

Tool contract enforcement and resource access policies.

**Protections:**
- Tool argument validation against schemas
- Response size limits (egress control)
- Per-tool quota enforcement
- Side effect declarations
- Filesystem access control via resource policies
- Session management
- Method chaining enforcement (opt-in)

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

#### Method Chaining Enforcement

Layer 4 can enforce valid method call sequences to prevent abuse patterns like calling dangerous tools without proper initialization.

**Enable chaining enforcement:**
```typescript
{
  enforceChaining: true,           // Enable method chaining (default: false)
  chainingDefaultAction: 'deny',   // 'allow' | 'deny' when no rule matches
  chainingRules: [
    // Allow any method to call initialize
    { from: '*', to: 'initialize' },
    // After initialize, can list tools or resources
    { from: 'initialize', to: 'tools/list' },
    { from: 'initialize', to: 'resources/list' },
    // After listing tools, can call them
    { from: 'tools/list', to: 'tools/call' },
    // Tool-to-tool calls allowed
    { from: 'tools/call', to: 'tools/call' },
  ]
}
```

**ChainingRule type:**
```typescript
interface ChainingRule {
  from: string;              // Method to transition from ('*' for any)
  to: string;                // Method to transition to ('*' for any)
  fromTool?: string;         // Tool name glob pattern (e.g., 'file-*', '*-http*')
  toTool?: string;           // Tool name glob pattern
  fromSideEffect?: SideEffects;  // 'none' | 'read' | 'write' | 'network'
  toSideEffect?: SideEffects;
  action?: 'allow' | 'deny'; // Default: 'allow'
  id?: string;               // Rule identifier for logging
  description?: string;      // Human-readable description
}
```

**Advanced example - block dangerous transitions:**
```typescript
{
  enforceChaining: true,
  chainingDefaultAction: 'allow',  // Allow by default
  chainingRules: [
    // Block read tools from calling write tools directly
    {
      from: 'tools/call',
      to: 'tools/call',
      fromSideEffect: 'read',
      toSideEffect: 'write',
      action: 'deny',
      id: 'no-read-to-write'
    },
    // Block file-* tools from calling *-http* tools
    {
      from: 'tools/call',
      to: 'tools/call',
      fromTool: 'file-*',
      toTool: '*-http*',
      action: 'deny',
      id: 'no-file-to-http'
    }
  ]
}
```

Rules are evaluated first-match-wins. Tool patterns use simple glob matching (`*` = any chars, `?` = single char).

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
npm install mcp-secure-server

# Or install globally
npm install -g mcp-secure-server
```

### From Source

```bash
# Clone the repository
git clone https://github.com/aself101/mcp-secure-server.git
cd mcp-secure-server

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
} from 'mcp-secure-server';
```

### Type-Safe Configuration

```typescript
import { SecureMcpServer, SecurityOptions } from 'mcp-secure-server';

const options: SecurityOptions = {
  maxMessageSize: 50000,
  maxParamCount: 100,           // Recursive key count limit (Infinity to disable)
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
    // Layer 1 & 2 - Structure & Content Validation
    // ═══════════════════════════════════════════
    maxMessageSize: 50000,        // Max message size (bytes)
    maxParamCount: 100,           // Max recursive parameters (Infinity to disable)
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
    burstThreshold: 10,           // Max requests in burst window
    burstWindowMs: 10000,         // Burst window duration (ms)
    suspiciousMessageSize: 20000, // Flag large messages (bytes)
    automationDetection: {        // Timing-based automation detection
      enabled: true,              // Enable/disable detection
      sampleSize: 5,              // Requests to analyze
      maxVariance: 50,            // Max timing variance (ms)
      minInterval: 100,           // Min interval to flag (ms)
      maxInterval: 2000           // Max interval to flag (ms)
    },

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
    enforceChaining: false,       // Enable method chaining (default: false)
    chainingDefaultAction: 'deny', // 'allow' | 'deny' when no rule matches
    chainingRules: [              // Method transition rules
      { from: '*', to: 'initialize' },
      { from: 'initialize', to: 'tools/list' },
      { from: 'tools/list', to: 'tools/call' },
      { from: 'tools/call', to: 'tools/call' },
      // Advanced: tool patterns and side effects
      // { from: 'tools/call', to: 'tools/call', fromTool: 'read-*', toTool: 'write-*', action: 'deny' }
    ],

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

## Tool Policies Configuration

Tool policies allow you to define security levels for individual MCP tools, enabling context-aware content validation. Tools that store documentation can have relaxed pattern detection, while tools that execute commands use full validation.

### Security Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `EXECUTION` | Full validation - all attack patterns checked | Command execution, file writes, system operations |
| `QUERY` | Standard validation - SQL/NoSQL patterns added | Database queries, API calls, search operations |
| `STORAGE` | Relaxed validation - critical patterns only | Issue trackers, notes, documentation storage |
| `DISPLAY` | Minimal validation - XSS and deserialization only | Read-only queries, help output, status displays |

### Configuration File

Create a `tool-policies.json` file in your project root or specify a path via the `TOOL_POLICIES_PATH` environment variable.

**File resolution order:**
1. `TOOL_POLICIES_PATH` environment variable
2. `./tool-policies.json` (current working directory)
3. `~/.config/mcp-secure-server/tool-policies.json` (user config)

### Basic Example

```json
{
  "version": "2.0",
  "tools": {
    "save_note": {
      "level": "STORAGE",
      "relaxedFields": ["content", "title"],
      "description": "Stores user notes"
    },
    "get_status": {
      "level": "DISPLAY",
      "description": "Read-only status query"
    },
    "execute_command": {
      "level": "EXECUTION",
      "description": "Runs shell commands"
    }
  },
  "defaultLevel": "EXECUTION"
}
```

### Full Schema

```json
{
  "version": "2.0",

  "basePolicies": {
    "storage-content": {
      "level": "STORAGE",
      "relaxedFields": ["content", "description", "title"],
      "description": "Base policy for content storage tools"
    },
    "display-readonly": {
      "level": "DISPLAY",
      "description": "Base policy for read-only tools"
    }
  },

  "patterns": [
    { "match": "get_*", "policy": "display-readonly" },
    { "match": "list_*", "policy": "display-readonly" },
    { "match": "search_*", "policy": "display-readonly" },
    { "match": "{save,create,update}_*", "policy": "storage-content" }
  ],

  "tools": {
    "execute_sql": {
      "level": "QUERY",
      "description": "Database queries with SQL injection checks"
    },
    "save_document": "storage-content",
    "dangerous_operation": {
      "level": "EXECUTION",
      "description": "High-risk operation requiring full validation"
    }
  },

  "defaultLevel": "EXECUTION"
}
```

### Schema Reference

| Field | Type | Description |
|-------|------|-------------|
| `version` | `"2.0"` | Required. Schema version (must be `"2.0"`) |
| `basePolicies` | `object` | Optional. Reusable policy definitions |
| `patterns` | `array` | Optional. Glob patterns for tool matching |
| `tools` | `object` | Optional. Explicit tool policy definitions |
| `defaultLevel` | `string` | Optional. Fallback level for unknown tools |

### Policy Object

```typescript
{
  level: 'EXECUTION' | 'QUERY' | 'STORAGE' | 'DISPLAY',  // Security level
  relaxedFields?: string[],  // Fields with relaxed validation
  skipPatterns?: string[],   // Pattern categories to skip
  description?: string,      // Documentation
  extends?: string           // Inherit from base policy
}
```

### Pattern Matching

Patterns use [minimatch](https://github.com/isaacs/minimatch) glob syntax:

| Pattern | Matches |
|---------|---------|
| `get_*` | `get_users`, `get_status`, `get_config` |
| `*_issues` | `query_issues`, `search_issues`, `list_issues` |
| `{get,list}_*` | `get_users`, `list_users`, `get_config`, `list_items` |
| `file-*` | `file-read`, `file-write`, `file-delete` |
| `v?_tool` | `v1_tool`, `v2_tool` |

**Resolution order:**
1. Explicit tool definitions (highest priority)
2. Pattern matching (first match wins)
3. `defaultLevel` from config
4. `EXECUTION` level (secure default)

### Inheritance with `extends`

Policies can inherit from base policies and add/override fields:

```json
{
  "version": "2.0",
  "basePolicies": {
    "base-storage": {
      "level": "STORAGE",
      "relaxedFields": ["content"]
    }
  },
  "tools": {
    "save_note": {
      "extends": "base-storage",
      "relaxedFields": ["extra_field"],
      "description": "Inherits STORAGE level, merges relaxedFields"
    }
  }
}
```

The result for `save_note`:
- `level`: `STORAGE` (inherited)
- `relaxedFields`: `["content", "extra_field"]` (merged and deduplicated)

### Relaxed Fields

The `relaxedFields` array specifies parameter names that should use `STORAGE`-level validation regardless of the tool's overall level. Useful for tools that have both sensitive and content parameters:

```json
{
  "tools": {
    "create_issue": {
      "level": "QUERY",
      "relaxedFields": ["description", "title"],
      "description": "QUERY level for project/priority, STORAGE for text content"
    }
  }
}
```

### Runtime Registration

You can also register tool policies programmatically:

```typescript
import { registerToolPolicy } from 'mcp-secure-server';

registerToolPolicy('my_custom_tool', {
  level: 'STORAGE',
  relaxedFields: ['content', 'notes'],
  description: 'Custom documentation tool'
});
```

### Loading Configuration Programmatically

```typescript
import { initializeToolPolicies, resetToolPolicies } from 'mcp-secure-server';

// Load from object
initializeToolPolicies({
  version: '2.0',
  patterns: [
    { match: 'get_*', policy: { level: 'DISPLAY' } }
  ],
  defaultLevel: 'QUERY'
});

// Reset to defaults
resetToolPolicies();
```

### Validation Behavior by Level

| Level | Checks SQL/NoSQL | Checks Command Injection | Checks Path Traversal | Checks XSS |
|-------|-----------------|-------------------------|----------------------|------------|
| `EXECUTION` | ✅ | ✅ | ✅ | ✅ |
| `QUERY` | ✅ | ❌ | ✅ | ✅ |
| `STORAGE` | ❌ | ❌ | ❌ | ✅ |
| `DISPLAY` | ❌ | ❌ | ❌ | ✅ |

All levels always check for XSS and deserialization attacks as these are universally dangerous.

### Advanced Tool Policy Helpers

Additional utilities for programmatic tool policy management:

```typescript
import {
  getToolsByLevel,
  isRelaxedField,
  isValidSecurityLevel,
  defaultToolPolicies
} from 'mcp-secure-server';

// Get all tools configured at a specific security level
const storageLevelTools = getToolsByLevel('STORAGE');
// Returns: ['save_note', 'create_document', ...]

// Check if a field has relaxed validation for a tool
if (isRelaxedField('save_note', 'content')) {
  // 'content' field uses STORAGE-level validation
}

// Validate security level strings
if (isValidSecurityLevel(userInput)) {
  // userInput is 'EXECUTION' | 'QUERY' | 'STORAGE' | 'DISPLAY'
}

// Access default policies (useful for extending)
const defaults = defaultToolPolicies;
```

**Use cases:**
- **Auditing:** List all tools at each security level
- **Debugging:** Check if a specific field is relaxed
- **Dynamic configuration:** Validate user-provided security levels
- **Testing:** Access defaults for baseline comparison

## API Reference

### SecureMcpServer

Drop-in replacement for McpServer with built-in 5-layer security.

```typescript
import { SecureMcpServer } from 'mcp-secure-server';

const server = new SecureMcpServer(serverInfo, options);
```

#### MCP SDK Passthrough Methods

SecureMcpServer delegates to the underlying McpServer for most operations. Some methods add security enhancements.

**Enhanced Methods** (security added):

| Method | Enhancement |
|--------|-------------|
| `tool()` | Response validation via Layer 5 |
| `registerTool()` | Response validation via Layer 5 |
| `connect()` | Wraps transport with SecureTransport |

**Pure Passthrough Methods** (direct delegation to McpServer):

```typescript
// Resource and prompt registration
server.resource(name, uri, handler);
server.prompt(name, description, handler);

// Connection management
await server.close();
server.isConnected();

// Notification methods (MCP SDK passthrough)
server.sendResourceListChanged();
server.sendToolListChanged();
server.sendPromptListChanged();
```

**Example with all registration types:**

```typescript
const server = new SecureMcpServer({ name: 'demo', version: '1.0.0' });

// Tool registration (response validation enabled)
server.tool('add', 'Add numbers', { a: z.number(), b: z.number() },
  async ({ a, b }) => ({ content: [{ type: 'text', text: `${a + b}` }] })
);

// Resource registration (passthrough)
server.resource('config', 'config://app', async () => ({
  contents: [{ uri: 'config://app', text: JSON.stringify(config) }]
}));

// Prompt registration (passthrough)
server.prompt('greeting', 'Generate greeting', async () => ({
  messages: [{ role: 'user', content: { type: 'text', text: 'Hello!' } }]
}));

await server.connect(new StdioServerTransport());
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
import { SecureTransport } from 'mcp-secure-server';

const secureTransport = new SecureTransport(
  transport,       // Original transport
  validator,       // Validation function
  {
    errorSanitizer // Optional error sanitizer
  }
);
```

### HTTP Transport

For remote MCP servers, use the built-in HTTP transport with security validation. Zero external dependencies - uses `node:http` directly.

```typescript
import { SecureMcpServer } from 'mcp-secure-server';
import { z } from 'zod';

const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  { enableLogging: true }
);

server.tool('add', 'Add two numbers', {
  a: z.number(),
  b: z.number()
}, async ({ a, b }) => ({
  content: [{ type: 'text', text: `${a + b}` }]
}));

// Create HTTP server with security validation
const httpServer = server.createHttpServer({ endpoint: '/mcp' });
httpServer.listen(3000, () => {
  console.log('MCP server listening on http://localhost:3000/mcp');
});
```

**Configuration options:**

```typescript
interface HttpServerOptions {
  endpoint?: string;      // MCP endpoint path (default: '/mcp')
  maxBodySize?: number;   // Max body size in bytes (default: 51200 = 50KB)
}
```

**Session ID handling:**

| Source | Value | Used By |
|--------|-------|---------|
| `Mcp-Session-Id` header | Client-provided | Layer 3 rate limiting, Layer 4 quotas |
| Missing header | `'stateless'` | Shared limits across all requests |

**Standalone function:**

```typescript
import { SecureMcpServer, createSecureHttpServer } from 'mcp-secure-server';

const server = new SecureMcpServer({ name: 'x', version: '1.0' });
const httpServer = createSecureHttpServer(server, { endpoint: '/api/mcp' });
httpServer.listen(8080);
```

**Multiple endpoints:**

For services exposing multiple MCP servers on different paths, use `createSecureHttpHandler` to compose your own routing:

```typescript
import { SecureMcpServer, createSecureHttpHandler } from 'mcp-secure-server';
import { createServer } from 'node:http';

// Create separate MCP servers with different tools/permissions
const adminServer = new SecureMcpServer({ name: 'admin', version: '1.0' });
const publicServer = new SecureMcpServer({ name: 'public', version: '1.0' });

// Register tools on each server
adminServer.tool('delete-user', ...);
publicServer.tool('get-status', ...);

// Create handlers (validates requests, forwards to MCP SDK transport)
const adminHandler = createSecureHttpHandler(adminServer);
const publicHandler = createSecureHttpHandler(publicServer);

// Compose with custom routing
const httpServer = createServer(async (req, res) => {
  if (req.url?.startsWith('/api/admin')) return adminHandler(req, res);
  if (req.url?.startsWith('/api/public')) return publicHandler(req, res);
  res.writeHead(404).end(JSON.stringify({ error: 'Not found' }));
});

httpServer.listen(3000);
```

| Function | Purpose |
|----------|---------|
| `createSecureHttpServer` | Single endpoint, includes routing |
| `createSecureHttpHandler` | Request handler only, you provide routing |

**CORS:** Add headers manually or wrap with a CORS middleware.

**HTTPS:** Use `node:https` with the same pattern, or deploy behind a reverse proxy.

### Available Exports

```typescript
import {
  SecureMcpServer,            // Main secure server class
  SecureTransport,            // Transport wrapper
  createSecureHttpServer,     // HTTP server factory (single endpoint)
  createSecureHttpHandler,    // HTTP handler factory (multi-endpoint)
  createSecureHttpsServer,    // HTTPS server factory with TLS
  ErrorRateLimiter,           // Rate limiter for error responses
  getClientIp,                // Extract client IP from request
  ContextualValidationLayer,  // Layer 5 class
  ContextualConfigBuilder,    // Builder for Layer 5 config
  createContextualLayer,      // Factory for Layer 5
  // Tool policy configuration
  initializeToolPolicies,     // Load config from object
  resetToolPolicies,          // Reset to defaults
  registerToolPolicy,         // Register policy at runtime
  getToolPolicy,              // Get policy for a tool
  isRelaxedField,             // Check if field has relaxed validation
  getToolsByLevel,            // List tools by security level
  isValidSecurityLevel,       // Validate security level string
  defaultToolPolicies,        // Default policy definitions
  getToolPoliciesConfig,      // Get current policies config
  loadToolPoliciesConfig,     // Load from file
  matchesPattern,             // Check if tool matches pattern
  resolvePolicy,              // Resolve policy for tool
  ToolPolicyError,            // Config error class
  // Security presets
  SECURITY_PRESETS,           // All preset definitions
  resolvePreset,              // Get preset by name
  getDefaultPreset,           // Get default preset name
  isValidPreset,              // Validate preset name
  // Type guards
  isSeverity,                 // Type guard for Severity
  isViolationType,            // Type guard for ViolationType
  isError,                    // Type guard for Error objects
  getErrorMessage             // Safe error message extraction
} from 'mcp-secure-server';
```

| Export | Description |
|--------|-------------|
| `SecureMcpServer` | Drop-in replacement for McpServer with 5-layer security |
| `SecureTransport` | Transport wrapper for message-level validation |
| `createSecureHttpServer` | HTTP server factory with security validation |
| `createSecureHttpHandler` | HTTP handler for composing multi-endpoint servers |
| `createSecureHttpsServer` | HTTPS server factory with TLS certificates |
| `ErrorRateLimiter` | Rate limiter for clients generating excessive errors |
| `getClientIp` | Extract client IP from request (X-Forwarded-For aware) |
| `ContextualValidationLayer` | Layer 5 class for advanced customization |
| `ContextualConfigBuilder` | Builder for Layer 5 configuration |
| `createContextualLayer` | Factory function for Layer 5 with defaults |
| `initializeToolPolicies` | Load tool policies from config object |
| `resetToolPolicies` | Reset to default (empty) policies |
| `registerToolPolicy` | Register single tool policy at runtime |
| `getToolPolicy` | Get resolved policy for a tool name |
| `isRelaxedField` | Check if a field has relaxed validation for a tool |
| `getToolsByLevel` | List tools registered at a specific security level |
| `isValidSecurityLevel` | Validate if a string is a valid security level |
| `defaultToolPolicies` | Default policy definitions for tools |
| `getToolPoliciesConfig` | Get current tool policies configuration |
| `loadToolPoliciesConfig` | Load policies from JSON file |
| `matchesPattern` | Check if tool name matches a pattern (glob-style) |
| `resolvePolicy` | Resolve merged policy for a tool from config |
| `ToolPolicyError` | Error class for config validation failures |
| `SECURITY_PRESETS` | Object containing all preset definitions (basic, standard, paranoid) |
| `resolvePreset` | Get preset configuration by name |
| `getDefaultPreset` | Get the default preset name ('standard') |
| `isValidPreset` | Validate if a string is a valid preset name |
| `isSeverity` | Type guard to check if value is a valid Severity |
| `isViolationType` | Type guard to check if value is a valid ViolationType |
| `isError` | Type guard to check if value is an Error object |
| `getErrorMessage` | Safely extract error message from unknown value |

## Layer 5 Customization

Layer 5 is enabled by default. You can add custom validators at runtime for application-specific security rules.

### Adding Custom Validators

```typescript
import { SecureMcpServer } from 'mcp-secure-server';

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

See [SECURITY.md](https://github.com/aself101/mcp-secure-server/blob/main/SECURITY.md) for full security documentation including:
- Attack detection coverage (injection, XSS, SSRF, deserialization, etc.)
- Security best practices applied
- SSRF protection details
- Error sanitization
- Reporting vulnerabilities

## Attack Coverage

The framework detects and blocks 200+ attack patterns across 19 categories including injection attacks, path traversal, SSRF, deserialization, and more.

See [SECURITY.md](https://github.com/aself101/mcp-secure-server/blob/main/SECURITY.md#attack-vectors) for the complete threat model with:
- Attack vectors and examples
- Severity levels and detection layers
- Mitigation strategies
- Violation type reference

## Error Handling

### Validation Errors

When the security pipeline blocks a request, the framework returns a JSON-RPC error with diagnostic context in the `data` field:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Request validation failed",
    "data": {
      "timestamp": "2026-04-05T06:00:00.000Z",
      "token": "a1b2c3d4e5f6",
      "reason": "Content validation: path traversal pattern detected in parameter 'file_path'",
      "layer": "VALIDATION_ERROR"
    }
  }
}
```

The `data` fields help MCP clients diagnose failures:

| Field | Description |
|-------|-------------|
| `timestamp` | When the error occurred (ISO 8601) |
| `token` | Unique error token for log correlation |
| `reason` | Redacted validation reason describing what failed and why |
| `layer` | Which validation layer or violation type triggered the block |
| `retryAfterMs` | Present only for `RATE_LIMIT_EXCEEDED` — milliseconds to wait |

The `reason` field is sanitized through the same credential/PII redaction pipeline used for logging, so it is safe to surface to clients while still providing actionable diagnostics.

### Error Codes

| Code | Violation Type | Meaning |
|------|---------------|---------|
| `-32602` | `VALIDATION_ERROR`, `POLICY_VIOLATION`, `CONTEXT_VIOLATION` | Invalid input or policy block |
| `-32000` | `RATE_LIMIT_EXCEEDED` | Too many requests — check `retryAfterMs` |
| `-32603` | `INTERNAL_ERROR` | Internal validation error |

### Severity Levels

| Severity | Description | Action |
|----------|-------------|--------|
| `CRITICAL` | Active exploit attempt (command injection, deserialization) | Block + Alert |
| `HIGH` | Serious attack (SQL injection, path traversal) | Block |
| `MEDIUM` | Suspicious activity (rate limit, size exceeded) | Block |
| `LOW` | Minor policy violation | Block or Warn |

### Outgoing Response Sanitization

The framework sanitizes outgoing JSON-RPC error responses that contain Zod validation patterns, with one important exception: **`-32602` (Invalid params) errors are preserved**. These errors describe the caller's input mistakes — field paths, expected types, and size limits — which are the input contract, not internal implementation details. Preserving them lets callers diagnose and fix their requests.

For non-`-32602` errors that contain Zod patterns (e.g., internal `-32603` errors), the framework replaces the response with a safe generic message:

```json
{
  "error": {
    "code": -32602,
    "message": "Invalid input parameters",
    "data": {
      "reason": "Input failed schema validation (Zod). Check parameter types and required fields.",
      "layer": "OUTGOING_SANITIZER"
    }
  }
}
```

This prevents internal Zod schema structures from leaking to clients while preserving actionable validation feedback on input errors.

### Type Guards for Error Handling

```typescript
import { isError, getErrorMessage, isSeverity } from 'mcp-secure-server';

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
      "args": ["tsx", "cookbook/minimal-server/minimal-test-server.ts"],
      "cwd": "/path/to/mcp-secure-server"
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
- 1066 comprehensive tests
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
├── index.ts                              # Main entry point & public exports
├── types/                                # TypeScript type definitions
│   ├── index.ts                          # Type exports & guards
│   ├── layers.ts                         # Layer type definitions
│   ├── messages.ts                       # MCP message types
│   ├── policies.ts                       # Policy type definitions
│   ├── server.ts                         # Server configuration types
│   └── validation.ts                     # Validation result types
└── security/
    ├── index.ts                          # Security module exports
    ├── mcp-secure-server.ts              # SecureMcpServer class
    ├── constants.ts                      # Configuration constants
    ├── transport/
    │   ├── index.ts                      # Transport exports
    │   ├── secure-transport.ts           # SecureTransport (stdio)
    │   └── http-server.ts                # HTTP transport server
    ├── layers/
    │   ├── validation-layer-base.ts      # Base class for all layers
    │   ├── layer1-structure.ts           # JSON-RPC validation
    │   ├── layer2-content.ts             # Content/injection detection
    │   ├── layer2-validators/            # Modular content validators
    │   │   ├── index.ts                  # Validator exports
    │   │   ├── pattern-detection.ts      # Attack pattern matching
    │   │   ├── base64-css.ts             # Base64/CSS attack detection
    │   │   └── data-semantics.ts         # Data format validation
    │   ├── layer3-behavior.ts            # Rate limiting & burst detection
    │   ├── layer4-semantics.ts           # Tool contracts & policies
    │   ├── layer5-contextual.ts          # Custom validators
    │   ├── contextual-config-builder.ts  # Layer 5 fluent configuration
    │   └── layer-utils/
    │       ├── content/
    │       │   ├── canonicalize.ts       # Text normalization
    │       │   ├── unicode.ts            # Unicode attack normalization
    │       │   ├── dangerous-patterns.ts # Pattern configuration
    │       │   ├── helper-utils.ts       # Content helper functions
    │       │   ├── patterns/             # Attack pattern definitions
    │       │   │   ├── index.ts          # Pattern exports & utilities
    │       │   │   ├── injection.ts      # SQL/XSS/NoSQL patterns
    │       │   │   ├── path-traversal.ts # Path traversal patterns
    │       │   │   ├── network.ts        # SSRF/network patterns
    │       │   │   └── overflow-validation.ts # Buffer/encoding patterns
    │       │   └── utils/
    │       │       ├── index.ts          # Utility exports
    │       │       ├── text-decoding.ts  # Encoding detection
    │       │       ├── hash-utils.ts     # Cache key generation
    │       │       └── structural-analysis.ts # Deep structure analysis
    │       └── semantics/
    │           ├── semantic-policies.ts  # Tool/resource policies
    │           └── semantic-quotas.ts    # Quota management
    └── utils/
        ├── validation-pipeline.ts        # Multi-layer orchestration
        ├── security-logger.ts            # Security event logging
        ├── error-sanitizer.ts            # Safe error responses
        ├── request-normalizer.ts         # Request normalization
        ├── response-validator.ts         # Response validation
        └── tool-registry.ts              # Tool management

cookbook/                                 # Example MCP servers
├── http-server/                          # HTTP transport example
├── multi-endpoint-server/                # Multi-endpoint routing
├── image-gen-server/                     # Image generation APIs
├── kenpom-server/                        # Sports analytics API
├── nba-server/                           # NBA statistics API
├── api-wrapper-server/                   # Safe external API wrapper
├── database-server/                      # SQL injection prevention
├── filesystem-server/                    # Path traversal prevention
├── cli-wrapper-server/                   # Command injection prevention
├── monitoring-server/                    # Security metrics & alerts
├── transaction-server/                   # State machine workflows
└── advanced-validation-server/           # Advanced security demos
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

### SQL Injection Detected (False Positive)

```
Error: Request blocked: SQL injection detected
```

**Cause:** Content contains SQL-like keywords (SELECT, DROP, UNION) in legitimate text.

**Solutions:**
1. Use tool policies to relax validation for content storage tools:
```json
{
  "version": "2.0",
  "tools": {
    "save_document": {
      "level": "STORAGE",
      "relaxedFields": ["content", "description"]
    }
  }
}
```

2. Set the tool's security level programmatically:
```typescript
import { registerToolPolicy } from 'mcp-secure-server';

registerToolPolicy('save_document', {
  level: 'STORAGE',
  relaxedFields: ['content']
});
```

### Command Injection Detected (False Positive)

```
Error: Request blocked: Command injection detected
```

**Cause:** Content contains shell characters (|, ;, &&, backticks) in legitimate text.

**Solution:** Same as SQL injection - use `STORAGE` level for content tools:
```typescript
registerToolPolicy('save_code_snippet', {
  level: 'STORAGE',
  relaxedFields: ['code']
});
```

### XSS Attempt Detected (False Positive)

```
Error: Request blocked: XSS attempt detected
```

**Cause:** Content contains HTML/script tags in legitimate documentation.

**Solution:** Use `DISPLAY` level for read-only display tools:
```typescript
registerToolPolicy('render_markdown', {
  level: 'DISPLAY'
});
```

### Semantic Validation: Missing Required Parameter

```
Error: Request blocked: Missing required parameter
```

**Cause:** Tool is registered in `toolRegistry` with `argsShape` that doesn't match the request.

**Solution:** Verify tool schema matches expected parameters:
```typescript
{
  toolRegistry: [{
    name: 'my-tool',
    argsShape: {
      query: { type: 'string', required: true },
      limit: { type: 'number' }  // optional
    }
  }]
}
```

### Semantic Validation: Tool Not Registered

```
Error: Request blocked: Tool not registered
```

**Cause:** Tool called via MCP but not in server's `toolRegistry`.

**Solutions:**
1. Register all tools you expose:
```typescript
{
  toolRegistry: [
    { name: 'tool-a', sideEffects: 'none' },
    { name: 'tool-b', sideEffects: 'read' }
  ]
}
```

2. Or allow unknown tools (less secure):
```typescript
// Don't include toolRegistry - all tools allowed
```

### Message Size Exceeded

```
Error: Request blocked: Message size exceeds limit
```

**Solution:** Increase message size limit:
```typescript
{
  maxMessageSize: 100000  // 100KB (default: 50KB)
}
```

### Burst Activity Detected

```
Error: Request blocked: Burst activity detected
```

**Cause:** Too many requests in the burst detection window.

**Solutions:**
1. Increase burst threshold:
```typescript
{
  burstThreshold: 20  // Max requests in window (default: 10)
}
```

2. Extend the burst window:
```typescript
{
  burstWindowMs: 15000  // 15 seconds (default: 10000)
}
```

3. Use the `basic` preset for development:
```typescript
{
  securityLevel: 'basic'  // 30 burst threshold, 10s window
}
```

### Automated Timing Pattern Detected

```
Error: Request blocked: Automated timing pattern detected
```

**Cause:** Requests are arriving at suspiciously consistent intervals, suggesting automation.

**Solutions:**
1. Disable automation detection (for legitimate automation):
```typescript
{
  automationDetection: { enabled: false }
}
```

2. Adjust detection thresholds:
```typescript
{
  automationDetection: {
    enabled: true,
    maxVariance: 100,   // Allow more timing variance (default: 50ms)
    sampleSize: 10      // Require more samples (default: 5)
  }
}
```

3. Use the `basic` preset (automation detection disabled):
```typescript
{
  securityLevel: 'basic'
}
```

### Suspiciously Large Message

```
Error: Request blocked: Suspiciously large message
```

**Cause:** Message exceeds the suspicious size threshold.

**Solution:** Increase the threshold:
```typescript
{
  suspiciousMessageSize: 50000  // 50KB (default: 20KB)
}
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

**Disclaimer:** This framework provides defense-in-depth security but cannot guarantee protection against all attacks. Always follow security best practices and keep dependencies updated.
