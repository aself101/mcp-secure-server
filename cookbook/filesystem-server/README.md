# Filesystem MCP Server

A secure MCP server demonstrating safe file system operations with comprehensive path traversal prevention and resource policies.

## Overview

This cookbook demonstrates how to build a secure file system access layer using the MCP Security Framework. It showcases:

- **Layer 2**: Path traversal attack prevention (../../../etc/passwd)
- **Layer 4**: Resource policies with root directory restrictions
- **Layer 4**: Deny glob patterns for sensitive files (.env, .key, etc.)
- **Layer 4**: File size limits and operation quotas
- **Layer 4**: Side effect declarations (read vs write)

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Path Traversal Prevention | L2, L4 | Blocks ../, encoded variants, null bytes |
| Root Directory Restriction | L4 | Confines access to data/, documents/ |
| Deny Globs | L4 | Blocks .env, .key, secrets, /etc/** |
| File Size Limits | L4 | Max 2MB per file read |
| Side Effect Enforcement | L4 | Separates read and write operations |
| Rate Limiting | L4 | Per-tool request quotas |

## Installation

```bash
cd cookbook/filesystem-server
npm install
npm run build
```

## Configuration

### Environment Variables

```bash
# Copy example config
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `VERBOSE_LOGGING` | `false` | Enable debug logging |
| `BASE_DIR` | `cwd()` | Base directory for operations |
| `MAX_FILE_SIZE` | `2097152` | Max file size in bytes (2MB) |
| `MAX_DIR_ENTRIES` | `1000` | Max directory entries to return |
| `MAX_SEARCH_FILES` | `100` | Max files to scan in search |

### Basic Configuration

```typescript
const server = new SecureMcpServer({
  name: 'filesystem-server',
  version: '1.0.0',
}, {
  resourcePolicy: {
    rootDirs: ['./data', './documents'],
    denyGlobs: ['**/*.key', '**/.env', '/etc/**'],
    maxReadBytes: 2 * 1024 * 1024,
  },
});
```

### Advanced Configuration

```typescript
const server = new SecureMcpServer({
  name: 'filesystem-server',
  version: '1.0.0',
}, {
  toolRegistry: [
    {
      name: 'read-file',
      sideEffects: 'read',
      maxEgressBytes: 2 * 1024 * 1024,
      quotaPerMinute: 30,
    },
    {
      name: 'write-log',
      sideEffects: 'write',
      quotaPerMinute: 100,
    },
  ],
  resourcePolicy: {
    rootDirs: ['/app/data', '/app/documents', '/app/logs'],
    denyGlobs: [
      '**/*.key',
      '**/*.pem',
      '**/.env',
      '**/.env.*',
      '**/credentials*',
      '**/secrets*',
      '/etc/**',
      '/proc/**',
      '/sys/**',
    ],
    maxReadBytes: 2 * 1024 * 1024,
  },
});
```

## Tools Reference

### read-file

Read a file from allowed directories.

**Parameters:**
- `filepath` (string, required): Path to file relative to allowed directories

**Example:**
```json
{
  "filepath": "data/config.json"
}
```

**Response:**
```json
{
  "path": "data/config.json",
  "normalizedPath": "data/config.json",
  "size": 256,
  "content": "{ ... }",
  "encoding": "utf-8"
}
```

### list-directory

List contents of a directory.

**Parameters:**
- `path` (string, required): Directory path relative to allowed directories

**Example:**
```json
{
  "path": "documents"
}
```

**Response:**
```json
{
  "path": "documents",
  "totalEntries": 5,
  "returnedEntries": 5,
  "truncated": false,
  "entries": [
    { "name": "nested", "type": "directory" },
    { "name": "readme.md", "type": "file", "size": 512, "modified": "2024-01-15T..." }
  ]
}
```

### search-files

Search for text patterns within files.

**Parameters:**
- `pattern` (string, required): Text to search for (case-insensitive)
- `directory` (string, required): Directory to search in

**Example:**
```json
{
  "pattern": "password",
  "directory": "data"
}
```

**Response:**
```json
{
  "pattern": "password",
  "filesScanned": 10,
  "filesWithMatches": 2,
  "totalMatches": 5,
  "results": [
    {
      "file": "data/config.json",
      "matches": [
        { "line": 15, "column": 8, "content": "  \"passwordPolicy\": \"strong\"" }
      ]
    }
  ]
}
```

### write-log

Append a log message (write operation).

**Parameters:**
- `message` (string, required): Log message (max 5,000 characters — the `standard` preset's per-string limit)
- `level` (enum, optional): debug | info | warn | error (default: info)

**Example:**
```json
{
  "message": "User logged in successfully",
  "level": "info"
}
```

**Response:**
```json
{
  "success": true,
  "level": "info",
  "message": "User logged in successfully",
  "file": "app-2024-01-15.log",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Security Analysis

### Attacks Prevented

| Attack | Payload Example | Prevention |
|--------|-----------------|------------|
| Path Traversal | `../../../etc/passwd` | Layer 2 pattern + Layer 4 rootDir |
| URL-Encoded Traversal | `%2e%2e/%2e%2e/etc/passwd` | Decoded and blocked |
| Overlong UTF-8 | `..%c0%af/etc/passwd` | Pattern detection |
| Null Byte Injection | `file.txt\x00.jpg` | Null bytes stripped |
| Sensitive File Access | `.env`, `*.key` | Deny glob patterns |
| System File Access | `/etc/passwd`, `/proc/self/environ` | Root directory restriction |
| Large File DoS | Reading 10GB file | Max file size limit |
| Directory Enumeration | Listing entire filesystem | Root directory restriction |

### Defense in Depth

The filesystem server implements multiple layers of protection:

1. **Input Validation**: Paths are validated before any operation
2. **Pattern Detection**: Known traversal patterns blocked at Layer 2
3. **Normalization**: Paths normalized to prevent encoding bypasses
4. **Root Restriction**: Operations confined to explicit directories
5. **Deny Patterns**: Sensitive files blocked regardless of location
6. **Size Limits**: Prevents resource exhaustion attacks
7. **Side Effects**: Read/write operations separated and tracked

## Performance

| Operation | Latency (P50) | Latency (P99) | Throughput |
|-----------|---------------|---------------|------------|
| read-file | 2ms | 15ms | 500/sec |
| list-directory | 5ms | 30ms | 200/sec |
| search-files | 50ms | 200ms | 50/sec |
| write-log | 3ms | 20ms | 300/sec |

*Benchmarks on: MacBook Pro M1, 16GB RAM, SSD*

## Common Issues

### "Access denied" for valid files

Ensure the file is within `rootDirs`:
```typescript
resourcePolicy: {
  rootDirs: ['/full/path/to/data'],  // Use absolute paths in production
}
```

### Files blocked by deny patterns

Check if filename matches any deny glob:
```typescript
denyGlobs: ['**/*.key']  // Blocks any .key file
```

### Rate limit exceeded

Adjust per-tool quotas:
```typescript
{
  name: 'read-file',
  quotaPerMinute: 60,  // Increase from default 30
}
```

## Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/filesystem-server",
      "env": {
        "BASE_DIR": "/path/to/your/data",
        "VERBOSE_LOGGING": "false"
      }
    }
  }
}
```

## Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch
```

## Examples

- [Basic Usage Examples](examples/basic-usage.md)
- [Security Demonstration](examples/security-demo.md)
- [Advanced Configuration Examples](examples/advanced.md)

## License

MIT - Part of the MCP Security Framework cookbook examples.
