# Security Demonstration

This document demonstrates attacks that are blocked by the filesystem server.

## Path Traversal Attacks

### Basic directory traversal

```text
Tool: read-file
Arguments: { "filepath": "../../../etc/passwd" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Path traversal attempt detected",
  "path": "../../../etc/passwd"
}
```

### Double-encoded traversal

```text
Tool: read-file
Arguments: { "filepath": "%2e%2e/%2e%2e/etc/passwd" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Path traversal attempt detected"
}
```

### Overlong UTF-8 encoding attack

```text
Tool: read-file
Arguments: { "filepath": "..%c0%af..%c0%af/etc/passwd" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Path traversal attempt detected"
}
```

### Windows-style traversal

```text
Tool: read-file
Arguments: { "filepath": "..\\..\\..\\windows\\system32\\config\\sam" }
```

**Result: BLOCKED**

### Traversal within allowed path

```text
Tool: read-file
Arguments: { "filepath": "data/../../../etc/passwd" }
```

**Result: BLOCKED** - Even though it starts with "data/", the traversal is detected.

## Root Directory Escape Attempts

### Absolute path outside root

```text
Tool: read-file
Arguments: { "filepath": "/etc/passwd" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Path outside allowed directories",
  "path": "/etc/passwd"
}
```

### Access to logs directory via read-file

```text
Tool: read-file
Arguments: { "filepath": "logs/app.log" }
```

**Result: BLOCKED** - The logs directory is only accessible via write-log tool.
```json
{
  "error": "Access denied",
  "message": "Path outside allowed directories"
}
```

### Accessing system directories

```text
Tool: read-file
Arguments: { "filepath": "/proc/self/environ" }
```

**Result: BLOCKED**

## Sensitive File Access

### Reading .env files

```text
Tool: read-file
Arguments: { "filepath": "data/.env" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Access to this file type is denied"
}
```

### Reading private keys

```text
Tool: read-file
Arguments: { "filepath": "data/server.key" }
```

**Result: BLOCKED** - Matches `**/*.key` deny pattern

### Reading credentials files

```text
Tool: read-file
Arguments: { "filepath": "data/credentials.json" }
```

**Result: BLOCKED** - Matches `**/credentials*` deny pattern

## Null Byte Injection

### Null byte to bypass extension check

```text
Tool: read-file
Arguments: { "filepath": "data/file.txt\u0000.jpg" }
```

**Result: SANITIZED** - Null bytes are stripped before processing

## Resource Exhaustion Attacks

### Reading oversized file

If a file exceeds the 2MB limit:

```text
Tool: read-file
Arguments: { "filepath": "data/huge-file.bin" }
```

**Result: BLOCKED**
```json
{
  "error": "File too large",
  "message": "File size (10485760 bytes) exceeds maximum allowed (2097152 bytes)",
  "size": 10485760,
  "maxSize": 2097152
}
```

### Directory listing bomb

Even if a directory has millions of entries:

```text
Tool: list-directory
Arguments: { "path": "data/huge-directory" }
```

**Result: TRUNCATED** - Limited to 1000 entries
```json
{
  "totalEntries": 1000000,
  "returnedEntries": 1000,
  "truncated": true
}
```

## Command Injection in Paths

### Shell command in path

```text
Tool: read-file
Arguments: { "filepath": "data/$(whoami).txt" }
```

**Result: SAFE** - Path is treated as literal string, file not found
```json
{
  "error": "File not found",
  "message": "The specified file does not exist"
}
```

### Backtick injection

```text
Tool: read-file
Arguments: { "filepath": "data/`id`.txt" }
```

**Result: SAFE** - No shell execution occurs

## Search Pattern Attacks

### Search with regex injection

```text
Tool: search-files
Arguments: { "pattern": ".*", "directory": "data" }
```

**Result: SAFE** - Pattern is treated as literal text, not regex
(Searches for the literal string ".*")

### Search with path traversal directory

```text
Tool: search-files
Arguments: { "pattern": "password", "directory": "../../../etc" }
```

**Result: BLOCKED**
```json
{
  "error": "Access denied",
  "message": "Path traversal attempt detected"
}
```

## Write Operation Restrictions

### Attempting to write via read-file

The read-file tool has `sideEffects: 'read'` - it cannot modify files.

### Writing to read directories

```text
Tool: write-log
Arguments: { "message": "test", "level": "info" }
```

Writes only go to the logs/ directory, never to data/ or documents/.

## Rate Limiting

### Exceeding request quota

After 30 read-file requests in one minute:

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests for tool: read-file"
}
```

## Summary

| Attack Type | Example | Result |
|-------------|---------|--------|
| Path Traversal | `../../../etc/passwd` | BLOCKED |
| URL Encoding | `%2e%2e/etc/passwd` | BLOCKED |
| UTF-8 Overlong | `..%c0%af/etc/passwd` | BLOCKED |
| Absolute Path | `/etc/passwd` | BLOCKED |
| Sensitive Files | `.env`, `*.key` | BLOCKED |
| Null Byte | `file.txt\0.jpg` | SANITIZED |
| Large Files | >2MB | BLOCKED |
| Command Injection | `$(whoami)` | SAFE |
| Rate Limit | >30/min | BLOCKED |
