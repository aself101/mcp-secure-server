# Security Demonstration

This document demonstrates security features of the KenPom MCP server.

## Rate Limiting

### Request quota enforcement

After exceeding 20 requests per minute:

```text
Tool: get-ratings
Arguments: {}
```

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 20 requests per minute exceeded",
  "retryAfter": 45
}
```

### Hourly limit enforcement

After 200 requests in an hour:

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 200 requests per hour exceeded",
  "retryAfter": 1800
}
```

## Input Validation

### Invalid season parameter

```text
Tool: get-ratings
Arguments: { "season": 1990 }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Season must be 1999 or later"
}
```

### Invalid conference code

```text
Tool: get-conference-standings
Arguments: { "conference": "Big Ten" }
```

**Result: BLOCKED**
```json
{
  "error": "Invalid conference",
  "message": "Use conference abbreviation 'B10' instead of 'Big Ten'"
}
```

### Invalid metric parameter

```text
Tool: get-player-stats
Arguments: { "metric": "INVALID" }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Metric must be one of: ORtg, Min, eFG, TS, OR, DR, TO, ARate, Blk, Stl, FC40, FD40, 2P, 3P, FT"
}
```

## Argument Size Limits

### Oversized arguments

```text
Tool: get-schedule
Arguments: { "team": "A".repeat(1000) }
```

**Result: BLOCKED**
```json
{
  "error": "Argument too large",
  "message": "Arguments exceed maximum size of 500 bytes"
}
```

## Credential Protection

### Credentials never exposed

Credentials are:
- Stored only in environment variables
- Never logged to console or files
- Never included in error messages
- Never returned in responses

Example error (credentials hidden):
```json
{
  "error": "Authentication failed",
  "message": "Unable to authenticate with KenPom. Check your credentials."
}
```

NOT:
```json
{
  "error": "Authentication failed",
  "message": "Login failed for user@example.com with password ****"
}
```

## Network Policy Enforcement

### Side effect declaration

All tools declare `sideEffects: 'network'`:

```typescript
toolRegistry: [
  { name: 'get-ratings', sideEffects: 'network' },
  { name: 'get-schedule', sideEffects: 'network' },
]
```

This ensures:
- Network operations are tracked
- Rate limits apply to network calls
- Audit logging captures external API usage

### No write operations

The server is configured as read-only:

```typescript
defaultPolicy: {
  allowNetwork: true,
  allowWrites: false,
}
```

Any attempt to add write operations would be blocked.

## Injection Prevention

### SQL injection in team names

```text
Tool: get-schedule
Arguments: { "team": "Duke'; DROP TABLE teams;--" }
```

**Result: SAFE**
- Input is URL-encoded before API call
- No SQL database in this server
- KenPom API handles input safely

### Command injection attempts

```text
Tool: get-schedule
Arguments: { "team": "$(whoami)" }
```

**Result: SAFE**
- No shell execution occurs
- Input treated as literal string
- Returns "Team not found"

## Response Sanitization

### Error messages don't leak internals

Internal errors are sanitized:

**Internal:**
```text
TypeError: Cannot read property 'data' of undefined at parseRatings (parsers.js:125)
```

**Exposed:**
```json
{
  "error": "Internal error",
  "message": "Failed to fetch ratings. Please try again."
}
```

## Summary

| Security Feature | Implementation |
|-----------------|----------------|
| Rate Limiting | 20/min, 200/hr enforced |
| Input Validation | Zod schemas on all inputs |
| Credential Security | Environment variables only |
| Size Limits | 500 bytes max per argument |
| Side Effects | All tools declare 'network' |
| Error Sanitization | No internal details exposed |
| Injection Prevention | URL encoding, no shell exec |
