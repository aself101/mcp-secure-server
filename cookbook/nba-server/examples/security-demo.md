# Security Demonstration

This document demonstrates security features of the NBA MCP server.

## Rate Limiting

### Request quota enforcement

After exceeding 30 requests per minute:

```text
Tool: get-player-stats
Arguments: { "playerId": 2544 }
```

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 30 requests per minute exceeded",
  "retryAfter": 45
}
```

### Hourly limit enforcement

After 500 requests in an hour:

**Result: BLOCKED**
```json
{
  "error": "Rate limit exceeded",
  "message": "Maximum 500 requests per hour exceeded",
  "retryAfter": 1200
}
```

## Input Validation

### Invalid player ID

```text
Tool: get-player-stats
Arguments: { "playerId": -1 }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Player ID must be a positive number"
}
```

### Invalid team ID

```text
Tool: get-team-roster
Arguments: { "teamId": 0 }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Invalid team ID"
}
```

### Invalid season format

```text
Tool: get-player-stats
Arguments: { "playerId": 2544, "season": "2024" }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Season must be in format YYYY-YY (e.g., 2024-25)"
}
```

### Invalid stat category

```text
Tool: get-league-leaders
Arguments: { "category": "INVALID" }
```

**Result: BLOCKED**
```json
{
  "error": "Validation failed",
  "message": "Category must be one of: PTS, REB, AST, STL, BLK, ..."
}
```

## Side Effect Handling

### Network operations properly declared

All tools that fetch from NBA.com APIs declare network side effects:

```typescript
toolRegistry: [
  { name: 'get-player-stats', sideEffects: 'network' },
  { name: 'get-live-scoreboard', sideEffects: 'network' },
]
```

### Local operation (no network)

The `find-player` tool searches a local static list:

```text
Tool: find-player
Arguments: { "name": "LeBron" }
```

**Result: SUCCESS (no network call)**
- Searches in-memory player database
- No rate limit consumed
- Declared as `sideEffects: 'none'`

## Injection Prevention

### SQL injection in player search

```text
Tool: find-player
Arguments: { "name": "'; DROP TABLE players;--" }
```

**Result: SAFE**
- No SQL database used
- String comparison only
- Returns empty results

### Command injection attempts

```text
Tool: find-player
Arguments: { "name": "$(whoami)" }
```

**Result: SAFE**
- No shell execution
- Literal string matching

## Argument Size Limits

### Oversized arguments

```text
Tool: get-player-stats
Arguments: { "playerId": 2544, "extra": "A".repeat(1000) }
```

**Result: BLOCKED**
```json
{
  "error": "Argument too large",
  "message": "Arguments exceed maximum size of 500 bytes"
}
```

## Response Sanitization

### Internal errors hidden

**Internal:**
```text
Error: ECONNREFUSED connecting to stats.nba.com
    at TCPConnectWrap.afterConnect [as oncomplete] (net.js:1141:16)
```

**Exposed:**
```json
{
  "error": "API unavailable",
  "message": "Unable to fetch data from NBA.com. Try again later."
}
```

### No stack traces

Error responses never include:
- Internal file paths
- Stack traces
- Database queries
- API endpoints

## Public API Safety

### No credentials exposed

This server uses public NBA.com APIs:
- No API keys required
- No authentication tokens
- No user credentials

### Respects API terms

Rate limiting protects against:
- Accidental abuse
- IP blocking
- Service disruption

## Summary

| Security Feature | Implementation |
|-----------------|----------------|
| Rate Limiting | 30/min, 500/hr |
| Input Validation | Zod schemas on all inputs |
| Side Effects | Network and none declarations |
| Size Limits | 500 bytes max arguments |
| Injection Prevention | No SQL, no shell execution |
| Error Sanitization | No internal details exposed |
| Public API | No credentials needed |
