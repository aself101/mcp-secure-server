# KenPom MCP Server

A secure MCP server providing access to KenPom college basketball analytics and efficiency ratings.

## Overview

This cookbook demonstrates how to build a secure API wrapper MCP server using the MCP Security Framework. It showcases:

- **Layer 3**: Rate limiting for external API protection (20 req/min, 200 req/hr)
- **Layer 4**: Network side effect declarations for all tools
- **Layer 4**: Tool-specific argument size limits
- **Credential Security**: Environment-based authentication

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Rate Limiting | L3, L4 | Prevents API abuse (20/min, 200/hr) |
| Side Effect Declaration | L4 | All tools declare `network` side effects |
| Argument Size Limits | L4 | Max 500 bytes per tool argument |
| Credential Protection | Config | API credentials in environment only |
| No Write Operations | L4 | Read-only access to KenPom data |

## Installation

```bash
cd cookbook/kenpom-server
npm install
npm run build
```

## Configuration

### Environment Variables

```bash
# Copy example config
cp .env.example .env
# Edit with your KenPom credentials
```

| Variable | Required | Description |
|----------|----------|-------------|
| `KENPOM_EMAIL` | Yes | KenPom account email |
| `KENPOM_PASSWORD` | Yes | KenPom account password |

### Basic Configuration

```typescript
const server = new SecureMcpServer({
  name: 'kenpom-server',
  version: '1.0.0',
}, {
  toolRegistry: [
    { name: 'get-ratings', sideEffects: 'network', maxArgsSize: 500 },
    { name: 'get-efficiency', sideEffects: 'network', maxArgsSize: 500 },
  ],
  defaultPolicy: {
    allowNetwork: true,
    allowWrites: false,
  },
  maxRequestsPerMinute: 20,
  maxRequestsPerHour: 200,
});
```

## Tools Reference

### get-ratings

Get KenPom team efficiency ratings for a season.

**Parameters:**
- `season` (number, optional): Season year (defaults to current, min 1999)

**Example:**
```json
{ "season": 2025 }
```

### get-program-ratings

Get all-time KenPom program rankings.

**Parameters:** None

### get-efficiency

Get offensive and defensive efficiency stats.

**Parameters:**
- `season` (number, optional): Season year (defaults to current)

### get-four-factors

Get four factors stats (shooting, turnovers, rebounding, free throws).

**Parameters:**
- `season` (number, optional): Season year (defaults to current)

### get-team-stats

Get 20+ team statistics for a season.

**Parameters:**
- `season` (number, optional): Season year (defaults to current)
- `defense` (boolean, optional): Get defensive stats instead of offensive

### get-schedule

Get a team's game-by-game schedule and results.

**Parameters:**
- `team` (string, required): Team name (e.g., "Duke", "Kansas")
- `season` (number, optional): Season year (defaults to current)

### get-scouting-report

Get detailed scouting report with 70+ stats for a team.

**Parameters:**
- `team` (string, required): Team name
- `season` (number, optional): Season year
- `conferenceOnly` (boolean, optional): Only show conference games

### get-player-stats

Get individual player statistics and metrics.

**Parameters:**
- `season` (number, optional): Season year (min 2004)
- `metric` (enum, optional): ORtg, Min, eFG, TS, OR, DR, TO, ARate, Blk, Stl, FC40, FD40, 2P, 3P, FT
- `conference` (string, optional): Filter by conference
- `conferenceOnly` (boolean, optional): Only conference games

### get-conference-standings

Get conference standings for a specific conference.

**Parameters:**
- `conference` (string, required): Conference abbreviation (A10, ACC, B10, B12, SEC, etc.)
- `season` (number, optional): Season year

### get-fan-match

Get daily game predictions and fan match data.

**Parameters:**
- `date` (string, optional): Date in YYYY-MM-DD format (defaults to today)

## Security Analysis

### Rate Limiting

The server enforces strict rate limits to protect both the external API and prevent abuse:

- **Per-minute limit**: 20 requests
- **Per-hour limit**: 200 requests
- **Burst protection**: Prevents rapid sequential requests

### Credential Security

- Credentials stored in environment variables only
- Never logged or exposed in responses
- KenPom API uses session-based authentication

## Claude Desktop Integration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "kenpom": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/kenpom-server",
      "env": {
        "KENPOM_EMAIL": "your-email@example.com",
        "KENPOM_PASSWORD": "your-password"
      }
    }
  }
}
```

## Running Tests

```bash
npm test
npm run test:coverage
```

## Examples

- [Basic Usage Examples](examples/basic-usage.md)
- [Security Demonstration](examples/security-demo.md)
- [Advanced Configuration](examples/advanced.md)

## License

MIT - Part of the MCP Security Framework cookbook examples.
