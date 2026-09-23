# NBA MCP Server

A secure MCP server providing NBA statistics, live scores, and player/team data from public APIs.

## Overview

This cookbook demonstrates how to build a sports data MCP server using the MCP Security Framework. It showcases:

- **Layer 3**: Rate limiting for public API protection (30 req/min)
- **Layer 4**: Network side effect declarations
- **Layer 4**: Mixed side effects (find-player is local, others are network)
- **Real-time Data**: Live scoreboard and box scores
- **No Authentication**: Uses public NBA.com APIs

## Security Features Demonstrated

| Feature | Layer | Description |
|---------|-------|-------------|
| Rate Limiting | L3, L4 | 30 req/min, 500 req/hr |
| Side Effect Declaration | L4 | Network for API calls, none for local search |
| Argument Size Limits | L4 | 500 bytes per tool argument |
| No Write Operations | L4 | Read-only access to NBA data |

## Installation

```bash
cd cookbook/nba-server
npm install
npm run build
```

## Configuration

### Environment Variables

```bash
# Copy example config (optional - no credentials needed)
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `VERBOSE_LOGGING` | `false` | Enable debug logging |

## Tools Reference

### Player Tools

#### find-player
Search for NBA players by name. **Local operation - no network call.**

**Parameters:**
- `name` (string, required): Player name to search for

#### get-player-info
Get biographical info for an NBA player.

**Parameters:**
- `playerId` (number, required): NBA player ID

#### get-player-stats
Get career statistics for an NBA player.

**Parameters:**
- `playerId` (number, required): NBA player ID
- `season` (string, optional): Season (e.g., "2024-25")

#### get-player-game-log
Get game-by-game stats for an NBA player.

**Parameters:**
- `playerId` (number, required): NBA player ID
- `season` (string, optional): Season (e.g., "2024-25")

### Team Tools

#### get-team-roster
Get the current roster for an NBA team.

**Parameters:**
- `teamId` (number, required): NBA team ID
- `season` (string, optional): Season

#### get-team-game-log
Get game-by-game results for an NBA team.

**Parameters:**
- `teamId` (number, required): NBA team ID
- `season` (string, optional): Season

### League Tools

#### get-league-leaders
Get league leaders in various statistical categories.

**Parameters:**
- `statCategory` (enum, optional): PTS, REB, AST, STL, BLK, FG_PCT, FT_PCT, FG3_PCT
- `season` (string, optional): Season

#### get-standings
Get NBA conference standings.

**Parameters:**
- `season` (string, optional): Season

### Game Tools

#### get-box-score
Get the box score for an NBA game.

**Parameters:**
- `gameId` (string, required): NBA game ID

#### get-play-by-play
Get play-by-play data for an NBA game.

**Parameters:**
- `gameId` (string, required): NBA game ID

### Live Tools

#### get-live-scoreboard
Get today's live NBA scores.

**Parameters:** None

#### get-live-box-score
Get real-time box score for an in-progress game.

**Parameters:**
- `gameId` (string, required): NBA game ID

## Security Analysis

### Rate Limiting

Moderate limits to respect public API usage:
- **Per-minute**: 30 requests
- **Per-hour**: 500 requests

### Side Effect Handling

```typescript
toolRegistry: [
  // Network operations
  { name: 'get-player-stats', sideEffects: 'network' },
  { name: 'get-live-scoreboard', sideEffects: 'network' },

  // Local operation (searches static player list)
  { name: 'find-player', sideEffects: 'none' },
]
```

## Claude Desktop Integration

```json
{
  "mcpServers": {
    "nba": {
      "command": "node",
      "args": ["dist/index.js"],
      "cwd": "/path/to/cookbook/nba-server"
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
