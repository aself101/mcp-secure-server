# Advanced Configuration

This document covers advanced configuration options for the NBA MCP server.

## NBA Team IDs

| Team | ID |
|------|-----|
| Atlanta Hawks | 1610612737 |
| Boston Celtics | 1610612738 |
| Brooklyn Nets | 1610612751 |
| Charlotte Hornets | 1610612766 |
| Chicago Bulls | 1610612741 |
| Cleveland Cavaliers | 1610612739 |
| Dallas Mavericks | 1610612742 |
| Denver Nuggets | 1610612743 |
| Detroit Pistons | 1610612765 |
| Golden State Warriors | 1610612744 |
| Houston Rockets | 1610612745 |
| Indiana Pacers | 1610612754 |
| LA Clippers | 1610612746 |
| Los Angeles Lakers | 1610612747 |
| Memphis Grizzlies | 1610612763 |
| Miami Heat | 1610612748 |
| Milwaukee Bucks | 1610612749 |
| Minnesota Timberwolves | 1610612750 |
| New Orleans Pelicans | 1610612740 |
| New York Knicks | 1610612752 |
| Oklahoma City Thunder | 1610612760 |
| Orlando Magic | 1610612753 |
| Philadelphia 76ers | 1610612755 |
| Phoenix Suns | 1610612756 |
| Portland Trail Blazers | 1610612757 |
| Sacramento Kings | 1610612758 |
| San Antonio Spurs | 1610612759 |
| Toronto Raptors | 1610612761 |
| Utah Jazz | 1610612762 |
| Washington Wizards | 1610612764 |

## Season Format

Seasons use the format `YYYY-YY`:
- `2024-25` - Current season
- `2023-24` - Last season
- `2022-23` - Two seasons ago

## Stat Categories

### League Leaders Categories

| Category | Description |
|----------|-------------|
| PTS | Points per game |
| REB | Rebounds per game |
| AST | Assists per game |
| STL | Steals per game |
| BLK | Blocks per game |
| FG_PCT | Field goal percentage |
| FG3_PCT | Three-point percentage |
| FT_PCT | Free throw percentage |
| EFF | Efficiency rating |

## Rate Limit Management

```typescript
const server = new SecureMcpServer({
  name: 'nba-server',
  version: '1.0.0',
}, {
  maxRequestsPerMinute: 30,
  maxRequestsPerHour: 500,
  toolRegistry: [
    // Live endpoints may need higher limits
    { name: 'get-live-scoreboard', quotaPerMinute: 10 },
    { name: 'get-live-box-score', quotaPerMinute: 10 },
  ],
});
```

## Caching Considerations

Different data types have different staleness tolerances:

| Data Type | Recommended Cache |
|-----------|-------------------|
| Player info | 24 hours |
| Career stats | 1 hour |
| Season stats | 15 minutes |
| Live scoreboard | No cache |
| Box scores (final) | 24 hours |

## Error Handling

Common error responses:

```json
{
  "error": "Player not found",
  "message": "No player found with ID 999999"
}
```

```json
{
  "error": "Game not found",
  "message": "Game ID 0022400999 does not exist"
}
```

```json
{
  "error": "API unavailable",
  "message": "NBA.com API is temporarily unavailable. Try again later."
}
```

## Game ID Format

NBA game IDs follow the format: `00YYGSNNNN`

- `00` - Game type prefix
- `YY` - Season year (e.g., 24 for 2024-25)
- `G` - Game type (2 = regular season, 4 = playoffs)
- `SNNNN` - Sequential game number

Examples:
- `0022400001` - First regular season game of 2024-25
- `0042400101` - First playoff game of 2024-25

## Finding Game IDs

Use the live scoreboard to find current game IDs:

```text
Tool: get-live-scoreboard
Arguments: {}
```

Or use team game log to find historical game IDs:

```text
Tool: get-team-game-log
Arguments: { "teamId": 1610612747, "season": "2024-25" }
```

## Common Player IDs

| Player | ID |
|--------|-----|
| LeBron James | 2544 |
| Stephen Curry | 201939 |
| Kevin Durant | 201142 |
| Giannis Antetokounmpo | 203507 |
| Nikola Jokic | 203999 |
| Luka Doncic | 1629029 |
| Joel Embiid | 203954 |
| Jayson Tatum | 1628369 |
