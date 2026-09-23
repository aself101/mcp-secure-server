# Basic Usage Examples

This document shows common usage patterns for the NBA MCP server.

## Finding Players

### Search for a player by name

```text
Tool: find-player
Arguments: { "name": "LeBron" }
```

Response:
```json
{
  "success": true,
  "results": [
    { "id": 2544, "name": "LeBron James", "team": "Los Angeles Lakers" }
  ]
}
```

### Partial name search

```text
Tool: find-player
Arguments: { "name": "Curry" }
```

Response returns all players matching "Curry".

## Player Statistics

### Get career stats

```text
Tool: get-player-stats
Arguments: { "playerId": 2544 }
```

Response:
```json
{
  "success": true,
  "player": "LeBron James",
  "careerStats": {
    "games": 1492,
    "ppg": 27.1,
    "rpg": 7.5,
    "apg": 7.4
  }
}
```

### Get season stats

```text
Tool: get-player-stats
Arguments: { "playerId": 2544, "season": "2024-25" }
```

### Get game log

```text
Tool: get-player-game-log
Arguments: { "playerId": 201566, "season": "2024-25" }
```

Response:
```json
{
  "success": true,
  "player": "Russell Westbrook",
  "games": [
    { "date": "2024-12-10", "opponent": "GSW", "pts": 22, "reb": 8, "ast": 12 }
  ]
}
```

## Team Information

### Get team roster

```text
Tool: get-team-roster
Arguments: { "teamId": 1610612747 }
```

Response:
```json
{
  "success": true,
  "team": "Los Angeles Lakers",
  "roster": [
    { "name": "LeBron James", "number": 23, "position": "F" },
    { "name": "Anthony Davis", "number": 3, "position": "F-C" }
  ]
}
```

### Get team game log

```text
Tool: get-team-game-log
Arguments: { "teamId": 1610612744 }
```

## League Data

### Get league leaders

```text
Tool: get-league-leaders
Arguments: { "statCategory": "PTS" }
```

Response:
```json
{
  "success": true,
  "category": "Points",
  "leaders": [
    { "rank": 1, "player": "Luka Doncic", "value": 33.2 },
    { "rank": 2, "player": "Giannis Antetokounmpo", "value": 31.8 }
  ]
}
```

### Get standings

```text
Tool: get-standings
Arguments: {}
```

Response includes both Eastern and Western conference standings.

## Live Scores

### Today's scoreboard

```text
Tool: get-live-scoreboard
Arguments: {}
```

Response:
```json
{
  "success": true,
  "date": "2024-12-14",
  "games": [
    {
      "gameId": "0022400350",
      "status": "In Progress",
      "home": { "team": "Lakers", "score": 85 },
      "away": { "team": "Celtics", "score": 82 },
      "period": 3,
      "clock": "5:23"
    }
  ]
}
```

### Live box score

```text
Tool: get-live-box-score
Arguments: { "gameId": "0022400350" }
```

## Game Data

### Get box score

```text
Tool: get-box-score
Arguments: { "gameId": "0022400350" }
```

Response includes full player stats for both teams.

### Get play-by-play

```text
Tool: get-play-by-play
Arguments: { "gameId": "0022400350" }
```

Response:
```json
{
  "success": true,
  "plays": [
    { "period": 1, "clock": "11:45", "description": "LeBron James 3PT Jump Shot" }
  ]
}
```

## Workflow Example: Research a Player

1. Find the player:
```text
Tool: find-player
Arguments: { "name": "Durant" }
```

2. Get their info:
```text
Tool: get-player-info
Arguments: { "playerId": 201142 }
```

3. Get career stats:
```text
Tool: get-player-stats
Arguments: { "playerId": 201142 }
```

4. Get recent games:
```text
Tool: get-player-game-log
Arguments: { "playerId": 201142, "season": "2024-25" }
```
