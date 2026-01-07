/**
 * NBA MCP Server
 * NBA stats, live scores, and player data from public APIs
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import {
  getPlayerStatsSchema, getPlayerStats,
  getPlayerGameLogSchema, getPlayerGameLog,
  getPlayerInfoSchema, getPlayerInfo,
  findPlayerSchema, findPlayer
} from './tools/player.js';
import { getTeamRosterSchema, getTeamRoster, getTeamGameLogSchema, getTeamGameLog } from './tools/team.js';
import { getLeagueLeadersSchema, getLeagueLeaders, getStandingsSchema, getStandings } from './tools/league.js';
import { getBoxScoreSchema, getBoxScore, getPlayByPlaySchema, getPlayByPlay } from './tools/game.js';
import { getLiveScoreboardSchema, getLiveScoreboard, getLiveBoxScoreSchema, getLiveBoxScore } from './tools/live.js';

const server = new SecureMcpServer(
  {
    name: 'nba-server',
    version: '1.0.0'
  },
  {
    // Security preset - standard for external API data fetching
    securityLevel: 'standard',
    enableLogging: true,
    toolRegistry: [
      { name: 'get-player-stats', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-player-game-log', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-player-info', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'find-player', sideEffects: 'none', maxArgsSize: 500 },
      { name: 'get-team-roster', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-team-game-log', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-league-leaders', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-standings', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-box-score', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-play-by-play', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-live-scoreboard', sideEffects: 'network', maxArgsSize: 100 },
      { name: 'get-live-box-score', sideEffects: 'network', maxArgsSize: 500 }
    ],
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false
    },
    maxRequestsPerMinute: 30,
    maxRequestsPerHour: 500
  }
);

// Player tools
server.tool(
  'get-player-stats',
  'Get career statistics for an NBA player',
  getPlayerStatsSchema.shape,
  async (args) => getPlayerStats(args)
);

server.tool(
  'get-player-game-log',
  'Get game-by-game stats for an NBA player',
  getPlayerGameLogSchema.shape,
  async (args) => getPlayerGameLog(args)
);

server.tool(
  'get-player-info',
  'Get biographical info for an NBA player',
  getPlayerInfoSchema.shape,
  async (args) => getPlayerInfo(args)
);

server.tool(
  'find-player',
  'Search for NBA players by name',
  findPlayerSchema.shape,
  async (args) => findPlayer(args)
);

// Team tools
server.tool(
  'get-team-roster',
  'Get the current roster for an NBA team',
  getTeamRosterSchema.shape,
  async (args) => getTeamRoster(args)
);

server.tool(
  'get-team-game-log',
  'Get game-by-game results for an NBA team',
  getTeamGameLogSchema.shape,
  async (args) => getTeamGameLog(args)
);

// League tools
server.tool(
  'get-league-leaders',
  'Get league leaders in various statistical categories',
  getLeagueLeadersSchema.shape,
  async (args) => getLeagueLeaders(args)
);

server.tool(
  'get-standings',
  'Get NBA conference standings',
  getStandingsSchema.shape,
  async (args) => getStandings(args)
);

// Game tools
server.tool(
  'get-box-score',
  'Get the box score for an NBA game',
  getBoxScoreSchema.shape,
  async (args) => getBoxScore(args)
);

server.tool(
  'get-play-by-play',
  'Get play-by-play data for an NBA game',
  getPlayByPlaySchema.shape,
  async (args) => getPlayByPlay(args)
);

// Live tools
server.tool(
  'get-live-scoreboard',
  'Get today\'s live NBA scores',
  getLiveScoreboardSchema.shape,
  async () => getLiveScoreboard()
);

server.tool(
  'get-live-box-score',
  'Get real-time box score for an in-progress game',
  getLiveBoxScoreSchema.shape,
  async (args) => getLiveBoxScore(args)
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('NBA MCP Server running on stdio');
}

main().catch(console.error);
