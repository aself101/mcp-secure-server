/**
 * KenPom MCP Server
 * College basketball analytics and efficiency ratings
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-secure-server';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { getRatingsSchema, getRatings, getProgramRatingsSchema, getProgramRatings } from './tools/ratings.js';
import { getEfficiencySchema, getEfficiency, getFourFactorsSchema, getFourFactors, getTeamStatsSchema, getTeamStats } from './tools/efficiency.js';
import { getScheduleSchema, getSchedule, getScoutingReportSchema, getScoutingReport } from './tools/team.js';
import { getPlayerStatsSchema, getPlayerStats } from './tools/player.js';
import { getConferenceStandingsSchema, getConferenceStandings, getFanMatchSchema, getFanMatch } from './tools/conference.js';

const server = new SecureMcpServer(
  {
    name: 'kenpom-server',
    version: '1.0.0'
  },
  {
    // Security preset - standard for external API data fetching
    securityLevel: 'standard',
    enableLogging: true,
    toolRegistry: [
      { name: 'get-ratings', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-program-ratings', sideEffects: 'network', maxArgsSize: 100 },
      { name: 'get-efficiency', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-four-factors', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-team-stats', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-schedule', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-scouting-report', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-player-stats', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-conference-standings', sideEffects: 'network', maxArgsSize: 500 },
      { name: 'get-fan-match', sideEffects: 'network', maxArgsSize: 500 }
    ],
    defaultPolicy: {
      allowNetwork: true,
      allowWrites: false
    },
    maxRequestsPerMinute: 20,
    maxRequestsPerHour: 200
  }
);

// Ratings
server.tool(
  'get-ratings',
  'Get KenPom team efficiency ratings for a season',
  getRatingsSchema.shape,
  async (args) => getRatings(args)
);

server.tool(
  'get-program-ratings',
  'Get all-time KenPom program rankings',
  getProgramRatingsSchema.shape,
  async () => getProgramRatings()
);

// Efficiency
server.tool(
  'get-efficiency',
  'Get offensive and defensive efficiency stats',
  getEfficiencySchema.shape,
  async (args) => getEfficiency(args)
);

server.tool(
  'get-four-factors',
  'Get four factors stats (shooting, turnovers, rebounding, free throws)',
  getFourFactorsSchema.shape,
  async (args) => getFourFactors(args)
);

server.tool(
  'get-team-stats',
  'Get 20+ team statistics for a season',
  getTeamStatsSchema.shape,
  async (args) => getTeamStats(args)
);

// Team
server.tool(
  'get-schedule',
  'Get a team\'s game-by-game schedule and results',
  getScheduleSchema.shape,
  async (args) => getSchedule(args)
);

server.tool(
  'get-scouting-report',
  'Get detailed scouting report with 70+ stats for a team',
  getScoutingReportSchema.shape,
  async (args) => getScoutingReport(args)
);

// Player
server.tool(
  'get-player-stats',
  'Get individual player statistics and metrics',
  getPlayerStatsSchema.shape,
  async (args) => getPlayerStats(args)
);

// Conference
server.tool(
  'get-conference-standings',
  'Get conference standings for a specific conference',
  getConferenceStandingsSchema.shape,
  async (args) => getConferenceStandings(args)
);

server.tool(
  'get-fan-match',
  'Get daily game predictions and fan match data',
  getFanMatchSchema.shape,
  async (args) => getFanMatch(args)
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('KenPom MCP Server running on stdio');
}

main().catch(console.error);
