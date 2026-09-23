/**
 * NBA player stats tools
 */

import { z } from 'zod';
import { NbaAPI } from 'nba-api';

let apiInstance: NbaAPI | null = null;

async function getApi(): Promise<NbaAPI> {
  if (!apiInstance) {
    try {
      apiInstance = new NbaAPI();
      await apiInstance.connect();
    } catch (error) {
      throw new Error(
        'Failed to connect to NBA API. The service may be temporarily unavailable. ' +
        `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
  return apiInstance;
}

export const getPlayerStatsSchema = z.object({
  playerId: z.number().min(1).describe('NBA player ID'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetPlayerStatsArgs = z.infer<typeof getPlayerStatsSchema>;

export async function getPlayerStats(args: GetPlayerStatsArgs) {
  try {
    const api = await getApi();
    const stats = await api.getPlayerCareerStats(args.playerId, {
      perMode: 'PerGame'
    });

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          playerId: args.playerId,
          stats
        }, null, 2)
      }]
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: message.includes('404') || message.includes('not found')
            ? `Player ID ${args.playerId} not found. Use find-player to search by name first.`
            : `Failed to fetch player stats: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getPlayerGameLogSchema = z.object({
  playerId: z.number().min(1).describe('NBA player ID'),
  season: z.string().regex(/^\d{4}-\d{2}$/, 'Season must be in format YYYY-YY (e.g., 2024-25)').optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetPlayerGameLogArgs = z.infer<typeof getPlayerGameLogSchema>;

export async function getPlayerGameLog(args: GetPlayerGameLogArgs) {
  try {
    const api = await getApi();
    const gameLog = await api.getPlayerGameLog(args.playerId, args.season, args.seasonType);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          playerId: args.playerId,
          season: args.season || 'current',
          games: gameLog
        }, null, 2)
      }]
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: message.includes('404') || message.includes('not found')
            ? `Player ID ${args.playerId} not found. Use find-player to search by name first.`
            : `Failed to fetch game log: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getPlayerInfoSchema = z.object({
  playerId: z.number().min(1).describe('NBA player ID')
});

export type GetPlayerInfoArgs = z.infer<typeof getPlayerInfoSchema>;

export async function getPlayerInfo(args: GetPlayerInfoArgs) {
  try {
    const api = await getApi();
    const info = await api.getCommonPlayerInfo(args.playerId);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          playerId: args.playerId,
          info
        }, null, 2)
      }]
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: message.includes('404') || message.includes('not found')
            ? `Player ID ${args.playerId} not found. Use find-player to search by name first.`
            : `Failed to fetch player info: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const findPlayerSchema = z.object({
  name: z.string().max(100).describe('Player name to search for (partial match supported)')
});

export type FindPlayerArgs = z.infer<typeof findPlayerSchema>;

export async function findPlayer(args: FindPlayerArgs) {
  try {
    const api = await getApi();
    const players = api.findPlayersByName(args.name);

    if (players.length === 0) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            searchTerm: args.name,
            count: 0,
            players: [],
            message: `No players found matching "${args.name}". Try a different spelling or partial name.`
          }, null, 2)
        }]
      };
    }

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          searchTerm: args.name,
          count: players.length,
          players: players.slice(0, 20)
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to search for players'
        }, null, 2)
      }],
      isError: true
    };
  }
}
