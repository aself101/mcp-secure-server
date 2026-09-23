/**
 * NBA team tools
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

export const getTeamRosterSchema = z.object({
  teamId: z.number().min(1).describe('NBA team ID'),
  season: z.string().regex(/^\d{4}-\d{2}$/, 'Season must be in format YYYY-YY (e.g., 2024-25)').optional().describe('Season in YYYY-YY format (e.g., "2024-25")')
});

export type GetTeamRosterArgs = z.infer<typeof getTeamRosterSchema>;

export async function getTeamRoster(args: GetTeamRosterArgs) {
  try {
    const api = await getApi();
    const roster = await api.getCommonTeamRoster(args.teamId, args.season);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          teamId: args.teamId,
          season: args.season || 'current',
          roster
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
            ? `Team ID ${args.teamId} not found. Common team IDs: Lakers=1610612747, Celtics=1610612738, Warriors=1610612744.`
            : `Failed to fetch team roster: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getTeamGameLogSchema = z.object({
  teamId: z.number().min(1).describe('NBA team ID'),
  season: z.string().regex(/^\d{4}-\d{2}$/, 'Season must be in format YYYY-YY (e.g., 2024-25)').optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type filter')
});

export type GetTeamGameLogArgs = z.infer<typeof getTeamGameLogSchema>;

export async function getTeamGameLog(args: GetTeamGameLogArgs) {
  try {
    const api = await getApi();
    const gameLog = await api.getTeamGameLog(args.teamId, args.season, args.seasonType);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          teamId: args.teamId,
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
            ? `Team ID ${args.teamId} not found. Common team IDs: Lakers=1610612747, Celtics=1610612738, Warriors=1610612744.`
            : `Failed to fetch team game log: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}
