/**
 * NBA league-wide tools
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

export const getLeagueLeadersSchema = z.object({
  season: z.string().regex(/^\d{4}-\d{2}$/, 'Season must be in format YYYY-YY (e.g., 2024-25)').optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  statCategory: z.enum(['PTS', 'REB', 'AST', 'STL', 'BLK', 'FG_PCT', 'FT_PCT', 'FG3_PCT']).optional()
    .describe('Stat category to rank by')
});

export type GetLeagueLeadersArgs = z.infer<typeof getLeagueLeadersSchema>;

export async function getLeagueLeaders(args: GetLeagueLeadersArgs) {
  try {
    const api = await getApi();
    const leaders = await api.getLeagueLeaders(args.season, args.statCategory);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          season: args.season || 'current',
          category: args.statCategory || 'PTS',
          leaders
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch league leaders'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getStandingsSchema = z.object({
  season: z.string().regex(/^\d{4}-\d{2}$/, 'Season must be in format YYYY-YY (e.g., 2024-25)').optional().describe('Season in YYYY-YY format (e.g., "2024-25")'),
  seasonType: z.enum(['Regular Season', 'Playoffs']).optional().describe('Season type')
});

export type GetStandingsArgs = z.infer<typeof getStandingsSchema>;

export async function getStandings(args: GetStandingsArgs) {
  try {
    const api = await getApi();
    const standings = await api.getLeagueStandings(args.season, args.seasonType);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          season: args.season || 'current',
          standings
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch standings'
        }, null, 2)
      }],
      isError: true
    };
  }
}
