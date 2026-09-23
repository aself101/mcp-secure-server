/**
 * KenPom player stats tools
 */

import { z } from 'zod';
import { KenpomAPI } from 'kenpom-api';

let apiInstance: KenpomAPI | null = null;

async function getApi(): Promise<KenpomAPI> {
  if (!apiInstance) {
    if (!process.env.KENPOM_EMAIL || !process.env.KENPOM_PASSWORD) {
      throw new Error(
        'KenPom credentials required. Set KENPOM_EMAIL and KENPOM_PASSWORD environment variables. ' +
        'Get your subscription at https://kenpom.com'
      );
    }
    try {
      apiInstance = new KenpomAPI({ logLevel: 'NONE' });
      await apiInstance.login();
    } catch (error) {
      throw new Error(
        'Failed to authenticate with KenPom. Verify your KENPOM_EMAIL and KENPOM_PASSWORD are correct. ' +
        `Error: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
  return apiInstance;
}

export const getPlayerStatsSchema = z.object({
  season: z.number().min(2004).optional().describe('Season year (defaults to current, min 2004)'),
  metric: z.enum(['ORtg', 'Min', 'eFG', 'TS', 'OR', 'DR', 'TO', 'ARate', 'Blk', 'Stl', 'FC40', 'FD40', '2P', '3P', 'FT']).optional()
    .describe('Specific metric to retrieve'),
  conference: z.string().max(50).optional().describe('Filter by conference'),
  conferenceOnly: z.boolean().optional().describe('Only conference games')
});

export type GetPlayerStatsArgs = z.infer<typeof getPlayerStatsSchema>;

export async function getPlayerStats(args: GetPlayerStatsArgs) {
  try {
    const api = await getApi();
    const stats = await api.getPlayerStats(args.season, args.metric, args.conference, args.conferenceOnly);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          season: args.season || 'current',
          metric: args.metric || 'all',
          count: stats.length,
          players: stats.slice(0, 100)
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch player stats'
        }, null, 2)
      }],
      isError: true
    };
  }
}
