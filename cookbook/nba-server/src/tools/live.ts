/**
 * NBA live data tools - scoreboard, live box scores
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

export const getLiveScoreboardSchema = z.object({});

export async function getLiveScoreboard() {
  try {
    const api = await getApi();
    const scoreboard = await api.getLiveScoreboard();

    if (!scoreboard || (Array.isArray(scoreboard) && scoreboard.length === 0)) {
      return {
        content: [{
          type: 'text' as const,
          text: JSON.stringify({
            success: true,
            date: new Date().toISOString().split('T')[0],
            message: 'No NBA games scheduled today',
            games: []
          }, null, 2)
        }]
      };
    }

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          date: new Date().toISOString().split('T')[0],
          games: scoreboard
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch live scoreboard'
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getLiveBoxScoreSchema = z.object({
  gameId: z.string().regex(/^\d{10}$/, 'Game ID must be 10 digits (e.g., "0022400350")').describe('NBA game ID (e.g., "0022400123")')
});

export type GetLiveBoxScoreArgs = z.infer<typeof getLiveBoxScoreSchema>;

export async function getLiveBoxScore(args: GetLiveBoxScoreArgs) {
  try {
    const api = await getApi();
    const boxScore = await api.getLiveBoxScore(args.gameId);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          gameId: args.gameId,
          live: true,
          boxScore
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
            ? `Game "${args.gameId}" not found or not currently in progress. Use get-live-scoreboard to see active games.`
            : `Failed to fetch live box score: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}
