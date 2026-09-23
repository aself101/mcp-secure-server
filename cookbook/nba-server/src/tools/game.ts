/**
 * NBA game tools - box scores, play-by-play
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

export const getBoxScoreSchema = z.object({
  gameId: z.string().regex(/^\d{10}$/, 'Game ID must be 10 digits (e.g., "0022400350")').describe('NBA game ID (e.g., "0022400123")')
});

export type GetBoxScoreArgs = z.infer<typeof getBoxScoreSchema>;

export async function getBoxScore(args: GetBoxScoreArgs) {
  // Validate game ID format
  if (!/^00\d{8}$/.test(args.gameId)) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: `Invalid game ID format: "${args.gameId}". Expected format: 00YYGSNNN (e.g., "0022400350"). Use get-live-scoreboard to find current game IDs.`
        }, null, 2)
      }],
      isError: true
    };
  }

  try {
    const api = await getApi();
    const boxScore = await api.getBoxScoreTraditional(args.gameId);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          gameId: args.gameId,
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
            ? `Game ID "${args.gameId}" not found. Use get-live-scoreboard to find current game IDs.`
            : `Failed to fetch box score: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getPlayByPlaySchema = z.object({
  gameId: z.string().regex(/^\d{10}$/, 'Game ID must be 10 digits (e.g., "0022400350")').describe('NBA game ID (e.g., "0022400123")')
});

export type GetPlayByPlayArgs = z.infer<typeof getPlayByPlaySchema>;

export async function getPlayByPlay(args: GetPlayByPlayArgs) {
  // Validate game ID format
  if (!/^00\d{8}$/.test(args.gameId)) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: `Invalid game ID format: "${args.gameId}". Expected format: 00YYGSNNN (e.g., "0022400350"). Use get-live-scoreboard to find current game IDs.`
        }, null, 2)
      }],
      isError: true
    };
  }

  try {
    const api = await getApi();
    const playByPlay = await api.getPlayByPlay(args.gameId);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          gameId: args.gameId,
          plays: playByPlay
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
            ? `Game ID "${args.gameId}" not found. Use get-live-scoreboard to find current game IDs.`
            : `Failed to fetch play-by-play: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}
