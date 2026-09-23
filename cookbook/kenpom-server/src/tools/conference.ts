/**
 * KenPom conference tools
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

export const getConferenceStandingsSchema = z.object({
  conference: z.string().max(50).describe('Conference name (e.g., "ACC", "Big Ten", "SEC")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetConferenceStandingsArgs = z.infer<typeof getConferenceStandingsSchema>;

export async function getConferenceStandings(args: GetConferenceStandingsArgs) {
  try {
    const api = await getApi();
    const standings = await api.getConferenceStandings(args.conference, args.season);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          conference: args.conference,
          season: args.season || 'current',
          standings
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
          error: message.includes('not found')
            ? `Conference "${args.conference}" not found. Try: ACC, Big Ten, SEC, Big 12, Pac-12, Big East.`
            : `Failed to fetch conference standings: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getFanMatchSchema = z.object({
  date: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, 'Must be YYYY-MM-DD format')
    .optional()
    .describe('Date in YYYY-MM-DD format (defaults to today)')
});

export type GetFanMatchArgs = z.infer<typeof getFanMatchSchema>;

export async function getFanMatch(args: GetFanMatchArgs) {
  try {
    const api = await getApi();
    const fanMatch = await api.getFanMatch(args.date);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          date: args.date || 'today',
          games: fanMatch
        }, null, 2)
      }]
    };
  } catch (error) {
    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to fetch fan match data'
        }, null, 2)
      }],
      isError: true
    };
  }
}
