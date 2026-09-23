/**
 * KenPom team tools - schedule, scouting report
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

export const getScheduleSchema = z.object({
  team: z.string().max(100).describe('Team name (e.g., "Duke", "Kansas")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)')
});

export type GetScheduleArgs = z.infer<typeof getScheduleSchema>;

export async function getSchedule(args: GetScheduleArgs) {
  try {
    const api = await getApi();
    const schedule = await api.getSchedule(args.team, args.season);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          team: args.team,
          season: args.season || 'current',
          games: schedule
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
            ? `Team "${args.team}" not found. Check spelling or try the full team name.`
            : `Failed to fetch schedule: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}

export const getScoutingReportSchema = z.object({
  team: z.string().max(100).describe('Team name (e.g., "Duke", "Kansas")'),
  season: z.number().min(1999).optional().describe('Season year (defaults to current)'),
  conferenceOnly: z.boolean().optional().describe('Only show conference games')
});

export type GetScoutingReportArgs = z.infer<typeof getScoutingReportSchema>;

export async function getScoutingReport(args: GetScoutingReportArgs) {
  try {
    const api = await getApi();
    const report = await api.getScoutingReport(args.team, args.season, args.conferenceOnly);

    return {
      content: [{
        type: 'text' as const,
        text: JSON.stringify({
          success: true,
          team: args.team,
          season: args.season || 'current',
          conferenceOnly: args.conferenceOnly || false,
          report
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
            ? `Team "${args.team}" not found. Check spelling or try the full team name.`
            : `Failed to fetch scouting report: ${message}`
        }, null, 2)
      }],
      isError: true
    };
  }
}
