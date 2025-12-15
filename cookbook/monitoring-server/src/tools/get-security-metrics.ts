/**
 * Get Security Metrics Tool
 *
 * Returns real-time security metrics including:
 * - Violation counts by type and severity
 * - Per-layer statistics (requests, blocks, latency)
 * - Per-tool statistics (calls, success rate, quota usage)
 * - Recent security events
 */

import { z } from 'zod';
import { getMetrics, getTopBlockedPatterns } from '../utils/index.js';

export const getSecurityMetricsSchema = z.object({
  includeEvents: z
    .boolean()
    .default(false)
    .describe('Include recent security events in response'),
  includeLayerStats: z
    .boolean()
    .default(true)
    .describe('Include per-layer statistics'),
  includeToolStats: z
    .boolean()
    .default(true)
    .describe('Include per-tool statistics'),
  topPatternsLimit: z
    .number()
    .int()
    .min(1)
    .max(50)
    .default(10)
    .describe('Number of top blocked patterns to return'),
});

export type GetSecurityMetricsArgs = z.infer<typeof getSecurityMetricsSchema>;

export interface GetSecurityMetricsResult {
  content: Array<{ type: 'text'; text: string }>;
}

export async function getSecurityMetrics(
  args: GetSecurityMetricsArgs
): Promise<GetSecurityMetricsResult> {
  const metrics = getMetrics();
  const topPatterns = getTopBlockedPatterns(args.topPatternsLimit);

  const result: Record<string, unknown> = {
    timestamp: new Date(metrics.timestamp).toISOString(),
    uptime: metrics.uptimeFormatted,
    summary: {
      totalEvents: metrics.summary.totalEvents,
      totalViolations: metrics.summary.totalViolations,
      violationsByType: metrics.summary.violationsByType,
      violationsBySeverity: metrics.summary.violationsBySeverity,
    },
    topBlockedPatterns: topPatterns,
  };

  if (args.includeLayerStats) {
    result.layers = metrics.layers;
  }

  if (args.includeToolStats) {
    result.tools = metrics.tools;
  }

  if (args.includeEvents) {
    result.recentEvents = metrics.recentEvents.slice(0, 50);
  }

  return {
    content: [{
      type: 'text',
      text: JSON.stringify(result, null, 2),
    }],
  };
}
