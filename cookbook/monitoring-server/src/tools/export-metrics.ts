/**
 * Export Metrics Tool
 *
 * Export metrics in various formats for external consumption.
 * Supports Prometheus exposition format and JSON.
 */

import { z } from 'zod';
import {
  getMetrics,
  getTopBlockedPatterns,
  exportPrometheusMetrics,
  getAuditStats,
  getAlertStats,
} from '../utils/index.js';

export const exportMetricsSchema = z.object({
  format: z
    .enum(['prometheus', 'json', 'summary'])
    .default('prometheus')
    .describe('Export format'),
  includeAuditStats: z
    .boolean()
    .default(true)
    .describe('Include audit log statistics (JSON/summary only)'),
  includeAlertStats: z
    .boolean()
    .default(true)
    .describe('Include alert statistics (JSON/summary only)'),
});

export type ExportMetricsArgs = z.infer<typeof exportMetricsSchema>;

export interface ExportMetricsResult {
  content: Array<{ type: 'text'; text: string }>;
}

export async function exportMetrics(
  args: ExportMetricsArgs
): Promise<ExportMetricsResult> {
  let result: string;

  switch (args.format) {
    case 'prometheus': {
      result = exportPrometheusMetrics();
      break;
    }

    case 'json': {
      const metrics = getMetrics();
      const data: Record<string, unknown> = {
        timestamp: new Date(metrics.timestamp).toISOString(),
        uptime: {
          ms: metrics.uptimeMs,
          formatted: metrics.uptimeFormatted,
        },
        security: {
          totalEvents: metrics.summary.totalEvents,
          totalViolations: metrics.summary.totalViolations,
          violationsByType: metrics.summary.violationsByType,
          violationsBySeverity: metrics.summary.violationsBySeverity,
          topBlockedPatterns: getTopBlockedPatterns(20),
        },
        layers: metrics.layers,
        tools: metrics.tools,
      };

      if (args.includeAuditStats) {
        data.audit = getAuditStats();
      }

      if (args.includeAlertStats) {
        data.alerts = getAlertStats();
      }

      result = JSON.stringify(data, null, 2);
      break;
    }

    case 'summary': {
      const metrics = getMetrics();
      const auditStats = args.includeAuditStats ? getAuditStats() : null;
      const alertStats = args.includeAlertStats ? getAlertStats() : null;

      const lines: string[] = [
        '╔══════════════════════════════════════════════════════════════╗',
        '║              MCP SECURITY MONITORING SUMMARY                 ║',
        '╚══════════════════════════════════════════════════════════════╝',
        '',
        `📊 Server Uptime: ${metrics.uptimeFormatted}`,
        `🕐 Report Time: ${new Date().toISOString()}`,
        '',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        'SECURITY EVENTS',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        '',
        `Total Events: ${metrics.summary.totalEvents}`,
        `Total Violations: ${metrics.summary.totalViolations}`,
        '',
        'Violations by Type:',
      ];

      for (const [type, count] of Object.entries(metrics.summary.violationsByType)) {
        lines.push(`  • ${type}: ${count}`);
      }

      lines.push('', 'Violations by Severity:');
      for (const [severity, count] of Object.entries(metrics.summary.violationsBySeverity)) {
        const icon = severity === 'CRITICAL' ? '🔴' :
                    severity === 'HIGH' ? '🟠' :
                    severity === 'MEDIUM' ? '🟡' : '🟢';
        lines.push(`  ${icon} ${severity}: ${count}`);
      }

      lines.push(
        '',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        'LAYER PERFORMANCE',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        '',
        'Layer  | Requests | Blocked | Block Rate | Avg Latency | P99 Latency',
        '-------|----------|---------|------------|-------------|------------',
      );

      for (const [layer, stats] of Object.entries(metrics.layers)) {
        const blockRate = (stats.blockRate * 100).toFixed(1);
        lines.push(
          `L${layer}     | ${padLeft(stats.totalRequests, 8)} | ${padLeft(stats.blocked, 7)} | ${padLeft(blockRate, 9)}% | ${padLeft(stats.avgLatencyMs.toFixed(1), 8)}ms | ${padLeft(stats.p99LatencyMs, 8)}ms`
        );
      }

      lines.push(
        '',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        'TOOL STATISTICS',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
        '',
        'Tool              | Calls  | Success | Avg Latency | Quota',
        '------------------|--------|---------|-------------|------',
      );

      for (const [tool, stats] of Object.entries(metrics.tools)) {
        const successRate = (stats.successRate * 100).toFixed(1);
        const quotaStr = `${stats.quotaUsed}/${stats.quotaLimit}`;
        lines.push(
          `${padRight(tool, 17)} | ${padLeft(stats.totalCalls, 6)} | ${padLeft(successRate, 6)}% | ${padLeft(stats.avgLatencyMs.toFixed(1), 8)}ms | ${quotaStr}`
        );
      }

      if (auditStats) {
        lines.push(
          '',
          '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
          'AUDIT LOG',
          '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
          '',
          `Total Entries: ${auditStats.totalEntries}`,
          `Last Hour: ${auditStats.lastHourEntries}`,
          `Last 24h: ${auditStats.last24hEntries}`,
        );
      }

      if (alertStats) {
        lines.push(
          '',
          '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
          'ALERTS',
          '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
          '',
          `Active Rules: ${alertStats.enabledRules}/${alertStats.totalRules}`,
          `Total Alerts: ${alertStats.totalAlerts}`,
          `Last Hour: ${alertStats.lastHourAlerts}`,
          `Last 24h: ${alertStats.last24hAlerts}`,
        );
      }

      lines.push(
        '',
        '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━',
      );

      result = lines.join('\n');
      break;
    }

    default:
      result = JSON.stringify({ error: `Unknown format: ${args.format}` });
  }

  return {
    content: [{
      type: 'text',
      text: result,
    }],
  };
}

function padLeft(value: string | number, width: number): string {
  return String(value).padStart(width);
}

function padRight(value: string, width: number): string {
  return value.padEnd(width);
}
