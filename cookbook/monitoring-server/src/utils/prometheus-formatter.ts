/**
 * Prometheus Formatter
 *
 * Formats metrics in Prometheus exposition format.
 * Compatible with Prometheus scraping and Grafana dashboards.
 */

import { getMetrics, getTopBlockedPatterns } from './metrics-collector.js';
import { getAlertStats } from './alert-manager.js';

interface MetricLine {
  name: string;
  type: 'counter' | 'gauge' | 'histogram' | 'summary';
  help: string;
  values: Array<{
    labels?: Record<string, string>;
    value: number;
  }>;
}

/**
 * Format a metric name to be Prometheus-compatible
 */
function formatMetricName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, '_').toLowerCase();
}

/**
 * Format labels for Prometheus
 */
function formatLabels(labels?: Record<string, string>): string {
  if (!labels || Object.keys(labels).length === 0) return '';
  const pairs = Object.entries(labels)
    .map(([k, v]) => `${k}="${v.replace(/"/g, '\\"')}"`)
    .join(',');
  return `{${pairs}}`;
}

/**
 * Generate a single metric block
 */
function formatMetricBlock(metric: MetricLine): string {
  const lines: string[] = [];
  const name = formatMetricName(metric.name);

  lines.push(`# HELP ${name} ${metric.help}`);
  lines.push(`# TYPE ${name} ${metric.type}`);

  for (const { labels, value } of metric.values) {
    lines.push(`${name}${formatLabels(labels)} ${value}`);
  }

  return lines.join('\n');
}

/**
 * Export all metrics in Prometheus format
 */
export function exportPrometheusMetrics(): string {
  const metrics = getMetrics();
  const alertStats = getAlertStats();
  const topPatterns = getTopBlockedPatterns(10);

  const blocks: MetricLine[] = [];

  // Server uptime
  blocks.push({
    name: 'mcp_server_uptime_seconds',
    type: 'gauge',
    help: 'Server uptime in seconds',
    values: [{ value: Math.floor(metrics.uptimeMs / 1000) }],
  });

  // Total events
  blocks.push({
    name: 'mcp_security_events_total',
    type: 'counter',
    help: 'Total number of security events',
    values: [{ value: metrics.summary.totalEvents }],
  });

  // Total violations
  blocks.push({
    name: 'mcp_security_violations_total',
    type: 'counter',
    help: 'Total number of security violations',
    values: [{ value: metrics.summary.totalViolations }],
  });

  // Violations by type
  blocks.push({
    name: 'mcp_security_violations_by_type',
    type: 'counter',
    help: 'Security violations by type',
    values: Object.entries(metrics.summary.violationsByType).map(([type, count]) => ({
      labels: { violation_type: type },
      value: count as number,
    })),
  });

  // Violations by severity
  blocks.push({
    name: 'mcp_security_violations_by_severity',
    type: 'counter',
    help: 'Security violations by severity',
    values: Object.entries(metrics.summary.violationsBySeverity).map(([severity, count]) => ({
      labels: { severity },
      value: count as number,
    })),
  });

  // Layer metrics
  for (const [layer, stats] of Object.entries(metrics.layers)) {
    const layerNum = layer.toString();

    blocks.push({
      name: 'mcp_layer_requests_total',
      type: 'counter',
      help: 'Total requests processed by layer',
      values: [{ labels: { layer: layerNum }, value: stats.totalRequests }],
    });

    blocks.push({
      name: 'mcp_layer_blocked_total',
      type: 'counter',
      help: 'Total requests blocked by layer',
      values: [{ labels: { layer: layerNum }, value: stats.blocked }],
    });

    blocks.push({
      name: 'mcp_layer_block_rate',
      type: 'gauge',
      help: 'Request block rate by layer',
      values: [{ labels: { layer: layerNum }, value: stats.blockRate }],
    });

    blocks.push({
      name: 'mcp_layer_latency_avg_ms',
      type: 'gauge',
      help: 'Average latency by layer in milliseconds',
      values: [{ labels: { layer: layerNum }, value: stats.avgLatencyMs }],
    });

    blocks.push({
      name: 'mcp_layer_latency_p50_ms',
      type: 'gauge',
      help: 'P50 latency by layer in milliseconds',
      values: [{ labels: { layer: layerNum }, value: stats.p50LatencyMs }],
    });

    blocks.push({
      name: 'mcp_layer_latency_p95_ms',
      type: 'gauge',
      help: 'P95 latency by layer in milliseconds',
      values: [{ labels: { layer: layerNum }, value: stats.p95LatencyMs }],
    });

    blocks.push({
      name: 'mcp_layer_latency_p99_ms',
      type: 'gauge',
      help: 'P99 latency by layer in milliseconds',
      values: [{ labels: { layer: layerNum }, value: stats.p99LatencyMs }],
    });
  }

  // Tool metrics
  for (const [tool, stats] of Object.entries(metrics.tools)) {
    blocks.push({
      name: 'mcp_tool_calls_total',
      type: 'counter',
      help: 'Total tool calls',
      values: [{ labels: { tool }, value: stats.totalCalls }],
    });

    blocks.push({
      name: 'mcp_tool_success_rate',
      type: 'gauge',
      help: 'Tool success rate',
      values: [{ labels: { tool }, value: stats.successRate }],
    });

    blocks.push({
      name: 'mcp_tool_latency_avg_ms',
      type: 'gauge',
      help: 'Average tool latency in milliseconds',
      values: [{ labels: { tool }, value: stats.avgLatencyMs }],
    });

    blocks.push({
      name: 'mcp_tool_quota_used',
      type: 'gauge',
      help: 'Tool quota currently used',
      values: [{ labels: { tool }, value: stats.quotaUsed }],
    });

    blocks.push({
      name: 'mcp_tool_quota_limit',
      type: 'gauge',
      help: 'Tool quota limit',
      values: [{ labels: { tool }, value: stats.quotaLimit }],
    });

    blocks.push({
      name: 'mcp_tool_quota_percent',
      type: 'gauge',
      help: 'Tool quota usage percentage',
      values: [{ labels: { tool }, value: stats.quotaPercent }],
    });
  }

  // Top blocked patterns
  blocks.push({
    name: 'mcp_top_blocked_patterns',
    type: 'gauge',
    help: 'Top blocked attack patterns',
    values: topPatterns.map(({ type, count }) => ({
      labels: { pattern: type },
      value: count,
    })),
  });

  // Alert stats
  blocks.push({
    name: 'mcp_alert_rules_total',
    type: 'gauge',
    help: 'Total alert rules configured',
    values: [{ value: alertStats.totalRules }],
  });

  blocks.push({
    name: 'mcp_alert_rules_enabled',
    type: 'gauge',
    help: 'Number of enabled alert rules',
    values: [{ value: alertStats.enabledRules }],
  });

  blocks.push({
    name: 'mcp_alerts_total',
    type: 'counter',
    help: 'Total alerts triggered',
    values: [{ value: alertStats.totalAlerts }],
  });

  blocks.push({
    name: 'mcp_alerts_last_hour',
    type: 'gauge',
    help: 'Alerts triggered in the last hour',
    values: [{ value: alertStats.lastHourAlerts }],
  });

  // Generate output
  const output = blocks
    .filter((b) => b.values.length > 0)
    .map(formatMetricBlock)
    .join('\n\n');

  return output + '\n';
}

/**
 * Get content type for Prometheus response
 */
export function getPrometheusContentType(): string {
  return 'text/plain; version=0.0.4; charset=utf-8';
}
