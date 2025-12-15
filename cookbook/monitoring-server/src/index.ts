/**
 * Monitoring MCP Server
 *
 * Demonstrates observability and monitoring patterns with:
 * - Real-time security metrics collection
 * - Structured audit logging with correlation IDs
 * - Alert rule management and notification
 * - Prometheus-compatible metrics export
 *
 * Tools:
 * - get-security-metrics: Real-time security metrics and statistics
 * - get-audit-log: Query and filter audit log entries
 * - configure-alerts: Manage alert rules and view history
 * - export-metrics: Export metrics in Prometheus or JSON format
 */

import 'dotenv/config';
import { SecureMcpServer } from 'mcp-security';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import {
  getSecurityMetricsSchema,
  getSecurityMetrics,
  type GetSecurityMetricsArgs,
  getAuditLogSchema,
  getAuditLog,
  type GetAuditLogArgs,
  configureAlertsSchema,
  configureAlerts,
  type ConfigureAlertsArgs,
  exportMetricsSchema,
  exportMetrics,
  type ExportMetricsArgs,
} from './tools/index.js';

import {
  seedDemoData,
  seedDemoAuditData,
  seedDemoAlertRules,
  logSystem,
  getMetrics,
  getAuditStats,
  getAlertStats,
} from './utils/index.js';

// ============================================================================
// Security Configuration
// ============================================================================

const server = new SecureMcpServer(
  {
    name: 'monitoring-server',
    version: '1.0.0',
  },
  {
    // Logging configuration
    enableLogging: process.env.VERBOSE_LOGGING === 'true',
    verboseLogging: process.env.VERBOSE_LOGGING === 'true',

    // Tool registry with per-tool security policies
    toolRegistry: [
      {
        name: 'get-security-metrics',
        sideEffects: 'read',
        maxArgsSize: 256,
        maxEgressBytes: 100 * 1024, // 100KB for metrics
        quotaPerMinute: 60,
        quotaPerHour: 1000,
      },
      {
        name: 'get-audit-log',
        sideEffects: 'read',
        maxArgsSize: 512,
        maxEgressBytes: 500 * 1024, // 500KB for audit logs
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
      {
        name: 'configure-alerts',
        sideEffects: 'write',
        maxArgsSize: 2 * 1024, // 2KB for rule config
        maxEgressBytes: 50 * 1024, // 50KB for response
        quotaPerMinute: 20,
        quotaPerHour: 200,
      },
      {
        name: 'export-metrics',
        sideEffects: 'read',
        maxArgsSize: 128,
        maxEgressBytes: 200 * 1024, // 200KB for Prometheus format
        quotaPerMinute: 30,
        quotaPerHour: 500,
      },
    ],

    // Default policy
    defaultPolicy: {
      allowNetwork: false,
      allowWrites: false,
    },

    // Global rate limits
    maxRequestsPerMinute: 120,
    maxRequestsPerHour: 2000,
  }
);

// ============================================================================
// Tool Definitions
// ============================================================================

/**
 * Tool 1: get-security-metrics
 * Real-time security metrics and statistics
 * - Violation counts by type and severity
 * - Per-layer performance (latency, block rates)
 * - Per-tool statistics (calls, success rate, quota)
 * - Recent security events
 */
server.tool(
  'get-security-metrics',
  'Get real-time security metrics including violations, layer performance, and tool statistics.',
  getSecurityMetricsSchema.shape,
  async (args: GetSecurityMetricsArgs) => getSecurityMetrics(args)
);

/**
 * Tool 2: get-audit-log
 * Query and filter audit log entries
 * - Filter by time range, type, level, tool
 * - Pagination support
 * - Correlation ID tracking
 * - Compliance-ready format
 */
server.tool(
  'get-audit-log',
  'Query audit log entries with filtering by time, type, level, tool, and more.',
  getAuditLogSchema.shape,
  async (args: GetAuditLogArgs) => getAuditLog(args)
);

/**
 * Tool 3: configure-alerts
 * Manage alert rules and view history
 * - Add/update/delete alert rules
 * - Configure thresholds and conditions
 * - View alert history
 * - Severity-based routing
 */
server.tool(
  'configure-alerts',
  'Manage alert rules: list, add, update, delete rules, or view alert history.',
  configureAlertsSchema.shape,
  async (args: ConfigureAlertsArgs) => configureAlerts(args)
);

/**
 * Tool 4: export-metrics
 * Export metrics in various formats
 * - Prometheus exposition format for scraping
 * - JSON for custom integrations
 * - Human-readable summary
 */
server.tool(
  'export-metrics',
  'Export metrics in Prometheus, JSON, or human-readable summary format.',
  exportMetricsSchema.shape,
  async (args: ExportMetricsArgs) => exportMetrics(args)
);

// ============================================================================
// Resource Definitions
// ============================================================================

/**
 * Resource 1: metrics-config
 * Exposes monitoring configuration
 */
server.resource(
  'metrics-config',
  'monitoring://config',
  {
    description: 'Monitoring server configuration and capabilities',
    mimeType: 'application/json',
  },
  async () => {
    return {
      contents: [{
        uri: 'monitoring://config',
        mimeType: 'application/json',
        text: JSON.stringify({
          server: 'monitoring-server',
          version: '1.0.0',
          capabilities: {
            metrics: ['security_events', 'layer_performance', 'tool_statistics'],
            audit: ['request_logging', 'response_logging', 'security_events', 'correlation_tracking'],
            alerts: ['rule_management', 'severity_routing', 'webhook_integration'],
            export: ['prometheus', 'json', 'summary'],
          },
          retentionMs: parseInt(process.env.METRICS_RETENTION_MS || '3600000', 10),
          maxAuditEntries: parseInt(process.env.MAX_AUDIT_ENTRIES || '10000', 10),
        }, null, 2),
      }],
    };
  }
);

/**
 * Resource 2: health
 * Quick health check endpoint
 */
server.resource(
  'health',
  'monitoring://health',
  {
    description: 'Health check status',
    mimeType: 'application/json',
  },
  async () => {
    const metrics = getMetrics();
    const auditStats = getAuditStats();
    const alertStats = getAlertStats();

    return {
      contents: [{
        uri: 'monitoring://health',
        mimeType: 'application/json',
        text: JSON.stringify({
          status: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: metrics.uptimeFormatted,
          metrics: {
            totalEvents: metrics.summary.totalEvents,
            totalViolations: metrics.summary.totalViolations,
          },
          audit: {
            totalEntries: auditStats.totalEntries,
            lastHourEntries: auditStats.lastHourEntries,
          },
          alerts: {
            enabledRules: alertStats.enabledRules,
            lastHourAlerts: alertStats.lastHourAlerts,
          },
        }, null, 2),
      }],
    };
  }
);

// ============================================================================
// Prompt Definitions
// ============================================================================

/**
 * Prompt 1: security-overview
 * Get a quick security overview
 */
server.prompt(
  'security-overview',
  'Get a quick overview of current security status',
  async () => {
    return {
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `To get a security overview, use these tools:

1. **Quick Metrics Summary**
   Use export-metrics with format "summary" for a human-readable dashboard.

2. **Detailed Metrics**
   Use get-security-metrics with includeLayerStats and includeToolStats.

3. **Recent Security Events**
   Use get-security-metrics with includeEvents: true.

4. **Audit Trail**
   Use get-audit-log with type: "security_event" to see security-related entries.

5. **Alert Status**
   Use configure-alerts with action: "stats" to see alert statistics.

What would you like to check?`,
        },
      }],
    };
  }
);

/**
 * Prompt 2: setup-monitoring
 * Guide for setting up monitoring
 */
server.prompt(
  'setup-monitoring',
  'Guide for setting up alerts and monitoring',
  async () => {
    return {
      messages: [{
        role: 'user',
        content: {
          type: 'text',
          text: `# Setting Up Monitoring

## 1. Configure Alert Rules

Use configure-alerts to set up alerting:

\`\`\`json
{
  "action": "add",
  "rule": {
    "name": "High Violation Rate",
    "enabled": true,
    "condition": {
      "metric": "violations",
      "operator": ">",
      "threshold": 10,
      "windowMs": 60000
    },
    "severity": "warning",
    "channels": ["console", "memory"],
    "cooldownMs": 300000
  }
}
\`\`\`

## 2. Set Up Prometheus Scraping

Export metrics in Prometheus format:

\`\`\`json
{
  "format": "prometheus"
}
\`\`\`

Then configure Prometheus to scrape the /metrics endpoint.

## 3. Review Audit Logs

Query security events from the audit log:

\`\`\`json
{
  "type": "security_event",
  "level": "warn",
  "limit": 50
}
\`\`\`

Would you like help with any of these steps?`,
        },
      }],
    };
  }
);

// ============================================================================
// Server Startup
// ============================================================================

async function main() {
  console.error('Monitoring MCP Server starting...');

  // Seed demo data for demonstration
  console.error('Seeding demo data...');
  seedDemoData();
  seedDemoAuditData();
  seedDemoAlertRules();

  // Log startup
  logSystem('info', 'Monitoring server started', {
    version: '1.0.0',
    features: ['metrics', 'audit', 'alerts', 'prometheus'],
  });

  console.error('Features enabled:');
  console.error('  - Real-time security metrics collection');
  console.error('  - Structured audit logging with correlation IDs');
  console.error('  - Alert rule management and notification');
  console.error('  - Prometheus-compatible metrics export');

  const transport = new StdioServerTransport();
  await server.connect(transport as Parameters<typeof server.connect>[0]);

  console.error('Monitoring MCP Server running on stdio');
  console.error('Tools available: get-security-metrics, get-audit-log, configure-alerts, export-metrics');
  console.error('Resources available: metrics-config, health');
  console.error('Prompts available: security-overview, setup-monitoring');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});
