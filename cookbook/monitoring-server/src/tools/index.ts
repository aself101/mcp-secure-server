/**
 * Tool exports for monitoring server
 */

export {
  getSecurityMetricsSchema,
  getSecurityMetrics,
  type GetSecurityMetricsArgs,
  type GetSecurityMetricsResult,
} from './get-security-metrics.js';

export {
  getAuditLogSchema,
  getAuditLog,
  type GetAuditLogArgs,
  type GetAuditLogResult,
} from './get-audit-log.js';

export {
  configureAlertsSchema,
  configureAlerts,
  type ConfigureAlertsArgs,
  type ConfigureAlertsResult,
} from './configure-alerts.js';

export {
  exportMetricsSchema,
  exportMetrics,
  type ExportMetricsArgs,
  type ExportMetricsResult,
} from './export-metrics.js';
