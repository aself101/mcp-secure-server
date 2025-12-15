/**
 * Utility exports for monitoring server
 */

export {
  recordEvent,
  recordLayerMetrics,
  recordToolCall,
  updateToolQuota,
  getMetrics,
  getTopBlockedPatterns,
  resetMetrics,
  seedDemoData,
  type SecurityEvent,
} from './metrics-collector.js';

export {
  logAudit,
  logRequest,
  logResponse,
  logSecurityEvent,
  logSystem,
  queryAuditLog,
  getAuditStats,
  exportAuditLog,
  clearAuditLog,
  generateCorrelationId,
  seedDemoAuditData,
  type AuditEntry,
  type AuditQuery,
} from './audit-logger.js';

export {
  addAlertRule,
  updateAlertRule,
  deleteAlertRule,
  getAlertRules,
  getAlertRule,
  addAlertChannel,
  getAlertChannels,
  triggerAlert,
  evaluateRules,
  getAlertHistory,
  clearAlertHistory,
  clearAlertRules,
  getAlertStats,
  seedDemoAlertRules,
  type AlertRule,
  type AlertChannel,
  type AlertEvent,
} from './alert-manager.js';

export {
  exportPrometheusMetrics,
  getPrometheusContentType,
} from './prometheus-formatter.js';
