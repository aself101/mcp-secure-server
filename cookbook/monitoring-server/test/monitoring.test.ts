/**
 * Monitoring Server Tests
 *
 * Tests for metrics collection, audit logging, alert management,
 * and export functionality.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  recordEvent,
  recordLayerMetrics,
  recordToolCall,
  getMetrics,
  getTopBlockedPatterns,
  resetMetrics,
} from '../src/utils/metrics-collector.js';
import {
  logRequest,
  logResponse,
  logSecurityEvent,
  logSystem,
  queryAuditLog,
  getAuditStats,
  clearAuditLog,
} from '../src/utils/audit-logger.js';
import {
  addAlertRule,
  updateAlertRule,
  deleteAlertRule,
  getAlertRules,
  getAlertHistory,
  getAlertStats,
  clearAlertRules,
} from '../src/utils/alert-manager.js';
import { exportPrometheusMetrics } from '../src/utils/prometheus-formatter.js';

// ============================================================================
// Metrics Collector Tests
// ============================================================================

describe('Metrics Collector', () => {
  beforeEach(() => {
    resetMetrics();
  });

  describe('Security Event Recording', () => {
    it('records security events with correct violation type', () => {
      recordEvent({ type: 'violation', violationType: 'SQL_INJECTION', severity: 'HIGH' });
      recordEvent({ type: 'violation', violationType: 'PATH_TRAVERSAL', severity: 'MEDIUM' });
      recordEvent({ type: 'violation', violationType: 'SQL_INJECTION', severity: 'HIGH' });

      const metrics = getMetrics();
      expect(metrics.summary.totalViolations).toBe(3);
      expect(metrics.summary.violationsByType['SQL_INJECTION']).toBe(2);
      expect(metrics.summary.violationsByType['PATH_TRAVERSAL']).toBe(1);
    });

    it('tracks violations by severity', () => {
      recordEvent({ type: 'violation', violationType: 'XSS', severity: 'CRITICAL' });
      recordEvent({ type: 'violation', violationType: 'RATE_LIMIT', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'INJECTION', severity: 'MEDIUM' });

      const metrics = getMetrics();
      expect(metrics.summary.violationsBySeverity['CRITICAL']).toBe(1);
      expect(metrics.summary.violationsBySeverity['LOW']).toBe(1);
      expect(metrics.summary.violationsBySeverity['MEDIUM']).toBe(1);
    });

    it('increments total events count', () => {
      const initialMetrics = getMetrics();
      const initialEvents = initialMetrics.summary.totalEvents;

      recordEvent({ type: 'violation', violationType: 'TEST', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'TEST', severity: 'LOW' });

      const metrics = getMetrics();
      expect(metrics.summary.totalEvents).toBe(initialEvents + 2);
    });
  });

  describe('Layer Timing Recording', () => {
    it('records layer timing metrics', () => {
      recordLayerMetrics(1, 5, false);
      recordLayerMetrics(1, 10, false);
      recordLayerMetrics(1, 50, true);

      const metrics = getMetrics();
      expect(metrics.layers['1']).toBeDefined();
      expect(metrics.layers['1'].totalRequests).toBe(3);
      expect(metrics.layers['1'].blocked).toBe(1);
    });

    it('calculates average latency', () => {
      recordLayerMetrics(2, 10, false);
      recordLayerMetrics(2, 20, false);
      recordLayerMetrics(2, 30, false);

      const metrics = getMetrics();
      expect(metrics.layers['2'].avgLatencyMs).toBe(20);
    });

    it('calculates block rate', () => {
      recordLayerMetrics(3, 5, false);
      recordLayerMetrics(3, 5, false);
      recordLayerMetrics(3, 5, false);
      recordLayerMetrics(3, 5, true);

      const metrics = getMetrics();
      expect(metrics.layers['3'].blockRate).toBe(0.25);
    });
  });

  describe('Tool Call Recording', () => {
    it('records tool call metrics', () => {
      recordToolCall('get-metrics', 100, true);
      recordToolCall('get-metrics', 150, true);
      recordToolCall('get-metrics', 200, false);

      const metrics = getMetrics();
      expect(metrics.tools['get-metrics']).toBeDefined();
      expect(metrics.tools['get-metrics'].totalCalls).toBe(3);
      expect(metrics.tools['get-metrics'].successRate).toBeCloseTo(0.666, 2);
    });

    it('tracks quota usage', () => {
      for (let i = 0; i < 5; i++) {
        recordToolCall('export-data', 50, true);
      }

      const metrics = getMetrics();
      expect(metrics.tools['export-data'].quotaUsed).toBe(5);
    });
  });

  describe('Top Blocked Patterns', () => {
    it('returns patterns sorted by count', () => {
      recordEvent({ type: 'violation', violationType: 'A', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'B', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'B', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'C', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'C', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'C', severity: 'LOW' });

      const patterns = getTopBlockedPatterns(3);
      expect(patterns[0].type).toBe('C');
      expect(patterns[0].count).toBe(3);
      expect(patterns[1].type).toBe('B');
      expect(patterns[2].type).toBe('A');
    });

    it('respects limit parameter', () => {
      recordEvent({ type: 'violation', violationType: 'A', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'B', severity: 'LOW' });
      recordEvent({ type: 'violation', violationType: 'C', severity: 'LOW' });

      const patterns = getTopBlockedPatterns(2);
      expect(patterns.length).toBe(2);
    });
  });
});

// ============================================================================
// Audit Logger Tests
// ============================================================================

describe('Audit Logger', () => {
  beforeEach(() => {
    clearAuditLog();
  });

  describe('Request Logging', () => {
    it('logs requests with correlation ID', () => {
      // logRequest(correlationId, tool, args)
      logRequest('corr-123', 'tool-1', { param: 'value' });

      const result = queryAuditLog({ type: 'request' });
      expect(result.entries.length).toBeGreaterThan(0);
      expect(result.entries[0].correlationId).toBe('corr-123');
    });

    it('sanitizes sensitive data', () => {
      logRequest('corr-456', 'tool-1', { password: 'secret123', apiKey: 'key123' });

      const result = queryAuditLog({ correlationId: 'corr-456' });
      expect(result.entries.length).toBeGreaterThan(0);
      expect(result.entries[0].metadata?.args).toBeDefined();
      const args = result.entries[0].metadata?.args as Record<string, unknown>;
      expect(args.password).toBe('[REDACTED]');
      expect(args.apiKey).toBe('[REDACTED]');
    });
  });

  describe('Response Logging', () => {
    it('logs responses with success status', () => {
      // logResponse(correlationId, tool, success, duration, error?)
      logResponse('corr-789', 'tool-1', true, 150);

      const result = queryAuditLog({ correlationId: 'corr-789' });
      const response = result.entries.find(e => e.type === 'response');
      expect(response).toBeDefined();
      expect(response?.success).toBe(true);
      expect(response?.duration).toBe(150);
    });

    it('logs failed responses', () => {
      logResponse('corr-failed', 'tool-1', false, 50, 'Error occurred');

      const result = queryAuditLog({ success: false });
      expect(result.entries.length).toBeGreaterThan(0);
    });
  });

  describe('Security Event Logging', () => {
    it('logs security events with layer', () => {
      // logSecurityEvent(correlationId, layer, blocked, reason?, violationType?)
      logSecurityEvent('corr-sec', 2, true, 'Blocked SQL injection attempt', 'SQL_INJECTION');

      const result = queryAuditLog({ type: 'security_event' });
      expect(result.entries.length).toBeGreaterThan(0);
      expect(result.entries[0].level).toBe('warn');
      expect(result.entries[0].metadata?.violationType).toBe('SQL_INJECTION');
    });
  });

  describe('Query Filtering', () => {
    it('filters by time range', () => {
      const now = Date.now();
      logSystem('info', 'Test message');

      const result = queryAuditLog({
        startTime: now - 1000,
        endTime: now + 1000,
      });
      expect(result.entries.length).toBeGreaterThan(0);
    });

    it('filters by log level', () => {
      logSystem('debug', 'Debug message');
      logSystem('warn', 'Warning message');
      logSystem('error', 'Error message');

      const result = queryAuditLog({ level: 'warn' });
      expect(result.entries.every(e => e.level === 'warn')).toBe(true);
    });

    it('supports pagination', () => {
      for (let i = 0; i < 10; i++) {
        logSystem('info', `Message ${i}`);
      }

      const page1 = queryAuditLog({ limit: 3, offset: 0 });
      const page2 = queryAuditLog({ limit: 3, offset: 3 });

      expect(page1.entries.length).toBe(3);
      expect(page2.entries.length).toBe(3);
      expect(page1.entries[0].id).not.toBe(page2.entries[0].id);
    });
  });

  describe('Audit Statistics', () => {
    it('calculates entry statistics', () => {
      logSystem('info', 'Test');
      logSystem('warn', 'Warning');

      const stats = getAuditStats();
      expect(stats.totalEntries).toBeGreaterThan(0);
      expect(typeof stats.lastHourEntries).toBe('number');
      expect(typeof stats.last24hEntries).toBe('number');
    });
  });
});

// ============================================================================
// Alert Manager Tests
// ============================================================================

describe('Alert Manager', () => {
  beforeEach(() => {
    clearAlertRules();
  });

  describe('Rule Management', () => {
    it('adds alert rules', () => {
      const rule = addAlertRule({
        name: 'Test Rule',
        enabled: true,
        condition: {
          metric: 'violations',
          operator: '>',
          threshold: 10,
          windowMs: 60000,
        },
        severity: 'warning',
        channels: ['console'],
        cooldownMs: 300000,
      });

      expect(rule.id).toBeDefined();
      expect(rule.name).toBe('Test Rule');
      expect(rule.triggerCount).toBe(0);
    });

    it('updates existing rules', () => {
      const rule = addAlertRule({
        name: 'Original Name',
        enabled: true,
        condition: {
          metric: 'violations',
          operator: '>',
          threshold: 5,
          windowMs: 30000,
        },
        severity: 'info',
        channels: ['memory'],
        cooldownMs: 60000,
      });

      const updated = updateAlertRule(rule.id, { name: 'Updated Name', enabled: false });

      expect(updated?.name).toBe('Updated Name');
      expect(updated?.enabled).toBe(false);
    });

    it('deletes rules', () => {
      const rule = addAlertRule({
        name: 'To Delete',
        enabled: true,
        condition: {
          metric: 'error_rate',
          operator: '>',
          threshold: 0.1,
          windowMs: 60000,
        },
        severity: 'critical',
        channels: ['console'],
        cooldownMs: 300000,
      });

      const deleted = deleteAlertRule(rule.id);
      expect(deleted).toBe(true);

      const rules = getAlertRules();
      expect(rules.find(r => r.id === rule.id)).toBeUndefined();
    });

    it('returns false when deleting non-existent rule', () => {
      const deleted = deleteAlertRule('non-existent-id');
      expect(deleted).toBe(false);
    });
  });

  describe('Rule Listing', () => {
    it('lists all rules', () => {
      addAlertRule({
        name: 'Rule 1',
        enabled: true,
        condition: { metric: 'violations', operator: '>', threshold: 5, windowMs: 60000 },
        severity: 'info',
        channels: ['memory'],
        cooldownMs: 60000,
      });
      addAlertRule({
        name: 'Rule 2',
        enabled: false,
        condition: { metric: 'latency_p99', operator: '>', threshold: 100, windowMs: 60000 },
        severity: 'warning',
        channels: ['console'],
        cooldownMs: 120000,
      });

      const rules = getAlertRules();
      expect(rules.length).toBe(2);
    });
  });

  describe('Alert Statistics', () => {
    it('calculates rule statistics', () => {
      addAlertRule({
        name: 'Enabled Rule',
        enabled: true,
        condition: { metric: 'violations', operator: '>', threshold: 5, windowMs: 60000 },
        severity: 'info',
        channels: ['memory'],
        cooldownMs: 60000,
      });
      addAlertRule({
        name: 'Disabled Rule',
        enabled: false,
        condition: { metric: 'violations', operator: '>', threshold: 10, windowMs: 60000 },
        severity: 'warning',
        channels: ['memory'],
        cooldownMs: 60000,
      });

      const stats = getAlertStats();
      expect(stats.totalRules).toBe(2);
      expect(stats.enabledRules).toBe(1);
    });
  });
});

// ============================================================================
// Prometheus Formatter Tests
// ============================================================================

describe('Prometheus Formatter', () => {
  beforeEach(() => {
    resetMetrics();
  });

  it('exports metrics in Prometheus format', () => {
    recordEvent({ type: 'violation', violationType: 'SQL_INJECTION', severity: 'HIGH' });
    recordLayerMetrics(1, 10, false);

    const output = exportPrometheusMetrics();

    expect(output).toContain('# HELP');
    expect(output).toContain('# TYPE');
    expect(output).toContain('mcp_security_');
  });

  it('includes violation counters', () => {
    recordEvent({ type: 'violation', violationType: 'XSS', severity: 'MEDIUM' });

    const output = exportPrometheusMetrics();

    expect(output).toContain('mcp_security_violations_total');
  });

  it('includes layer latency gauges', () => {
    recordLayerMetrics(1, 25, false);
    recordLayerMetrics(2, 50, false);

    const output = exportPrometheusMetrics();

    expect(output).toContain('mcp_layer_latency');
    expect(output).toContain('layer="1"');
    expect(output).toContain('layer="2"');
  });

  it('formats numbers correctly', () => {
    recordEvent({ type: 'violation', violationType: 'TEST', severity: 'LOW' });

    const output = exportPrometheusMetrics();

    // Should not contain NaN or Infinity
    expect(output).not.toContain('NaN');
    expect(output).not.toContain('Infinity');
  });
});

// ============================================================================
// Integration Tests
// ============================================================================

describe('Integration', () => {
  beforeEach(() => {
    resetMetrics();
    clearAuditLog();
    clearAlertRules();
  });

  it('metrics and audit log work together', () => {
    // Simulate a blocked request
    recordEvent({ type: 'violation', violationType: 'PATH_TRAVERSAL', severity: 'HIGH' });
    logSecurityEvent('corr-int-1', 2, true, 'Blocked path traversal', 'PATH_TRAVERSAL');

    const metrics = getMetrics();
    const auditResult = queryAuditLog({ type: 'security_event' });

    expect(metrics.summary.totalViolations).toBeGreaterThan(0);
    expect(auditResult.entries.length).toBeGreaterThan(0);
  });

  it('tool calls are tracked in metrics', () => {
    recordToolCall('get-security-metrics', 50, true);
    logRequest('corr-tool-1', 'get-security-metrics', {});
    logResponse('corr-tool-1', 'get-security-metrics', true, 50);

    const metrics = getMetrics();
    const auditResult = queryAuditLog({ tool: 'get-security-metrics' });

    expect(metrics.tools['get-security-metrics']).toBeDefined();
    expect(auditResult.entries.length).toBe(2); // request + response
  });
});
