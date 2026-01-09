/**
 * Log data formatting utilities for security logger
 * @module log-formatters
 */

import type { SecurityDecision, LoggableMessage, LogContext, LayerStats } from './security-logger-types.js';

/** Request log data structure */
export interface RequestLogData {
  event: string;
  requestId: number;
  method: string | undefined;
  timestamp: string;
  messageSize: number;
  hasParams: boolean;
  paramCount: number;
  context: LogContext;
  messagePreview: string;
}

/** Security decision log data structure */
export interface SecurityDecisionLogData {
  event: string;
  requestId: number;
  timestamp: string;
  layer: string;
  layerNumber: number | undefined;
  decision: 'BLOCK' | 'ALLOW';
  passed: boolean | undefined;
  allowed: boolean | undefined;
  severity: string;
  violationType: string;
  reason: string;
  confidence: number;
  patternName: string | undefined;
  patternCategory: string | undefined;
  method: string | undefined;
  messageSize: number;
  attackAnalysis?: {
    attackType: string | null | undefined;
    patternName: string | undefined;
    patternCategory: string | undefined;
    riskLevel: string | undefined;
    detectionLayer: string;
    layerNumber: number | undefined;
    mitigationAction: string;
  };
  validationTime: number;
  messagePreview: string;
  sessionStats: {
    totalRequests: number;
    totalBlocked: number;
    blockRate: string;
  };
}

/** Performance log data structure */
export interface PerformanceLogData {
  event: string;
  requestId: number;
  method: string | undefined;
  timestamp: string;
  validationDuration: number;
  performanceCategory: 'FAST' | 'ACCEPTABLE' | 'SLOW';
  thresholds: {
    fast: boolean;
    acceptable: boolean;
    slow: boolean;
    critical: boolean;
  };
  messageSize: number;
  memoryUsage: NodeJS.MemoryUsage;
  uptime: number;
}

/**
 * Format request log data
 */
export function formatRequestLogData(
  message: LoggableMessage,
  context: LogContext,
  requestId: number
): RequestLogData {
  return {
    event: 'MCP_REQUEST',
    requestId,
    method: message.method,
    timestamp: new Date().toISOString(),
    messageSize: JSON.stringify(message).length,
    hasParams: !!message.params,
    paramCount: message.params ? Object.keys(message.params).length : 0,
    context,
    messagePreview: (context?.canonical ?? JSON.stringify(message)).substring(0, 300) + '...'
  };
}

/**
 * Format security decision log data
 */
export function formatSecurityDecisionLogData(
  decision: SecurityDecision,
  message: LoggableMessage,
  layer: string,
  requestCount: number,
  blockCount: number
): SecurityDecisionLogData {
  const isBlocked = !decision.passed && !decision.allowed;
  const layerName = decision.layerName || layer;

  const logData: SecurityDecisionLogData = {
    event: 'SECURITY_DECISION',
    requestId: requestCount,
    timestamp: new Date().toISOString(),
    layer: layerName,
    layerNumber: decision.layerNumber,
    decision: isBlocked ? 'BLOCK' : 'ALLOW',
    passed: decision.passed,
    allowed: decision.allowed,
    severity: decision.severity || 'UNKNOWN',
    violationType: decision.violationType || 'NONE',
    reason: decision.reason || 'No reason provided',
    confidence: decision.confidence || 0,
    patternName: decision.patternName,
    patternCategory: decision.patternCategory,
    method: message.method,
    messageSize: JSON.stringify(message).length,
    validationTime: decision.validationTime || 0,
    messagePreview: JSON.stringify(message).substring(0, 200) + '...',
    sessionStats: {
      totalRequests: requestCount,
      totalBlocked: blockCount,
      blockRate: ((blockCount / requestCount) * 100).toFixed(2) + '%'
    }
  };

  if (isBlocked) {
    logData.attackAnalysis = {
      attackType: decision.violationType,
      patternName: decision.patternName,
      patternCategory: decision.patternCategory,
      riskLevel: decision.severity,
      detectionLayer: layerName,
      layerNumber: decision.layerNumber,
      mitigationAction: 'REQUEST_BLOCKED'
    };
  }

  return logData;
}

/**
 * Format performance log data
 */
export function formatPerformanceLogData(
  startTime: number,
  endTime: number,
  message: LoggableMessage,
  requestId: number
): PerformanceLogData {
  const duration = endTime - startTime;

  return {
    event: 'PERFORMANCE_METRIC',
    requestId,
    method: message.method,
    timestamp: new Date().toISOString(),
    validationDuration: duration,
    performanceCategory: duration < 5 ? 'FAST' : duration < 20 ? 'ACCEPTABLE' : 'SLOW',
    thresholds: {
      fast: duration < 5,
      acceptable: duration < 20,
      slow: duration >= 20,
      critical: duration >= 50
    },
    messageSize: JSON.stringify(message).length,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime()
  };
}

/**
 * Check if a security decision is blocked
 */
export function isBlockedDecision(decision: SecurityDecision): boolean {
  return !decision.passed && !decision.allowed;
}

/**
 * Update layer statistics
 */
export function updateLayerStats(
  layerStats: Map<string, LayerStats>,
  layerName: string,
  isBlocked: boolean
): void {
  if (!layerStats.has(layerName)) {
    layerStats.set(layerName, { passed: 0, blocked: 0 });
  }
  const stats = layerStats.get(layerName)!;
  isBlocked ? stats.blocked++ : stats.passed++;
}
