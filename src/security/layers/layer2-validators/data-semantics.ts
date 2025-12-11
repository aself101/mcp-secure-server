/**
 * Data consistency and semantic validation functions for Layer 2
 */

import type { Severity, ViolationType } from '../../../types/index.js';
import type { AttackPattern } from '../layer-utils/content/patterns/index.js';
import { ATTACK_PATTERNS } from '../layer-utils/content/dangerous-patterns.js';
import { calculateNestingLevel, countParameters } from '../layer-utils/content/helper-utils.js';
import { containsMaliciousPatterns } from './pattern-detection.js';

/** Validation result */
export interface DataValidationResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  confidence?: number;
}

/** Message with params */
export interface MessageWithParams {
  params?: unknown;
  [key: string]: unknown;
}

/** Request history entry */
interface RequestHistoryEntry {
  timestamp: number;
}

/** Context with request history */
export interface ValidationContext {
  requestHistory?: RequestHistoryEntry[];
  [key: string]: unknown;
}

/**
 * Data format validation
 */
export function validateDataFormats(strings: string[]): DataValidationResult {
  const dataCategories: AttackPattern[][] = [
    ATTACK_PATTERNS.dataValidation.testCredentials,
    ATTACK_PATTERNS.dataValidation.sensitiveData
  ];

  for (const str of strings) {
    for (const category of dataCategories) {
      for (const { pattern, name, severity } of category) {
        if (pattern.test(str)) {
          return {
            passed: false,
            reason: `Suspicious data pattern detected: ${name}`,
            severity,
            violationType: 'SUSPICIOUS_TEST_DATA',
            confidence: 0.6
          };
        }
      }
    }

    if (str.length > 100 && /^[A-Za-z0-9+/]{50,}={0,2}$/.test(str)) {
      try {
        const decoded = atob(str);
        if (containsMaliciousPatterns(decoded)) {
          return {
            passed: false,
            reason: 'Large base64 data contains malicious patterns',
            severity: 'HIGH',
            violationType: 'SUSPICIOUS_ENCODING',
            confidence: 0.8
          };
        }
      } catch (_e) {
        return {
          passed: false,
          reason: 'Large suspicious base64-like string detected',
          severity: 'LOW',
          violationType: 'SUSPICIOUS_ENCODING',
          confidence: 0.5
        };
      }
    }
  }

  return { passed: true };
}

/**
 * Encoding consistency validation
 */
export function validateEncodingConsistency(content: string): DataValidationResult {
  const encodingCount = {
    html: (content.match(/&[#\w]+;/g) || []).length,
    url: (content.match(/%[0-9A-F]{2}/gi) || []).length,
    unicode: (content.match(/\\u[0-9A-F]{4}/gi) || []).length,
    hex: (content.match(/\\x[0-9A-F]{2}/gi) || []).length
  };

  const activeEncodings = Object.values(encodingCount).filter(count => count > 0).length;
  const totalEncodings = Object.values(encodingCount).reduce((sum, count) => sum + count, 0);

  if (activeEncodings >= 3 && totalEncodings > 10) {
    return {
      passed: false,
      reason: `Suspicious mixed encoding schemes detected: ${JSON.stringify(encodingCount)}`,
      severity: 'MEDIUM',
      violationType: 'ENCODING_EVASION',
      confidence: 0.7
    };
  }

  return { passed: true };
}

/**
 * Parameter validation
 */
export function validateParameters(message: unknown): DataValidationResult {
  if (message === null || message === undefined || typeof message !== 'object') {
    return {
      passed: false,
      reason: 'Invalid message for parameter validation',
      severity: 'CRITICAL',
      violationType: 'VALIDATION_ERROR'
    };
  }

  const msg = message as MessageWithParams;
  if (!msg.params) {
    return { passed: true };
  }

  const nestingLevel = calculateNestingLevel(msg.params);
  if (nestingLevel > 15) {
    return {
      passed: false,
      reason: `Parameter nesting too deep: ${nestingLevel} levels`,
      severity: 'MEDIUM',
      violationType: 'EXCESSIVE_NESTING'
    };
  }

  let paramString: string;
  try {
    paramString = JSON.stringify(msg.params);
  } catch (error) {
    return {
      passed: false,
      reason: `Parameter serialization error: ${(error as Error).message}`,
      severity: 'MEDIUM',
      violationType: 'PARAM_SERIALIZATION_ERROR'
    };
  }

  if (paramString.length > 50000) {
    return {
      passed: false,
      reason: `Parameter payload too large: ${paramString.length} bytes`,
      severity: 'MEDIUM',
      violationType: 'OVERSIZED_PARAMS'
    };
  }

  const paramCount = countParameters(msg.params);
  if (paramCount > 100) {
    return {
      passed: false,
      reason: `Too many parameters: ${paramCount}`,
      severity: 'MEDIUM',
      violationType: 'EXCESSIVE_PARAM_COUNT'
    };
  }

  return { passed: true };
}

/**
 * Context validation
 */
export function validateContext(_message: unknown, context: ValidationContext | null | undefined): DataValidationResult {
  if (context && context.requestHistory) {
    const recentRequests = context.requestHistory.filter(
      req => Date.now() - req.timestamp < 60000
    );

    if (recentRequests.length > 100) {
      return {
        passed: false,
        reason: `Excessive request frequency: ${recentRequests.length} requests/minute`,
        severity: 'HIGH',
        violationType: 'REQUEST_FLOODING'
      };
    }
  }

  return { passed: true };
}
