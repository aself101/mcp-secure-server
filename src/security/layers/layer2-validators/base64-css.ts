/**
 * Base64 and CSS validation functions for Layer 2
 */

import type { Severity, ViolationType } from '../../../types/index.js';
import type { AttackPattern } from '../layer-utils/content/patterns/index.js';
import { ATTACK_PATTERNS } from '../layer-utils/content/dangerous-patterns.js';
import { containsMaliciousPatterns } from './pattern-detection.js';

/** Validation result */
export interface Base64ValidationResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  confidence?: number;
}

/** Data URI info for logging */
interface DataUriInfo {
  mimeType: string;
  encodingParams: string;
  data: string;
}

/** Debug logger function type */
type DebugLogger = (message: string) => void;

/**
 * Validate base64 content including data URIs
 */
export function validateBase64Content(content: string, logDebug?: DebugLogger): Base64ValidationResult {
  const dataUriPattern = /data:\s*([^;,\s]+)?\s*((?:;[^,\s]*)*)\s*,\s*([A-Za-z0-9+/=\s]+)/gi;
  const foundUris: DataUriInfo[] = [];
  let match: RegExpExecArray | null;

  while ((match = dataUriPattern.exec(content)) !== null) {
    const mimeType = (match[1] || '').toLowerCase().trim();
    const encodingParams = (match[2] || '').toLowerCase();
    const data = (match[3] || '').replace(/\s/g, '');

    foundUris.push({ mimeType, encodingParams, data: data.substring(0, 100) });

    const mimeResult = validateDataUriMimeType(mimeType);
    if (!mimeResult.passed) return mimeResult;

    if (encodingParams.includes('base64') && data.length > 0) {
      const base64Result = validateBase64Data(data);
      if (!base64Result.passed) return base64Result;
    }
  }

  if (foundUris.length > 0 && logDebug) {
    logDebug(`Validated ${foundUris.length} data URIs: ${JSON.stringify(foundUris)}`);
  }

  return { passed: true };
}

/**
 * Validate data URI MIME types
 */
export function validateDataUriMimeType(mimeType: string): Base64ValidationResult {
  const dangerousMimes = ATTACK_PATTERNS.dataValidation.mimeTypes;

  if (dangerousMimes.some(dangerous => mimeType.includes(dangerous))) {
    return {
      passed: false,
      reason: `Dangerous data URI MIME type detected: ${mimeType}`,
      severity: 'CRITICAL',
      violationType: 'DANGEROUS_DATA_URI',
      confidence: 0.95
    };
  }

  return { passed: true };
}

/**
 * Validate base64-encoded data content
 */
export function validateBase64Data(data: string): Base64ValidationResult {
  let decoded: string;
  try {
    const buf = Buffer.from(data, 'base64');
    decoded = buf.toString('utf8');
    if (decoded.includes('\uFFFD')) {
      decoded = buf.toString('latin1');
    }
  } catch (_error) {
    return {
      passed: false,
      reason: 'Base64-encoded malformed content',
      severity: 'CRITICAL',
      violationType: 'BASE64_INJECTION',
      confidence: 0.9
    };
  }

  if (containsMaliciousPatterns(decoded)) {
    return {
      passed: false,
      reason: 'Base64-encoded malicious content detected',
      severity: 'CRITICAL',
      violationType: 'BASE64_INJECTION',
      confidence: 0.9
    };
  }

  if (decoded.toLowerCase().includes('data:')) {
    return {
      passed: false,
      reason: 'Nested data URI detected (data URI inception attack)',
      severity: 'HIGH',
      violationType: 'NESTED_DATA_URI',
      confidence: 0.8
    };
  }

  return { passed: true };
}

/**
 * CSS validation using consolidated patterns
 */
export function validateCSSContent(content: string): Base64ValidationResult {
  const cssCategories: AttackPattern[][] = [
    ATTACK_PATTERNS.css.expressions,
    ATTACK_PATTERNS.css.protocolInjection
  ];

  for (const category of cssCategories) {
    for (const { pattern, name, severity } of category) {
      if (pattern.test(content)) {
        return {
          passed: false,
          reason: `CSS injection detected: ${name}`,
          severity,
          violationType: 'CSS_INJECTION',
          confidence: 0.9
        };
      }
    }
  }

  return { passed: true };
}
