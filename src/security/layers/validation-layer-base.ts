/**
 * Base class for validation layers
 * Defines the contract and shared functionality for all validation layers
 */

import type { Severity, ViolationType, ValidationResult as ValidationResultType } from '../../types/index.js';
import { ErrorSanitizer } from '../utils/error-sanitizer.js';

/** Options for validation layers */
export interface ValidationLayerOptions {
  enabled?: boolean;
  [key: string]: unknown;
}

/** Constructor parameters for ValidationResult */
export interface ValidationResultParams {
  passed?: boolean;
  severity?: Severity;
  reason?: string | null;
  violationType?: ViolationType | null;
  confidence?: number;
}

/** Validation context passed to layers */
export interface ValidationContext {
  logger?: {
    logSecurityDecision?: (result: unknown, message: unknown, layer: string) => void;
  };
  canonical?: string;
  [key: string]: unknown;
}

/**
 * Standard validation result format - all layers return this
 * Backward compatible with existing middleware
 */
export class ValidationResult implements ValidationResultType {
  passed: boolean;
  allowed: boolean;
  severity: Severity;
  reason: string | null;
  violationType: ViolationType | null;
  confidence: number;
  timestamp: number;
  layerName: string | null;

  constructor({
    passed = true,
    severity = 'LOW',
    reason = null,
    violationType = null,
    confidence = 1.0
  }: ValidationResultParams = {}) {
    this.passed = passed;
    this.allowed = passed;  // Backward compatibility alias for securityCheck.allowed
    this.severity = severity;
    this.reason = reason;
    this.violationType = violationType;
    this.confidence = confidence;
    this.timestamp = Date.now();
    this.layerName = null; // Will be set by the layer
  }
}

/**
 * Base class for all validation layers
 * Defines the contract and shared functionality
 */
export class ValidationLayer {
  protected options: ValidationLayerOptions & { enabled: boolean };
  protected name: string;
  protected errorSanitizer: ErrorSanitizer;
  protected debugMode?: boolean;

  constructor(options: ValidationLayerOptions = {}) {
    this.options = {
      enabled: options.enabled !== false, // default enabled
      ...options
    };
    this.name = this.constructor.name;

    // Error sanitizer instance
    this.errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());
  }

  /**
   * Main validation method - MUST be implemented by each layer
   */
  async validate(_message: unknown, _context?: ValidationContext): Promise<ValidationResult> {
    throw new Error(`validate() method must be implemented by ${this.name}`);
  }

  /**
   * Quick check if this layer is enabled
   */
  isEnabled(): boolean {
    return this.options.enabled;
  }

  /**
   * Get layer name for logging/debugging
   */
  getName(): string {
    return this.name;
  }

  /**
   * Create a standardized success result
   */
  createSuccessResult(): ValidationResult {
    const result = new ValidationResult({ passed: true });
    result.layerName = this.getName();
    return result;
  }

  /**
   * Create a standardized failure result
   */
  createFailureResult(
    reason: string,
    severity: Severity = 'MEDIUM',
    violationType: ViolationType = 'UNKNOWN',
    confidence = 1.0
  ): ValidationResult {
    // Sanitize the reason before creating result
    const sanitizedReason = this.errorSanitizer.redact(reason);

    const result = new ValidationResult({
      passed: false,
      reason: sanitizedReason,
      severity,
      violationType,
      confidence
    });
    result.layerName = this.getName();
    return result;
  }

  /**
   * Helper to safely extract message size
   */
  getMessageSize(message: unknown): number {
    try {
      return JSON.stringify(message).length;
    } catch (_error) {
      return 0;
    }
  }

  /**
   * Helper to safely convert message to string for pattern matching
   */
  getMessageString(message: unknown): string {
    try {
      return JSON.stringify(message);
    } catch (_error) {
      return '';
    }
  }

  /**
   * Helper to extract all string values from message (for pattern matching)
   */
  extractStrings(obj: unknown): string[] {
    const strings: string[] = [];

    const extract = (item: unknown): void => {
      if (typeof item === 'string') {
        strings.push(item);
      } else if (Array.isArray(item)) {
        item.forEach(extract);
      } else if (item && typeof item === 'object') {
        Object.values(item).forEach(extract);
      }
    };

    extract(obj);
    return strings;
  }

  /**
   * Helper: Debug logging (writes to stderr when debugMode is enabled)
   * Sanitizes messages to prevent sensitive data leakage
   */
  logDebug(message: string): void {
    if (this.debugMode) {
      // Sanitize debug message to prevent sensitive data leakage
      const sanitized = this.errorSanitizer.redact(message);
      process.stderr.write(`[DEBUG] ${this.name} ${sanitized}\n`);
    }
  }
}
