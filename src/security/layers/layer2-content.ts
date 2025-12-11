/**
 * Layer 2: Enhanced Content Validation (Security-Hardened)
 *
 * SECURITY FEATURES:
 * Unicode normalization (fullwidth → halfwidth)
 * HTML entity decoding (hex, decimal, named)
 * Base64 data URI inspection and validation
 * CSS expression attack detection
 * Advanced XSS pattern detection
 * Multi-stage encoding attack prevention
 * Case-insensitive pattern matching
 * Performance optimization with content caching
 * Comprehensive attack vector coverage
 */

import { getMessageCacheKey } from "./layer-utils/content/helper-utils.js";
import { canonicalizeFromMessage } from './layer-utils/content/canonicalize.js';
import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import type { Severity, ViolationType } from '../../types/index.js';

import {
  validateBase64Content as checkBase64,
  validateCSSContent as checkCSS,
  validatePayloadSafety as checkPayload,
  validateDataFormats as checkDataFormats,
  validateEncodingConsistency as checkEncoding,
  validateParameters as checkParams,
  validateContext as checkContext
} from './layer2-validators/index.js';

/** Maximum input size for content validation (2MB) */
const MAX_CONTENT_INPUT_SIZE = 2 * 1024 * 1024;

/** Layer 2 specific options */
export interface ContentLayerOptions extends ValidationLayerOptions {
  cacheMaxSize?: number;
  debugMode?: boolean;
  maxInputSize?: number;
}

/** Validator result from layer2-validators */
interface ValidatorResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType | null;
  confidence?: number;
}

/** Extended validation result with Layer 2 metadata */
interface ContentValidationResult extends ValidationResult {
  validationTime?: number;
  failedAtMethod?: string;
  detectionLayer?: string;
  processingStage?: string;
}

export default class ContentValidationLayer extends ValidationLayer {
  private processedContentCache: Map<string, string>;
  private cacheMaxSize: number;
  private maxInputSize: number;
  protected override debugMode: boolean;

  constructor(options: ContentLayerOptions = {}) {
    super(options);

    this.processedContentCache = new Map();
    this.cacheMaxSize = options.cacheMaxSize ?? 1000;
    this.maxInputSize = options.maxInputSize ?? MAX_CONTENT_INPUT_SIZE;
    this.debugMode = options.debugMode ?? false;

    this.logDebug('Enhanced Content Validation Layer initialized with security hardening');
  }

  async validate(message: unknown, context?: ValidationContext): Promise<ContentValidationResult> {
    const startTime = performance.now();

    try {
      if (message === null || message === undefined || typeof message !== 'object') {
        const type = message === null ? 'null' : typeof message;
        return this.createContentFailureResult(
          `Invalid message input: ${type}`,
          'CRITICAL',
          'VALIDATION_ERROR'
        );
      }

      if (Object.keys(message).length === 0) {
        return this.createContentFailureResult(
          'Empty message object',
          'CRITICAL',
          'VALIDATION_ERROR'
        );
      }

      // Input length validation before regex processing to prevent ReDoS
      const messageSize = this.getMessageSize(message);
      if (messageSize > this.maxInputSize) {
        return this.createContentFailureResult(
          `Input size ${messageSize} exceeds maximum allowed ${this.maxInputSize}`,
          'HIGH',
          'VALIDATION_ERROR'
        );
      }

      const processedContent = this.getSecureProcessedContent(message, context);
      this.logDebug(`L2 using canonical, len=${processedContent.length}`);

      const validations = [
        this.validateContent(message, processedContent),
        this.validatePayloadSafety(message, processedContent),
        this.validateDataConsistency(message, processedContent),
        this.validateSemantics(message, context, processedContent)
      ];

      const methodNames = ['validateContent', 'validatePayloadSafety', 'validateDataConsistency', 'validateSemantics'];

      for (let i = 0; i < validations.length; i++) {
        const result = await validations[i] as ContentValidationResult;
        if (!result.passed) {
          result.validationTime = performance.now() - startTime;
          result.failedAtMethod = methodNames[i];

          this.logDebug(`Validation failed at ${result.failedAtMethod}: ${result.reason}`);
          return result;
        }
      }

      const successResult = this.createSuccessResult() as ContentValidationResult;
      successResult.validationTime = performance.now() - startTime;

      this.logDebug(`All content validations passed in ${successResult.validationTime.toFixed(2)}ms`);
      return successResult;

    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logDebug(`Content validation error: ${errorMessage}`);
      return this.createContentFailureResult(
        `Content validation error: ${errorMessage}`,
        'CRITICAL',
        'VALIDATION_ERROR'
      );
    }
  }

  private getSecureProcessedContent(message: unknown, context?: ValidationContext): string {
    const messageKey = getMessageCacheKey(message);

    const cached = this.processedContentCache.get(messageKey);
    if (cached) {
      return cached;
    }

    if (this.processedContentCache.size >= this.cacheMaxSize) {
      this.processedContentCache.clear();
    }

    const processed = canonicalizeFromMessage(message);

    if (context) context.canonical = processed;
    this.processedContentCache.set(messageKey, processed);
    this.logDebug(`Content processed via canonicalize(): ${processed.length} chars`);

    return processed;
  }

  private async validateContent(_message: unknown, processedContent: string): Promise<ValidationResult> {
    const base64Check = checkBase64(processedContent, this.logDebug.bind(this));
    if (!base64Check.passed) return this.wrapResult(base64Check);

    const cssCheck = checkCSS(processedContent);
    if (!cssCheck.passed) return this.wrapResult(cssCheck);

    return this.createSuccessResult();
  }

  private async validatePayloadSafety(_message: unknown, processedContent: string): Promise<ValidationResult> {
    const result = checkPayload(processedContent);
    if (!result.passed) return this.wrapResult(result);

    return this.createSuccessResult();
  }

  private async validateDataConsistency(message: unknown, processedContent: string): Promise<ValidationResult> {
    const strings = this.extractStrings(message);

    const formatResult = checkDataFormats(strings);
    if (!formatResult.passed) return this.wrapResult(formatResult);

    const encodingResult = checkEncoding(processedContent);
    if (!encodingResult.passed) return this.wrapResult(encodingResult);

    return this.createSuccessResult();
  }

  private async validateSemantics(message: unknown, context: ValidationContext | undefined, _processedContent: string): Promise<ValidationResult> {
    if (message === null || message === undefined || typeof message !== 'object') {
      return this.createFailureResult(
        'Invalid message for semantic validation',
        'CRITICAL',
        'VALIDATION_ERROR'
      );
    }

    const paramResult = checkParams(message);
    if (!paramResult.passed) return this.wrapResult(paramResult);

    const contextResult = checkContext(message, context);
    if (!contextResult.passed) return this.wrapResult(contextResult);

    return this.createSuccessResult();
  }

  private wrapResult(result: ValidatorResult): ValidationResult {
    if (result.passed) {
      return this.createSuccessResult();
    }
    return this.createFailureResult(
      result.reason ?? 'Unknown error',
      result.severity ?? 'MEDIUM',
      result.violationType ?? 'UNKNOWN',
      result.confidence ?? 1.0
    );
  }

  private createContentFailureResult(
    reason: string,
    severity: Severity = 'MEDIUM',
    violationType: ViolationType = 'UNKNOWN',
    confidence = 1.0
  ): ContentValidationResult {
    const result = super.createFailureResult(reason, severity, violationType, confidence);

    return {
      ...result,
      detectionLayer: 'Layer2-Content',
      timestamp: Date.now(),
      processingStage: 'content_validation'
    };
  }
}
