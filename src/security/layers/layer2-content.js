/* Utils */
import { getMessageCacheKey } from "./layer-utils/content/helper-utils.js"
import { canonicalizeFromMessage } from './layer-utils/content/canonicalize.js';
import { ValidationLayer } from './validation-layer-base.js';

/* Validators - extracted for modularity */
import {
    validateBase64Content as checkBase64,
    validateCSSContent as checkCSS,
    validatePayloadSafety as checkPayload,
    validateDataFormats as checkDataFormats,
    validateEncodingConsistency as checkEncoding,
    validateParameters as checkParams,
    validateContext as checkContext
} from './layer2-validators/index.js';

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
export default class ContentValidationLayer extends ValidationLayer {
    constructor(options = {}) {
        super(options);

        this.processedContentCache = new Map();
        this.cacheMaxSize = options.cacheMaxSize || 1000;
        this.debugMode = options.debugMode || false;

        this.logDebug('Enhanced Content Validation Layer initialized with security hardening');
    }

    /**
     * Main validation entry point
     * Applies centralized content processing to ALL validation methods
     */
    async validate(message, context) {
        const startTime = performance.now();

        try {
            if (message === null || message === undefined || typeof message !== 'object') {
                const type = message === null ? 'null' : typeof message;
                return this.createFailureResult(
                    `Invalid message input: ${type}`,
                    'CRITICAL',
                    'VALIDATION_ERROR'
                );
            }

            if (Object.keys(message).length === 0) {
                return this.createFailureResult(
                    'Empty message object',
                    'CRITICAL',
                    'VALIDATION_ERROR'
                );
            }

            const processedContent = this.getSecureProcessedContent(message, context);
            this.logDebug?.(`L2 using canonical, len=${processedContent.length}`);

            const validations = [
                this.validateContent(message, processedContent),
                this.validatePayloadSafety(message, processedContent),
                this.validateDataConsistency(message, processedContent),
                this.validateSemantics(message, context, processedContent)
            ];

            for (let i = 0; i < validations.length; i++) {
                const result = await validations[i];
                if (!result.passed) {
                    result.validationTime = performance.now() - startTime;
                    result.failedAtMethod = ['validateContent', 'validatePayloadSafety', 'validateDataConsistency', 'validateSemantics'][i];

                    this.logDebug(`Validation failed at ${result.failedAtMethod}: ${result.reason}`);
                    return result;
                }
            }

            const successResult = this.createSuccessResult();
            successResult.validationTime = performance.now() - startTime;

            this.logDebug(`All content validations passed in ${successResult.validationTime.toFixed(2)}ms`);
            return successResult;

        } catch (error) {
            console.error(error)
            this.logDebug(`Content validation error: ${error.message}`);
            return this.createFailureResult(
                `Content validation error: ${error.message}`,
                'CRITICAL',
                'VALIDATION_ERROR'
            );
        }
    }

    /**
     * Centralized secure content processing
     * Applies ALL security transformations in correct order
     */
    getSecureProcessedContent(message, context) {
        const messageKey = getMessageCacheKey(message);

        if (this.processedContentCache.has(messageKey)) {
            return this.processedContentCache.get(messageKey);
        }

        if (this.processedContentCache.size >= this.cacheMaxSize) {
            this.processedContentCache.clear();
        }
        const processed = canonicalizeFromMessage(message)

        if (context) context.canonical = processed
        this.processedContentCache.set(messageKey, processed);
        this.logDebug(`Content processed via canonicalize(): ${processed.length} chars`);

        return processed;
    }

    /**
     * Content validation with multi-stage processing
     */
    async validateContent(message, processedContent) {
        const content = processedContent || this.getSecureProcessedContent(message, processedContent);

        const base64Check = checkBase64(content, this.logDebug?.bind(this));
        if (!base64Check.passed) return this.wrapResult(base64Check);

        const cssCheck = checkCSS(content);
        if (!cssCheck.passed) return this.wrapResult(cssCheck);

        return this.createSuccessResult();
    }

    /**
     * Payload safety validation using pattern detection
     */
    async validatePayloadSafety(message, processedContent) {
        const content = processedContent || this.getSecureProcessedContent(message, processedContent);

        const result = checkPayload(content);
        if (!result.passed) return this.wrapResult(result);

        return this.createSuccessResult();
    }

    /**
     * Data consistency validation with processed content
     */
    async validateDataConsistency(message, processedContent) {
        const content = processedContent || this.getSecureProcessedContent(message, processedContent);
        const strings = this.extractStrings(message);

        const formatResult = checkDataFormats(strings);
        if (!formatResult.passed) return this.wrapResult(formatResult);

        const encodingResult = checkEncoding(content);
        if (!encodingResult.passed) return this.wrapResult(encodingResult);

        return this.createSuccessResult();
    }

    /**
     * Semantic validation with processed content
     */
    async validateSemantics(message, context, _processedContent) {
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

    /**
     * Convert validator result to layer result format
     */
    wrapResult(result) {
        if (result.passed) {
            return this.createSuccessResult();
        }
        return this.createFailureResult(
            result.reason,
            result.severity || 'MEDIUM',
            result.violationType || 'UNKNOWN',
            result.confidence || 1.0
        );
    }

    /**
     * Enhanced validation result with additional metadata
     */
    createFailureResult(reason, severity = 'MEDIUM', violationType = 'UNKNOWN', confidence = 1.0) {
        const result = super.createFailureResult(reason, severity, violationType, confidence);

        return {
            ...result,
            detectionLayer: 'Layer2-Content',
            timestamp: Date.now(),
            processingStage: 'content_validation'
        }
    }
}

/* END */
