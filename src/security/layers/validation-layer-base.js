// src/security/layers/validation-layer-base.js
import { ErrorSanitizer } from '../utils/error-sanitizer.js';

/**
 * Standard validation result format - all layers return this
 * Backward compatible with existing middleware
 */
class ValidationResult {
    constructor({
        passed = true,
        severity = 'LOW',
        reason = null,
        violationType = null,
        confidence = 1.0
    } = {}) {
        this.passed = passed;
        
        // Backward compatibility aliases for existing middleware
        this.allowed = passed;  // for securityCheck.allowed
        this.valid = passed;    // for existing validation methods
        
        this.severity = severity; // 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        this.reason = reason;
        this.violationType = violationType;
        this.confidence = confidence; // 0.0 to 1.0
        this.timestamp = Date.now();
        this.layerName = null; // Will be set by the layer
    }
}

/**
 * Base class for all validation layers
 * Defines the contract and shared functionality
 */
class ValidationLayer {
    constructor(options = {}) {
        this.options = {
            enabled: options.enabled !== false, // default enabled
            ...options
        };
        this.name = this.constructor.name;
        
        // ADD: Error sanitizer instance
        this.errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());
    }

    /**
     * Main validation method - MUST be implemented by each layer
     * @param {Object} message - The MCP JSON-RPC message
     * @param {Object} context - Request context (session, user, etc.)
     * @returns {Promise<ValidationResult>}
     */
    async validate(message, context) {
        throw new Error(`validate() method must be implemented by ${this.name}`);
    }

    /**
     * Quick check if this layer is enabled
     * @returns {boolean}
     */
    isEnabled() {
        return this.options.enabled;
    }

    /**
     * Get layer name for logging/debugging
     * @returns {string}
     */
    getName() {
        return this.name;
    }

    /**
     * Create a standardized success result
     * @returns {ValidationResult}
     */
    createSuccessResult() {
        const result = new ValidationResult({ passed: true });
        result.layerName = this.getName();
        return result;
    }

    /**
     * Create a standardized failure result
     * UPDATED: Sanitize reason before creating result
     * @param {string} reason - Why it failed
     * @param {string} severity - 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
     * @param {string} violationType - Type of violation detected
     * @param {number} confidence - How confident we are (0.0-1.0)
     * @returns {ValidationResult}
     */
    createFailureResult(reason, severity = 'MEDIUM', violationType = 'UNKNOWN', confidence = 1.0) {
        // UPDATED: Sanitize the reason before creating result
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
     * @param {Object} message
     * @returns {number}
     */
    getMessageSize(message) {
        try {
            return JSON.stringify(message).length;
        } catch (error) {
            return 0;
        }
    }

    /**
     * Helper to safely convert message to string for pattern matching
     * @param {Object} message
     * @returns {string}
     */
    getMessageString(message) {
        try {
            return JSON.stringify(message);
        } catch (error) {
            return '';
        }
    }

    /**
     * Helper to extract all string values from message (for pattern matching)
     * @param {Object} obj
     * @returns {string[]}
     */
    extractStrings(obj) {
        const strings = [];
        
        const extract = (item) => {
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
     * Helper: Debug logging
     */
    logDebug(message) {
        if (this.debugMode) {
            console.error(`${this.name} ${message}`);
        }
    }
}

export { ValidationLayer, ValidationResult }