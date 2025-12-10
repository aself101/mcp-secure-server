// Pattern detection functions for Layer 2

import { ATTACK_PATTERNS, attackConfigs } from '../layer-utils/content/dangerous-patterns.js';

/**
 * Consolidated malicious pattern detection for decoded content
 * @param {string} content - Content to check for malicious patterns
 * @returns {boolean} True if malicious patterns found
 */
export function containsMaliciousPatterns(content) {
    const patternGroups = [
        ...ATTACK_PATTERNS.xss.basicVectors,
        ...ATTACK_PATTERNS.xss.eventHandlers,
        ...ATTACK_PATTERNS.xss.jsExecution,
        ...ATTACK_PATTERNS.xss.extraAttributes,
        ...ATTACK_PATTERNS.css.expressions,
        ...ATTACK_PATTERNS.script.pythonInjection,
        ...ATTACK_PATTERNS.script.nodeInjection,
        ...ATTACK_PATTERNS.command.basicInjection,
        ...ATTACK_PATTERNS.command.executionWrappers
    ];

    return patternGroups.some(({ pattern }) => pattern.test(content));
}

/**
 * Generic pattern detection method
 * @param {string} content - Processed content to analyze
 * @param {string} attackType - Human-readable attack type name
 * @param {Array} patternCategories - Array of pattern category objects
 * @param {string} violationType - Violation type for error result
 * @param {number} confidence - Confidence score (0-1)
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function detectPatternCategories(content, attackType, patternCategories, violationType, confidence = 0.85) {
    for (const category of patternCategories) {
        for (const { pattern, name, severity } of category) {
            if (pattern.test(content)) {
                return {
                    passed: false,
                    reason: `${attackType} detected: ${name}`,
                    severity,
                    violationType,
                    confidence
                };
            }
        }
    }
    return { passed: true };
}

/**
 * Validate payload safety against all attack configs
 * @param {string} content - Content to validate
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function validatePayloadSafety(content) {
    for (const config of attackConfigs) {
        const result = detectPatternCategories(
            content,
            config.name,
            config.categories,
            config.violationType,
            config.confidence
        );
        if (!result.passed) return result;
    }

    return { passed: true };
}
