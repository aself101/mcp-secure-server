// Base64 and CSS validation functions for Layer 2

import { ATTACK_PATTERNS } from '../layer-utils/content/dangerous-patterns.js';
import { containsMaliciousPatterns } from './pattern-detection.js';

/**
 * Validate base64 content including data URIs
 * @param {string} content - Content to validate
 * @param {Function} logDebug - Debug logging function
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function validateBase64Content(content, logDebug) {
    const dataUriPattern = /data:\s*([^;,\s]+)?\s*((?:;[^,\s]*)*)\s*,\s*([A-Za-z0-9+/=\s]+)/gi;
    const foundUris = [];
    let match;

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
 * @param {string} mimeType - MIME type to validate
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function validateDataUriMimeType(mimeType) {
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
 * @param {string} data - Base64 data to validate
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function validateBase64Data(data) {
    let decoded;
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
 * @param {string} content - Content to validate
 * @returns {{ passed: boolean, reason?: string, severity?: string, violationType?: string, confidence?: number }}
 */
export function validateCSSContent(content) {
    const cssCategories = [
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
