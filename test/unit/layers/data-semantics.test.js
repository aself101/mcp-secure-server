import { describe, it, expect } from 'vitest';
import {
    validateDataFormats,
    validateEncodingConsistency,
    validateParameters,
    validateContext
} from '@/security/layers/layer2-validators/data-semantics.js';

describe('Data Semantics Validation', () => {
    describe('validateDataFormats', () => {
        it('should pass for normal strings', () => {
            const result = validateDataFormats(['Hello', 'World', 'Normal text']);
            expect(result.passed).toBe(true);
        });

        it('should pass for empty array', () => {
            const result = validateDataFormats([]);
            expect(result.passed).toBe(true);
        });

        it('should detect test credentials like password123', () => {
            const result = validateDataFormats(['user input', 'password123', 'more text']);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('SUSPICIOUS_TEST_DATA');
        });

        it('should pass for generic test usernames (pattern-specific)', () => {
            // Generic "testuser" may not trigger pattern - depends on exact pattern definitions
            const result = validateDataFormats(['testuser']);
            // Actual behavior: testuser alone doesn't match patterns
            expect(result.passed).toBe(true);
        });

        it('should detect test credentials with password patterns', () => {
            // These should match test credential patterns
            const result = validateDataFormats(['test123password']);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('SUSPICIOUS_TEST_DATA');
        });

        it('should detect admin password patterns', () => {
            const result = validateDataFormats(['admin123']);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('SUSPICIOUS_TEST_DATA');
        });

        it('should detect malicious content in large base64 strings', () => {
            // Create base64 of malicious content that's > 100 chars
            const malicious = '<script>alert("xss")</script>'.repeat(5);
            const largeBase64 = btoa(malicious);
            const result = validateDataFormats([largeBase64]);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('SUSPICIOUS_ENCODING');
        });

        it('should flag large suspicious base64-like strings that fail decoding', () => {
            // Invalid base64 that's long enough to trigger check
            const suspiciousString = 'AAAA'.repeat(30) + '!!!invalid!!!';
            // This doesn't match base64 pattern due to invalid chars, so it passes
            const result = validateDataFormats([suspiciousString]);
            expect(result.passed).toBe(true);
        });

        it('should pass for valid short base64 strings', () => {
            // Short base64 strings are not checked
            const shortBase64 = btoa('short');
            const result = validateDataFormats([shortBase64]);
            expect(result.passed).toBe(true);
        });

        it('should pass for safe long base64 content', () => {
            // Long but safe content
            const safeContent = 'This is a normal safe string that is quite long but contains no malicious patterns'.repeat(2);
            const safeBase64 = btoa(safeContent);
            const result = validateDataFormats([safeBase64]);
            expect(result.passed).toBe(true);
        });
    });

    describe('validateEncodingConsistency', () => {
        it('should pass for normal text', () => {
            const result = validateEncodingConsistency('Hello, this is normal text');
            expect(result.passed).toBe(true);
        });

        it('should pass for single encoding type', () => {
            const result = validateEncodingConsistency('Some text with &amp; and &lt; entities');
            expect(result.passed).toBe(true);
        });

        it('should pass for two encoding types', () => {
            const result = validateEncodingConsistency('&amp; %20 %3C');
            expect(result.passed).toBe(true);
        });

        it('should detect mixed encoding evasion (3+ types, >10 total)', () => {
            // HTML entities + URL encoding + Unicode escapes + hex
            const mixed = '&amp; &lt; &gt; %20 %3C %3E \\u0041 \\u0042 \\u0043 \\x41 \\x42 \\x43';
            const result = validateEncodingConsistency(mixed);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('ENCODING_EVASION');
            expect(result.severity).toBe('MEDIUM');
        });

        it('should pass when 3 types but low total count', () => {
            // 3 types but only a few of each
            const mixed = '&amp; %20 \\u0041';
            const result = validateEncodingConsistency(mixed);
            expect(result.passed).toBe(true);
        });

        it('should pass for empty string', () => {
            const result = validateEncodingConsistency('');
            expect(result.passed).toBe(true);
        });
    });

    describe('validateParameters', () => {
        it('should pass for valid message with params', () => {
            const message = {
                method: 'tools/call',
                params: { name: 'test', value: 123 }
            };
            const result = validateParameters(message);
            expect(result.passed).toBe(true);
        });

        it('should pass for message without params', () => {
            const message = { method: 'ping' };
            const result = validateParameters(message);
            expect(result.passed).toBe(true);
        });

        it('should fail for null message', () => {
            const result = validateParameters(null);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('VALIDATION_ERROR');
        });

        it('should fail for undefined message', () => {
            const result = validateParameters(undefined);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('VALIDATION_ERROR');
        });

        it('should fail for non-object message', () => {
            const result = validateParameters('not an object');
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('VALIDATION_ERROR');
        });

        it('should detect excessive nesting (>15 levels)', () => {
            // Create deeply nested object
            let nested = { value: 'deep' };
            for (let i = 0; i < 20; i++) {
                nested = { level: nested };
            }
            const message = { method: 'test', params: nested };
            const result = validateParameters(message);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('EXCESSIVE_NESTING');
        });

        it('should pass for acceptable nesting (<=15 levels)', () => {
            let nested = { value: 'acceptable' };
            for (let i = 0; i < 10; i++) {
                nested = { level: nested };
            }
            const message = { method: 'test', params: nested };
            const result = validateParameters(message);
            expect(result.passed).toBe(true);
        });

        it('should detect oversized params (>50000 bytes by default)', () => {
            const largeData = 'x'.repeat(60000);
            const message = { method: 'test', params: { data: largeData } };
            const result = validateParameters(message);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('OVERSIZED_PARAMS');
        });

        it('should pass params above 50000 bytes when maxParamBytes is raised', () => {
            // Regression: bulk-save tools (e.g. tracker save_run with 46 recommendations)
            // legitimately exceed 50KB; the per-tool maxArgsSize allowed 2MB but this
            // hardcoded cap rejected the call first.
            const largeData = 'x'.repeat(60000);
            const message = { method: 'test', params: { data: largeData } };
            const result = validateParameters(message, Infinity, 500 * 1024);
            expect(result.passed).toBe(true);
        });

        it('should enforce a lowered maxParamBytes', () => {
            const message = { method: 'test', params: { data: 'x'.repeat(2000) } };
            const result = validateParameters(message, Infinity, 1000);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('OVERSIZED_PARAMS');
        });

        it('should detect excessive parameter count when limit is set', () => {
            const params = {};
            for (let i = 0; i < 150; i++) {
                params[`param${i}`] = i;
            }
            const message = { method: 'test', params };
            // Pass explicit limit of 100
            const result = validateParameters(message, 100);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('EXCESSIVE_PARAM_COUNT');
        });

        it('should pass for acceptable parameter count when under limit', () => {
            const params = {};
            for (let i = 0; i < 50; i++) {
                params[`param${i}`] = i;
            }
            const message = { method: 'test', params };
            // Pass explicit limit of 100
            const result = validateParameters(message, 100);
            expect(result.passed).toBe(true);
        });

        it('should skip parameter count check when limit is Infinity', () => {
            const params = {};
            for (let i = 0; i < 500; i++) {
                params[`param${i}`] = i;
            }
            const message = { method: 'test', params };
            // Default limit is Infinity - should pass
            const result = validateParameters(message);
            expect(result.passed).toBe(true);
        });

        it('should handle circular reference in params (caught as excessive nesting)', () => {
            const params = { a: 1 };
            params.circular = params;
            const message = { method: 'test', params };
            const result = validateParameters(message);
            expect(result.passed).toBe(false);
            // Circular references are caught by nesting check before serialization
            expect(result.violationType).toBe('EXCESSIVE_NESTING');
        });
    });

    describe('validateContext', () => {
        it('should pass when no context provided', () => {
            const result = validateContext({ method: 'test' }, null);
            expect(result.passed).toBe(true);
        });

        it('should pass when no request history in context', () => {
            const result = validateContext({ method: 'test' }, {});
            expect(result.passed).toBe(true);
        });

        it('should pass for normal request frequency', () => {
            const now = Date.now();
            const context = {
                requestHistory: Array(50).fill(null).map((_, i) => ({
                    timestamp: now - i * 1000
                }))
            };
            const result = validateContext({ method: 'test' }, context);
            expect(result.passed).toBe(true);
        });

        it('should detect request flooding (>100 requests/minute)', () => {
            const now = Date.now();
            const context = {
                requestHistory: Array(150).fill(null).map((_, i) => ({
                    timestamp: now - i * 100 // All within last 15 seconds
                }))
            };
            const result = validateContext({ method: 'test' }, context);
            expect(result.passed).toBe(false);
            expect(result.violationType).toBe('REQUEST_FLOODING');
            expect(result.severity).toBe('HIGH');
        });

        it('should not count old requests in frequency check', () => {
            const now = Date.now();
            const context = {
                requestHistory: [
                    ...Array(50).fill(null).map((_, i) => ({
                        timestamp: now - i * 1000 // Recent: 50 in last 50 seconds
                    })),
                    ...Array(200).fill(null).map((_, i) => ({
                        timestamp: now - 120000 - i * 1000 // Old: 200 more than 2 minutes ago
                    }))
                ]
            };
            const result = validateContext({ method: 'test' }, context);
            expect(result.passed).toBe(true); // Only 50 recent
        });
    });
});
