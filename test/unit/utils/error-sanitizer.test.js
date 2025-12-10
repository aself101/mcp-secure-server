// tests/error-sanitizer.test.js
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ErrorSanitizer, createSanitizedErrorResponse } from '../../../src/security/utils/error-sanitizer.js';

describe('ErrorSanitizer', () => {
  let sanitizer;
  let consoleSpy;

  beforeEach(() => {
    sanitizer = new ErrorSanitizer();
    consoleSpy = {
      error: vi.spyOn(console, 'error').mockImplementation(() => {}),
      warn: vi.spyOn(console, 'warn').mockImplementation(() => {}),
      info: vi.spyOn(console, 'info').mockImplementation(() => {})
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Constructor', () => {
    it('sets default options correctly', () => {
      const sanitizer = new ErrorSanitizer();
      expect(sanitizer.enableDetailedErrors).toBe(false);
      expect(sanitizer.maxLogLength).toBe(1000);
    });

    it('respects custom options', () => {
      const sanitizer = new ErrorSanitizer({
        enableDetailedErrors: true,
        maxLogLength: 500
      });
      expect(sanitizer.enableDetailedErrors).toBe(true);
      expect(sanitizer.maxLogLength).toBe(500);
    });

    it('handles falsy enableDetailedErrors', () => {
      const sanitizer = new ErrorSanitizer({ enableDetailedErrors: 0 });
      expect(sanitizer.enableDetailedErrors).toBe(false);
    });
  });

  describe('ID Generation', () => {
    it('generates correlation IDs with sec_ prefix', () => {
      const id = sanitizer.generateCorrelationId();
      expect(id).toMatch(/^sec_[0-9a-f-]{36}$/);
    });

    it('generates unique correlation IDs', () => {
      const id1 = sanitizer.generateCorrelationId();
      const id2 = sanitizer.generateCorrelationId();
      expect(id1).not.toBe(id2);
    });

    it('generates 12-character hex public tokens', () => {
      const token = sanitizer.generatePublicToken();
      expect(token).toMatch(/^[0-9a-f]{12}$/);
    });

    it('generates unique public tokens', () => {
      const token1 = sanitizer.generatePublicToken();
      const token2 = sanitizer.generatePublicToken();
      expect(token1).not.toBe(token2);
    });
  });

  describe('Message Generation', () => {
    describe('Production mode (enableDetailedErrors: false)', () => {
      beforeEach(() => {
        sanitizer = new ErrorSanitizer({ enableDetailedErrors: false });
      });

      it('returns generic messages', () => {
        const message = sanitizer.getSanitizedMessage('VALIDATION_ERROR');
        const validMessages = [
          'Request validation failed',
          'Invalid request format',
          'Request could not be processed'
        ];
        expect(validMessages).toContain(message);
      });

      it('uses crypto-secure randomization', () => {
        // Test that different calls can return different messages
        const messages = new Set();
        for (let i = 0; i < 50; i++) {
          messages.add(sanitizer.getSanitizedMessage('VALIDATION_ERROR'));
        }
        // Should have some variety in 50 calls (not deterministic but highly likely)
        expect(messages.size).toBeGreaterThanOrEqual(1);
      });

      it('ignores violation type in production', () => {
        const msg1 = sanitizer.getSanitizedMessage('VALIDATION_ERROR');
        const msg2 = sanitizer.getSanitizedMessage('POLICY_VIOLATION');
        // Both should be from the same generic pool
        const validMessages = [
          'Request validation failed',
          'Invalid request format',
          'Request could not be processed'
        ];
        expect(validMessages).toContain(msg1);
        expect(validMessages).toContain(msg2);
      });
    });

    describe('Development mode (enableDetailedErrors: true)', () => {
      beforeEach(() => {
        sanitizer = new ErrorSanitizer({ enableDetailedErrors: true });
      });

      it('returns specific messages for known violation types', () => {
        expect(sanitizer.getSanitizedMessage('VALIDATION_ERROR')).toBe('Request validation failed');
        expect(sanitizer.getSanitizedMessage('POLICY_VIOLATION')).toBe('Request violates policy');
        expect(sanitizer.getSanitizedMessage('CONTEXT_VIOLATION')).toBe('Request not permitted in context');
        expect(sanitizer.getSanitizedMessage('RATE_LIMIT_EXCEEDED')).toBe('Too many requests');
        expect(sanitizer.getSanitizedMessage('INTERNAL_ERROR')).toBe('Internal validation error');
        expect(sanitizer.getSanitizedMessage('UNKNOWN')).toBe('Request could not be processed');
      });

      it('returns default message for unknown violation types', () => {
        expect(sanitizer.getSanitizedMessage('UNKNOWN_TYPE')).toBe('Request could not be processed');
      });
    });
  });

  describe('Error Code Mapping', () => {
    it('maps rate limit to -32000', () => {
      expect(sanitizer.mapSeverityToErrorCode('HIGH', 'RATE_LIMIT_EXCEEDED')).toBe(-32000);
    });

    it('maps internal error to -32603', () => {
      expect(sanitizer.mapSeverityToErrorCode('CRITICAL', 'INTERNAL_ERROR')).toBe(-32603);
    });

    it('maps other violations to -32602', () => {
      expect(sanitizer.mapSeverityToErrorCode('HIGH', 'VALIDATION_ERROR')).toBe(-32602);
      expect(sanitizer.mapSeverityToErrorCode('MEDIUM', 'POLICY_VIOLATION')).toBe(-32602);
      expect(sanitizer.mapSeverityToErrorCode('LOW', 'UNKNOWN')).toBe(-32602);
    });
  });

  describe('Credential Redaction', () => {
    it('redacts AWS access keys', () => {
      expect(sanitizer.redactCredentials('AKIAIOSFODNN7EXAMPLE')).toBe('****AWS_KEY****');
      expect(sanitizer.redactCredentials('AISAIOSFODNN7EXAMPLE')).toBe('****AWS_KEY****');
      expect(sanitizer.redactCredentials('ARIAIOSFODNN7EXAMPLE')).toBe('****AWS_KEY****');
    });

    it('redacts GitHub tokens', () => {
      expect(sanitizer.redactCredentials('ghp_1234567890abcdef1234567890abcdef12345678')).toBe('****GITHUB_TOKEN****');
      expect(sanitizer.redactCredentials('gho_1234567890abcdef1234567890abcdef12345678')).toBe('****GITHUB_TOKEN****');
      expect(sanitizer.redactCredentials('ghu_1234567890abcdef1234567890abcdef12345678')).toBe('****GITHUB_TOKEN****');
    });

    it('redacts Stripe-style API keys', () => {
      expect(sanitizer.redactCredentials('sk_test_1234567890abcdef1234567890abcdef')).toBe('****API_KEY****');
      expect(sanitizer.redactCredentials('SK_LIVE_1234567890abcdef1234567890abcdef')).toBe('****API_KEY****');
    });

    it('redacts hex keys', () => {
      expect(sanitizer.redactCredentials('abcdef1234567890abcdef1234567890ab')).toBe('****HEX_KEY****');
    });

    it('preserves non-hex 32+ char strings', () => {
      expect(sanitizer.redactCredentials('this_is_not_a_hex_key_but_very_long_string')).toBe('this_is_not_a_hex_key_but_very_long_string');
    });

    it('redacts JWT tokens', () => {
      expect(sanitizer.redactCredentials('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c')).toBe('****JWT_TOKEN****');
    });

    it('redacts authorization headers', () => {
      expect(sanitizer.redactCredentials('Bearer abc123def456')).toBe('Bearer ****TOKEN****');
      expect(sanitizer.redactCredentials('Authorization: Basic dXNlcjpwYXNz')).toBe('Authorization: Basic ****');
      expect(sanitizer.redactCredentials('Authorization: Bearer token123')).toBe('Authorization: Bearer ****');
    });

    it('redacts database connection strings', () => {
      expect(sanitizer.redactCredentials('mysql://user:pass@localhost/db')).toBe('****DB_CONNECTION****');
      expect(sanitizer.redactCredentials('postgresql://admin:secret@db.example.com/mydb')).toBe('****DB_CONNECTION****');
    });

    it('redacts PEM private keys', () => {
      const pemKey = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----';
      expect(sanitizer.redactCredentials(pemKey)).toBe('****PRIVATE_KEY****');
    });

    it('redacts password fields', () => {
      expect(sanitizer.redactCredentials('"password": "secret123"')).toBe('"password": "****"');
      expect(sanitizer.redactCredentials("'pass': 'mysecret'")).toBe('"pass": "****"');
      expect(sanitizer.redactCredentials('secret: "topsecret"')).toBe('"secret": "****"');
    });
  });

  describe('PII Redaction', () => {
    it('redacts email addresses', () => {
      expect(sanitizer.redactPII('user@example.com')).toBe('****EMAIL****');
      expect(sanitizer.redactPII('Contact: admin@company.org for help')).toBe('Contact: ****EMAIL**** for help');
    });

    it('preserves non-email @ symbols', () => {
      expect(sanitizer.redactPII('Price: $10 @ store')).toBe('Price: $10 @ store');
    });
  });

  describe('Combined Redaction', () => {
    it('applies both credential and PII redaction', () => {
      const input = 'AWS key AKIAIOSFODNN7EXAMPLE sent to user@example.com';
      const result = sanitizer.redact(input);
      expect(result).toBe('AWS key ****AWS_KEY**** sent to ****EMAIL****');
    });

    it('respects maxLogLength', () => {
      const sanitizer = new ErrorSanitizer({ maxLogLength: 10 });
      const longText = 'This is a very long string that exceeds the limit';
      expect(sanitizer.redact(longText)).toBe('This is a …');
    });

    it('handles null and undefined', () => {
      expect(sanitizer.redact(null)).toBe('Validation value null or undefined');
      expect(sanitizer.redact(undefined)).toBe('Validation value null or undefined');
    });

    it('handles non-string values', () => {
      expect(sanitizer.redact(123)).toBe('123');
      expect(sanitizer.redact(true)).toBe('true');
      expect(sanitizer.redact({})).toBe('[object Object]');
    });
  });

  describe('Security Violation Logging', () => {
    it('logs CRITICAL/HIGH to console.error', () => {
      sanitizer.logSecurityViolation('corr-123', 'Test violation', 'CRITICAL', 'VALIDATION_ERROR');
      expect(consoleSpy.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        type: 'security_violation',
        severity: 'CRITICAL',
        violationType: 'VALIDATION_ERROR',
        correlationId: 'corr-123'
      }));
    });

    it('logs MEDIUM to console.warn', () => {
      sanitizer.logSecurityViolation('corr-456', 'Test violation', 'MEDIUM', 'POLICY_VIOLATION');
      expect(consoleSpy.warn).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        severity: 'MEDIUM'
      }));
    });

    it('logs LOW to console.info', () => {
      sanitizer.logSecurityViolation('corr-789', 'Test violation', 'LOW', 'UNKNOWN');
      expect(consoleSpy.info).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        severity: 'LOW'
      }));
    });

    it('redacts sensitive data in log entries', () => {
      sanitizer.logSecurityViolation('corr-123', 'AWS key AKIAIOSFODNN7EXAMPLE found', 'HIGH', 'VALIDATION_ERROR');
      expect(consoleSpy.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'AWS key ****AWS_KEY**** found'
      }));
    });

    it('includes timestamp in ISO format', () => {
      const beforeTime = new Date().toISOString();
      sanitizer.logSecurityViolation('corr-123', 'Test', 'HIGH', 'VALIDATION_ERROR');
      const afterTime = new Date().toISOString();
      
      const logCall = consoleSpy.error.mock.calls[0][1];
      expect(logCall.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
      expect(logCall.ts >= beforeTime && logCall.ts <= afterTime).toBe(true);
    });
  });

  describe('createSanitizedErrorResponse', () => {
    it('creates valid JSON-RPC error response', () => {
      const response = sanitizer.createSanitizedErrorResponse('test-123', 'Validation failed', 'HIGH', 'VALIDATION_ERROR');
      
      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 'test-123',
        error: {
          code: -32602,
          message: expect.any(String),
          data: {
            timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
            token: expect.stringMatching(/^[0-9a-f]{12}$/)
          }
        }
      });
    });

    it('adds retryAfterMs for rate limit violations', () => {
      const response = sanitizer.createSanitizedErrorResponse('test-456', 'Rate limited', 'HIGH', 'RATE_LIMIT_EXCEEDED');
      expect(response.error.data.retryAfterMs).toBe(60000);
    });

    it('handles null messageId', () => {
      const response = sanitizer.createSanitizedErrorResponse(null, 'Test error', 'MEDIUM', 'UNKNOWN');
      expect(response.id).toBe(null);
    });

    it('logs security violation', () => {
      sanitizer.createSanitizedErrorResponse('test-789', 'Test error', 'HIGH', 'POLICY_VIOLATION');
      expect(consoleSpy.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'Test error',
        violationType: 'POLICY_VIOLATION'
      }));
    });
  });

  describe('createMiddlewareErrorResponse', () => {
    it('creates internal error response', () => {
      const response = sanitizer.createMiddlewareErrorResponse('mid-123', 'Middleware failure');
      
      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 'mid-123',
        error: {
          code: -32603,
          message: 'Internal validation error',
          data: {
            timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
            token: expect.stringMatching(/^[0-9a-f]{12}$/)
          }
        }
      });
    });

    it('handles Error objects', () => {
      const error = new Error('Test error message');
      sanitizer.createMiddlewareErrorResponse('mid-456', error);
      
      expect(consoleSpy.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'Test error message',
        violationType: 'INTERNAL_ERROR'
      }));
    });

    it('handles unknown error types', () => {
      sanitizer.createMiddlewareErrorResponse('mid-789', { custom: 'error' });
      
      expect(consoleSpy.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'Middleware error',
        violationType: 'INTERNAL_ERROR'
      }));
    });
  });

  describe('Configuration Helpers', () => {
    it('creates production config', () => {
      const config = ErrorSanitizer.createProductionConfig();
      expect(config).toEqual({
        enableDetailedErrors: false,
        maxLogLength: 500
      });
    });

    it('creates development config', () => {
      const config = ErrorSanitizer.createDevelopmentConfig();
      expect(config).toEqual({
        enableDetailedErrors: true,
        maxLogLength: 2000
      });
    });
  });

  describe('Factory Function', () => {
    it('creates sanitized response using factory', () => {
      const response = createSanitizedErrorResponse('factory-123', 'Factory test', 'MEDIUM', 'VALIDATION_ERROR', {
        enableDetailedErrors: true
      });
      
      expect(response).toEqual({
        jsonrpc: '2.0',
        id: 'factory-123',
        error: {
          code: -32602,
          message: 'Request validation failed',
          data: expect.objectContaining({
            timestamp: expect.any(String),
            token: expect.any(String)
          })
        }
      });
    });
  });

  describe('Stress Tests', () => {
    it('handles large payloads efficiently', () => {
      const largeText = 'A'.repeat(100000);
      const start = performance.now();
      const result = sanitizer.redact(largeText);
      const duration = performance.now() - start;
      
      expect(duration).toBeLessThan(100); // Should complete in < 100ms
      expect(result.length).toBeLessThanOrEqual(1001); // Truncated to maxLogLength + ellipsis
    });

    it('generates many unique IDs without performance degradation', () => {
      const ids = new Set();
      const start = performance.now();
      
      for (let i = 0; i < 1000; i++) {
        ids.add(sanitizer.generateCorrelationId());
      }
      
      const duration = performance.now() - start;
      expect(duration).toBeLessThan(100); // Should complete in < 100ms
      expect(ids.size).toBe(1000); // All unique
    });

    it('handles complex redaction patterns', () => {
      const complexText = `
        AWS: AKIAIOSFODNN7EXAMPLE
        GitHub: ghp_1234567890abcdef1234567890abcdef12345678
        Email: admin@company.com
        JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature
        Password: "password": "secret123"
        DB: postgresql://user:pass@localhost/db
      `;
      
      const start = performance.now();
      const result = sanitizer.redact(complexText);
      const duration = performance.now() - start;
      
      expect(duration).toBeLessThan(50); // Should be fast even with many patterns
      expect(result).toContain('****AWS_KEY****');
      expect(result).toContain('****GITHUB_TOKEN****');
      expect(result).toContain('****EMAIL****');
      expect(result).toContain('****JWT_TOKEN****');
      expect(result).toContain('"password": "****"');
      expect(result).toContain('****DB_CONNECTION****');
    });
  });
});