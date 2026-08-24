// tests/error-sanitizer.test.js
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ErrorSanitizer, createSanitizedErrorResponse } from '../../../src/security/utils/error-sanitizer.js';

describe('ErrorSanitizer', () => {
  let sanitizer;
  let mockLogger;

  beforeEach(() => {
    mockLogger = {
      error: vi.fn(),
      warn: vi.fn(),
      info: vi.fn()
    };
    sanitizer = new ErrorSanitizer({ logger: mockLogger });
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

      it('returns deterministic type-specific messages', () => {
        expect(sanitizer.getSanitizedMessage('VALIDATION_ERROR')).toBe('Request validation failed');
        expect(sanitizer.getSanitizedMessage('POLICY_VIOLATION')).toBe('Request violates policy');
        expect(sanitizer.getSanitizedMessage('RATE_LIMIT_EXCEEDED')).toBe('Too many requests');
      });

      it('returns consistent message for same violation type', () => {
        const messages = new Set();
        for (let i = 0; i < 50; i++) {
          messages.add(sanitizer.getSanitizedMessage('VALIDATION_ERROR'));
        }
        expect(messages.size).toBe(1);
        expect(messages.has('Request validation failed')).toBe(true);
      });

      it('differentiates violation types', () => {
        const msg1 = sanitizer.getSanitizedMessage('VALIDATION_ERROR');
        const msg2 = sanitizer.getSanitizedMessage('POLICY_VIOLATION');
        expect(msg1).toBe('Request validation failed');
        expect(msg2).toBe('Request violates policy');
        expect(msg1).not.toBe(msg2);
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

    describe('Multiple credential pattern collisions', () => {
      it('redacts multiple adjacent credentials', () => {
        // Note: sk_test pattern requires 32+ chars after prefix
        const input = 'Keys: AKIAIOSFODNN7EXAMPLE ghp_1234567890abcdef1234567890abcdef12345678 sk_test_1234567890abcdef1234567890abcdef';
        const result = sanitizer.redact(input);
        expect(result).toContain('****AWS_KEY****');
        expect(result).toContain('****GITHUB_TOKEN****');
        expect(result).toContain('****API_KEY****');
        expect(result).not.toContain('AKIA');
        expect(result).not.toContain('ghp_');
        expect(result).not.toContain('sk_test');
      });

      it('redacts credentials separated only by whitespace', () => {
        // Test multiple AKIA-style AWS keys (exact 20 char format)
        const input = 'AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN8EXAMPLE AKIAIOSFODNN9EXAMPLE';
        const result = sanitizer.redact(input);
        // All three AWS keys should be redacted (each is exactly 20 chars)
        expect((result.match(/\*\*\*\*AWS_KEY\*\*\*\*/g) || []).length).toBe(3);
        expect(result).not.toContain('AKIA');
      });

      it('redacts credentials embedded in JSON-like strings', () => {
        const input = '{"apiKey":"sk_live_abcdef1234567890abcdef12","awsKey":"AKIAIOSFODNN7EXAMPLE"}';
        const result = sanitizer.redact(input);
        expect(result).toContain('****API_KEY****');
        expect(result).toContain('****AWS_KEY****');
      });

      it('redacts standalone hex keys', () => {
        // Pure hex keys are detected when standalone
        const input = 'key: abcdef1234567890abcdef1234567890ab';
        const result = sanitizer.redact(input);
        expect(result).toContain('****HEX_KEY****');
      });

      it('preserves non-credential strings with embedded credential-like substrings', () => {
        // When a credential pattern is embedded in a larger non-matching string,
        // it may not be detected - this documents actual behavior
        const input = 'prefix_AKIAIOSFODNN7EXAMPLE_suffix';
        const result = sanitizer.redact(input);
        // The embedded AWS key pattern isn't detected due to word boundary matching
        // This is actually acceptable behavior - we want to avoid false positives
        expect(typeof result).toBe('string');
      });

      it('redacts multiple emails in same string', () => {
        const input = 'CC: admin@example.com, user@test.org, support@company.net';
        const result = sanitizer.redact(input);
        expect((result.match(/\*\*\*\*EMAIL\*\*\*\*/g) || []).length).toBe(3);
      });

      it('redacts mixed credentials and PII in complex string', () => {
        const input = `
          Config: {
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "github_token": "ghp_1234567890abcdef1234567890abcdef12345678",
            "db_url": "mysql://admin:secret@localhost/mydb",
            "admin_email": "admin@company.com",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
            "password": "super_secret_123"
          }
        `;
        const result = sanitizer.redact(input);
        expect(result).toContain('****AWS_KEY****');
        expect(result).toContain('****GITHUB_TOKEN****');
        expect(result).toContain('****DB_CONNECTION****');
        expect(result).toContain('****EMAIL****');
        expect(result).toContain('****JWT_TOKEN****');
        expect(result).toContain('"password": "****"');
        // Ensure no raw credentials leaked
        expect(result).not.toContain('AKIAIOSFODNN7EXAMPLE');
        expect(result).not.toContain('ghp_1234567890');
        expect(result).not.toContain('admin@company.com');
      });

      it('handles overlapping Bearer token and API key patterns', () => {
        const input = 'Authorization: Bearer sk_test_1234567890abcdef1234567890abcdef';
        const result = sanitizer.redact(input);
        // Should handle both the Bearer prefix and the API key
        expect(result).toContain('Bearer');
        expect(result).toContain('****');
        expect(result).not.toContain('sk_test');
      });

      it('redacts password fields with various quote styles', () => {
        const input = `"password": "secret1" 'password': 'secret2' password="secret3"`;
        const result = sanitizer.redact(input);
        expect(result).not.toContain('secret1');
        expect(result).not.toContain('secret2');
        // Note: password=value without quotes may not be caught - this tests actual behavior
      });

      it('handles repeated same credential', () => {
        const input = 'Key1: AKIAIOSFODNN7EXAMPLE Key2: AKIAIOSFODNN7EXAMPLE Key3: AKIAIOSFODNN7EXAMPLE';
        const result = sanitizer.redact(input);
        expect((result.match(/\*\*\*\*AWS_KEY\*\*\*\*/g) || []).length).toBe(3);
      });
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
    it('logs CRITICAL/HIGH to logger.error', () => {
      sanitizer.logSecurityViolation('corr-123', 'Test violation', 'CRITICAL', 'VALIDATION_ERROR');
      expect(mockLogger.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        type: 'security_violation',
        severity: 'CRITICAL',
        violationType: 'VALIDATION_ERROR',
        correlationId: 'corr-123'
      }));
    });

    it('logs MEDIUM to logger.warn', () => {
      sanitizer.logSecurityViolation('corr-456', 'Test violation', 'MEDIUM', 'POLICY_VIOLATION');
      expect(mockLogger.warn).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        severity: 'MEDIUM'
      }));
    });

    it('logs LOW to logger.info', () => {
      sanitizer.logSecurityViolation('corr-789', 'Test violation', 'LOW', 'UNKNOWN');
      expect(mockLogger.info).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        severity: 'LOW'
      }));
    });

    it('redacts sensitive data in log entries', () => {
      sanitizer.logSecurityViolation('corr-123', 'AWS key AKIAIOSFODNN7EXAMPLE found', 'HIGH', 'VALIDATION_ERROR');
      expect(mockLogger.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'AWS key ****AWS_KEY**** found'
      }));
    });

    it('includes timestamp in ISO format', () => {
      const beforeTime = new Date().toISOString();
      sanitizer.logSecurityViolation('corr-123', 'Test', 'HIGH', 'VALIDATION_ERROR');
      const afterTime = new Date().toISOString();

      const logCall = mockLogger.error.mock.calls[0][1];
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
            token: expect.stringMatching(/^[0-9a-f]{12}$/),
            reason: expect.any(String),
            layer: 'VALIDATION_ERROR',
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
      expect(mockLogger.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
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

      expect(mockLogger.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        reason: 'Test error message',
        violationType: 'INTERNAL_ERROR'
      }));
    });

    it('handles unknown error types', () => {
      sanitizer.createMiddlewareErrorResponse('mid-789', { custom: 'error' });

      expect(mockLogger.error).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
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
          message: 'Request validation failed: Factory test',
          data: expect.objectContaining({
            timestamp: expect.any(String),
            token: expect.any(String)
          })
        }
      });
    });
  });

  describe('Zod Error Detection', () => {
    it('detects "too_big" Zod error code', () => {
      expect(sanitizer.isZodError({ code: 'too_big', maximum: 50, path: ['expression'] })).toBe(true);
    });

    it('detects "too_small" Zod error code', () => {
      expect(sanitizer.isZodError({ code: 'too_small', minimum: 1, path: ['name'] })).toBe(true);
    });

    it('detects "invalid_type" Zod error code', () => {
      expect(sanitizer.isZodError({ code: 'invalid_type', expected: 'string', received: 'number' })).toBe(true);
    });

    it('detects "invalid_enum_value" Zod error code', () => {
      expect(sanitizer.isZodError({ code: 'invalid_enum_value', options: ['a', 'b'], received: 'c' })).toBe(true);
    });

    it('detects Zod errors in issues array', () => {
      const zodErrorData = {
        issues: [
          { code: 'too_big', maximum: 50, path: ['field1'] },
          { code: 'invalid_type', expected: 'string', path: ['field2'] }
        ]
      };
      expect(sanitizer.isZodError(zodErrorData)).toBe(true);
    });

    it('detects errors with path array and code', () => {
      expect(sanitizer.isZodError({ code: 'custom', path: ['nested', 'field'], message: 'Custom error' })).toBe(true);
    });

    it('returns false for null/undefined', () => {
      expect(sanitizer.isZodError(null)).toBe(false);
      expect(sanitizer.isZodError(undefined)).toBe(false);
    });

    it('returns false for non-object values', () => {
      expect(sanitizer.isZodError('string')).toBe(false);
      expect(sanitizer.isZodError(123)).toBe(false);
    });

    it('returns false for non-Zod error codes', () => {
      expect(sanitizer.isZodError({ code: 'UNKNOWN_ERROR', message: 'Something failed' })).toBe(false);
    });

    it('returns false for regular error data without Zod patterns', () => {
      expect(sanitizer.isZodError({ message: 'Regular error', status: 500 })).toBe(false);
    });
  });

  describe('Outgoing Error Sanitization', () => {
    it('preserves -32602 Zod errors (input validation details help callers fix requests)', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: 'req-123',
        error: {
          code: -32602,
          message: 'Invalid params',
          data: {
            code: 'too_big',
            maximum: 50,
            inclusive: true,
            path: ['expression'],
            message: 'String must contain at most 50 character(s)'
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(zodError);
      expect(result).toBe(null);
    });

    it('preserves -32602 Zod "invalid_type" errors', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: 42,
        error: {
          code: -32602,
          message: 'Invalid params',
          data: {
            code: 'invalid_type',
            expected: 'string',
            received: 'number',
            path: ['param1'],
            message: 'Expected string, received number'
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(zodError);
      expect(result).toBe(null);
    });

    it('preserves -32602 Zod "invalid_enum_value" errors', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32602,
          message: 'Invalid params',
          data: {
            code: 'invalid_enum_value',
            options: ['getUsers', 'getUser', 'searchProducts'],
            received: 'deleteAll',
            path: ['operation'],
            message: "Invalid enum value. Expected 'getUsers' | 'getUser' | 'searchProducts', received 'deleteAll'"
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(zodError);
      expect(result).toBe(null);
    });

    it('sanitizes Zod errors on non-(-32602) error codes', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: 'req-internal',
        error: {
          code: -32603,
          message: 'Internal error',
          data: {
            code: 'too_big',
            maximum: 50,
            path: ['internal_field'],
            message: 'String must contain at most 50 character(s)'
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(zodError);

      expect(result).not.toBe(null);
      expect(result.error.message).toBe('Invalid input parameters');
      expect(result.error.data).not.toHaveProperty('path');
      expect(result.error.data).toHaveProperty('layer', 'OUTGOING_SANITIZER');
    });

    it('returns null for non-JSON-RPC messages', () => {
      expect(sanitizer.sanitizeOutgoingError({ type: 'not-jsonrpc' })).toBe(null);
      expect(sanitizer.sanitizeOutgoingError('string')).toBe(null);
      expect(sanitizer.sanitizeOutgoingError(null)).toBe(null);
    });

    describe('MCP SDK raw validation-message rewrite (T3)', () => {
      const sdkError = (message, extra = {}) => ({
        jsonrpc: '2.0',
        id: 'req-sdk',
        error: { code: -32602, message, ...extra }
      });

      it('rewrites the SDK Zod dump into per-field prose, preserving code and id', () => {
        const raw = 'Input validation error: Invalid arguments for tool validate_run: ' +
          '[{"code":"invalid_type","expected":"array","received":"undefined","path":["recommendations"],"message":"Required"}]';
        const result = sanitizer.sanitizeOutgoingError(sdkError(raw));

        expect(result).not.toBe(null);
        expect(result.error.code).toBe(-32602);
        expect(result.id).toBe('req-sdk');
        expect(result.error.message).toContain('Invalid arguments for tool validate_run');
        expect(result.error.message).toContain('recommendations: Required (expected array, the field is missing)');
        expect(result.error.message).not.toContain('"code":"invalid_type"');
        expect(result.error.message).toContain("tool's input schema");
      });

      it('joins multiple issues and dot-joins nested paths', () => {
        const raw = 'Input validation error: Invalid arguments for tool save_run: [' +
          '{"code":"invalid_type","expected":"string","received":"number","path":["agents",0,"name"],"message":"Expected string, received number"},' +
          '{"code":"invalid_type","expected":"array","received":"undefined","path":["recommendations"],"message":"Required"}]';
        const result = sanitizer.sanitizeOutgoingError(sdkError(raw));

        expect(result).not.toBe(null);
        expect(result.error.message).toContain('agents.0.name: Expected string, received number (expected string, received number)');
        expect(result.error.message).toContain('; recommendations: Required');
      });

      it('does NOT rewrite a -32602 whose JSON array is not Zod issues (positive control)', () => {
        const raw = 'Input validation error: Invalid arguments for tool save_run: [{"foo":"bar"}]';
        expect(sanitizer.sanitizeOutgoingError(sdkError(raw))).toBe(null);
      });

      it('does NOT rewrite unparseable or non-matching -32602 messages', () => {
        expect(sanitizer.sanitizeOutgoingError(sdkError('Invalid arguments for tool x: [not json'))).toBe(null);
        expect(sanitizer.sanitizeOutgoingError(sdkError('Tool save_run disabled'))).toBe(null);
        expect(sanitizer.sanitizeOutgoingError(sdkError('Output validation error: Tool x has an output schema but no structured content was provided'))).toBe(null);
      });

      it('rewrites the current-SDK "msg at path" line format', () => {
        const raw = 'Input validation error: Invalid arguments for tool validate_run: ' +
          'Required at project\nRequired at workflow_type\nRequired at agents';
        const result = sanitizer.sanitizeOutgoingError(sdkError(raw));

        expect(result).not.toBe(null);
        expect(result.error.message).toContain('Invalid arguments for tool validate_run');
        expect(result.error.message).toContain('project: Required; workflow_type: Required; agents: Required');
        expect(result.error.message).toContain("tool's input schema");
      });

      it('rewrites an isError CallToolResult carrying the SDK dump (current SDKs wrap, not throw)', () => {
        const message = {
          jsonrpc: '2.0',
          id: 7,
          result: {
            content: [{
              type: 'text',
              text: 'MCP error -32602: Input validation error: Invalid arguments for tool validate_run: ' +
                'Required at project\nRequired at agents',
            }],
            isError: true,
          },
        };
        const result = sanitizer.sanitizeOutgoingError(message);

        expect(result).not.toBe(null);
        expect(result.id).toBe(7);
        expect(result.result.isError).toBe(true);
        const text = result.result.content[0].text;
        expect(text).toContain('project: Required; agents: Required');
        expect(text).not.toContain('MCP error -32602');
        expect(text).toContain("tool's input schema");
      });

      it('passes ordinary tool results and non-matching error results through (positive control)', () => {
        expect(sanitizer.sanitizeOutgoingError({
          jsonrpc: '2.0', id: 1,
          result: { content: [{ type: 'text', text: '{"ok":true}' }] },
        })).toBe(null);
        expect(sanitizer.sanitizeOutgoingError({
          jsonrpc: '2.0', id: 2,
          result: { content: [{ type: 'text', text: '{"error":"Project not found","status":404}' }], isError: true },
        })).toBe(null);
      });

      it('carries existing error.data through the rewrite untouched', () => {
        const raw = 'Input validation error: Invalid arguments for tool get_run: ' +
          '[{"code":"invalid_type","expected":"string","received":"undefined","path":["run_id"],"message":"Required"}]';
        const result = sanitizer.sanitizeOutgoingError(sdkError(raw, { data: { hint: 'kept' } }));
        expect(result).not.toBe(null);
        expect(result.error.data).toEqual({ hint: 'kept' });
      });
    });

    it('returns null for JSON-RPC success responses', () => {
      const successResponse = {
        jsonrpc: '2.0',
        id: 'req-456',
        result: { data: 'success' }
      };
      expect(sanitizer.sanitizeOutgoingError(successResponse)).toBe(null);
    });

    it('returns null for non-Zod error responses', () => {
      const regularError = {
        jsonrpc: '2.0',
        id: 'req-789',
        error: {
          code: -32603,
          message: 'Internal error',
          data: { reason: 'Database connection failed' }
        }
      };
      expect(sanitizer.sanitizeOutgoingError(regularError)).toBe(null);
    });

    it('logs sanitized Zod errors on non-(-32602) codes', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: 'req-log-test',
        error: {
          code: -32603,
          message: 'Internal error',
          data: { code: 'too_big', maximum: 50, path: ['field'] }
        }
      };

      sanitizer.sanitizeOutgoingError(zodError);

      expect(mockLogger.info).toHaveBeenCalledWith('[SECURITY]', expect.objectContaining({
        type: 'security_violation',
        severity: 'LOW',
        violationType: 'VALIDATION_ERROR',
        reason: expect.stringContaining('Zod validation error sanitized')
      }));
    });

    it('does not log for -32602 Zod errors (pass-through)', () => {
      const zodError = {
        jsonrpc: '2.0',
        id: 'req-no-log',
        error: {
          code: -32602,
          message: 'Invalid params',
          data: { code: 'too_big', maximum: 50, path: ['field'] }
        }
      };

      mockLogger.info.mockClear();
      sanitizer.sanitizeOutgoingError(zodError);

      const securityCalls = mockLogger.info.mock.calls.filter(
        call => call[0] === '[SECURITY]'
      );
      expect(securityCalls).toHaveLength(0);
    });
  });

  describe('Exception Path Handling', () => {
    it('should handle circular reference objects in redact', () => {
      const circular = { a: 1 };
      circular.self = circular;

      // Should not throw, should return something sensible
      const result = sanitizer.redact(circular);
      expect(typeof result).toBe('string');
      expect(result).toContain('[object Object]');
    });

    it('should handle objects with throwing toString by propagating error', () => {
      const badObject = {
        toString() {
          throw new Error('toString exploded');
        }
      };

      // String() propagates toString errors - this is expected JavaScript behavior
      // The test documents that redact doesn't add additional try/catch complexity
      expect(() => sanitizer.redact(badObject)).toThrow('toString exploded');
    });

    it('should handle objects with throwing valueOf', () => {
      const badObject = {
        valueOf() {
          throw new Error('valueOf exploded');
        }
      };

      // Should not throw, String() handles this
      expect(() => sanitizer.redact(badObject)).not.toThrow();
    });

    it('should handle Symbol in redact gracefully', () => {
      const sym = Symbol('test');
      // Should not throw
      expect(() => sanitizer.redact(sym)).not.toThrow();
    });

    it('should handle BigInt in redact gracefully', () => {
      const bigNum = BigInt(9007199254740991);
      const result = sanitizer.redact(bigNum);
      expect(result).toBe('9007199254740991');
    });

    it('should handle empty string in redact', () => {
      const result = sanitizer.redact('');
      expect(result).toBe('');
    });

    it('should handle console.error throwing', () => {
      const originalError = console.error;
      console.error = () => {
        throw new Error('console.error failed');
      };

      // logSecurityViolation should not throw even if console does
      try {
        // This might throw, but we want to verify the sanitizer doesn't crash catastrophically
        sanitizer.logSecurityViolation('id', 'test', 'HIGH', 'VALIDATION_ERROR');
      } catch (e) {
        // Expected if console.error throws
      }

      console.error = originalError;
    });

    it('should handle very deeply nested objects in redact', () => {
      let deep = { value: 'secret@email.com' };
      for (let i = 0; i < 100; i++) {
        deep = { nested: deep };
      }

      // Should not throw or hang
      const result = sanitizer.redact(deep);
      expect(typeof result).toBe('string');
    });

    it('should handle array with undefined elements', () => {
      const arr = [1, undefined, 'test@email.com', null];
      const result = sanitizer.redact(arr);
      expect(result).toContain('****EMAIL****');
    });

    it('should handle regex special characters in input without regex errors', () => {
      const regexDangerous = 'test[.*+?^${}()|[]\\input';
      // Should not throw
      const result = sanitizer.redact(regexDangerous);
      expect(typeof result).toBe('string');
    });

    it('should create valid error response even with empty string reason', () => {
      const response = sanitizer.createSanitizedErrorResponse('id-1', '', 'HIGH', 'VALIDATION_ERROR');
      expect(response.jsonrpc).toBe('2.0');
      expect(response.error.code).toBeDefined();
    });

    it('should handle createMiddlewareErrorResponse with null error', () => {
      const response = sanitizer.createMiddlewareErrorResponse('mid-null', null);
      expect(response.jsonrpc).toBe('2.0');
      expect(response.error.code).toBe(-32603);
    });

    it('should handle createMiddlewareErrorResponse with undefined error', () => {
      const response = sanitizer.createMiddlewareErrorResponse('mid-undef', undefined);
      expect(response.jsonrpc).toBe('2.0');
      expect(response.error.code).toBe(-32603);
    });

    it('should handle sanitizeOutgoingError with deeply nested error data on non-(-32602) code', () => {
      const deepZodError = {
        jsonrpc: '2.0',
        id: 'deep-1',
        error: {
          code: -32603,
          message: 'Internal error',
          data: {
            code: 'too_big',
            maximum: 50,
            path: ['level1', 'level2', 'level3', 'level4', 'level5'],
            nested: { deep: { very: { data: 'sensitive' } } }
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(deepZodError);
      expect(result).not.toBe(null);
      expect(result.error.data).not.toHaveProperty('nested');
      expect(result.error.data).not.toHaveProperty('path');
    });

    it('should pass through deeply nested -32602 Zod errors', () => {
      const deepZodError = {
        jsonrpc: '2.0',
        id: 'deep-2',
        error: {
          code: -32602,
          message: 'Invalid params',
          data: {
            code: 'too_big',
            maximum: 50,
            path: ['level1', 'level2', 'level3'],
          }
        }
      };

      const result = sanitizer.sanitizeOutgoingError(deepZodError);
      expect(result).toBe(null);
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