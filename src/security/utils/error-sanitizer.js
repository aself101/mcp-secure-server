// src/security/utils/error-sanitizer.js
// FIXED: Handle undefined/null values properly

import { randomUUID, randomBytes } from 'node:crypto';

export class ErrorSanitizer {
  constructor(options = {}) {
    this.enableDetailedErrors = !!options.enableDetailedErrors;
    this.maxLogLength = options.maxLogLength || 1000;
  }

  // FIXED: redact method to handle undefined values
  redact(value) {
    // FIXED: Provide meaningful default instead of returning undefined
    if (value === null || value === undefined) {
      return 'Validation value null or undefined';
    }
    
    const s = String(value);
    const trimmed = s.length > this.maxLogLength ? s.slice(0, this.maxLogLength) + '…' : s;
    
    return this.redactCredentials(this.redactPII(trimmed));
  }

  // ... rest of methods unchanged ...
  
  generateCorrelationId() {
    return `sec_${randomUUID()}`;
  }

  generatePublicToken() {
    return randomBytes(6).toString('hex');
  }

  getSanitizedMessage(type, severity) {
    if (!this.enableDetailedErrors) {
      const messages = [
        'Request validation failed',
        'Invalid request format', 
        'Request could not be processed'
      ];
      
      const randomValue = randomBytes(1)[0];
      const index = randomValue % messages.length;
      return messages[index];
    }

    const base = {
      VALIDATION_ERROR: 'Request validation failed',
      POLICY_VIOLATION: 'Request violates policy',
      CONTEXT_VIOLATION: 'Request not permitted in context',
      RATE_LIMIT_EXCEEDED: 'Too many requests',
      INTERNAL_ERROR: 'Internal validation error',
      UNKNOWN: 'Request could not be processed'
    }[type] || 'Request could not be processed';

    return base;
  }

  mapSeverityToErrorCode(severity, violationType) {
    if (violationType === 'RATE_LIMIT_EXCEEDED') return -32000;
    if (violationType === 'INTERNAL_ERROR') return -32603;
    return -32602; // Invalid params
  }

  redactCredentials(text) {
    return text
      // Cloud provider keys
      .replace(/\bAKIA[0-9A-Z]{16}\b/g, '****AWS_KEY****')
      .replace(/\bAISA[0-9A-Z]{16}\b/g, '****AWS_KEY****')
      .replace(/\bARIA[0-9A-Z]{16}\b/g, '****AWS_KEY****')
      
      // GitHub tokens
      .replace(/\bgh[pousrnt]_[A-Za-z0-9]{36,255}\b/g, '****GITHUB_TOKEN****')
      
      // Generic API keys
      .replace(/\b[sS][kK]_(?:test|live)_[a-zA-Z0-9]{20,}\b/gi, '****API_KEY****')
      .replace(/\b[a-zA-Z0-9]{32,}\b/g, (match) => {
        return /^[a-fA-F0-9]+$/.test(match) ? '****HEX_KEY****' : match;
      })
      
      // JWT tokens  
      .replace(/\beyJ[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]*\b/g, '****JWT_TOKEN****')
      
      // Authorization headers
      .replace(/Bearer\s+[A-Za-z0-9._\-]{10,}/gi, 'Bearer ****TOKEN****')
      .replace(/Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/gi, 'Authorization: Basic ****')
      .replace(/Authorization:\s*Bearer\s+[A-Za-z0-9._\-]+/gi, 'Authorization: Bearer ****')
      
      // Database connection strings
      .replace(/\b\w+:\/\/[^:]+:[^@]+@[^\/\s]+(?:\/[^\s]*)?/g, '****DB_CONNECTION****')
      
      // Private keys
      .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----/g, '****PRIVATE_KEY****')
      
      // Common password patterns
      .replace(/["\']?password["\']?\s*[:=]\s*["\'][^"']+["\']/gi, '"password": "****"')
      .replace(/["\']?pass["\']?\s*[:=]\s*["\'][^"']+["\']/gi, '"pass": "****"')
      .replace(/["\']?secret["\']?\s*[:=]\s*["\'][^"']+["\']/gi, '"secret": "****"');
  }

  redactPII(text) {
    return text
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '****EMAIL****');
  }

  logSecurityViolation(correlationId, internalReason, severity, violationType) {
    const entry = {
      type: 'security_violation',
      severity,
      violationType,
      correlationId,
      reason: this.redact(internalReason),
      ts: new Date().toISOString()
    };

    if (severity === 'CRITICAL' || severity === 'HIGH') {
      console.error('[SECURITY]', entry);
    } else if (severity === 'MEDIUM') {
      console.warn('[SECURITY]', entry);  
    } else {
      console.info('[SECURITY]', entry);
    }
  }

  createSanitizedErrorResponse(messageId, internalReason, severity = 'MEDIUM', violationType = 'UNKNOWN') {
    const correlationId = this.generateCorrelationId();
    const publicToken = this.generatePublicToken();

    this.logSecurityViolation(correlationId, internalReason, severity, violationType);

    const data = { 
      timestamp: new Date().toISOString(),
      token: publicToken
    };

    if (violationType === 'RATE_LIMIT_EXCEEDED') {
      data.retryAfterMs = 60000;
    }

    return {
      jsonrpc: '2.0',
      id: messageId ?? null,
      error: {
        code: this.mapSeverityToErrorCode(severity, violationType),
        message: this.getSanitizedMessage(violationType, severity),
        data
      }
    };
  }

  createMiddlewareErrorResponse(messageId, errorMessage) {
    const correlationId = this.generateCorrelationId();
    const publicToken = this.generatePublicToken();

    const detail = typeof errorMessage === 'string' ? errorMessage : (errorMessage?.message || 'Middleware error');
    this.logSecurityViolation(correlationId, detail, 'HIGH', 'INTERNAL_ERROR');

    return {
      jsonrpc: '2.0',
      id: messageId ?? null,
      error: {
        code: -32603,
        message: 'Internal validation error',
        data: { 
          timestamp: new Date().toISOString(),
          token: publicToken
        }
      }
    };
  }

  static createProductionConfig() {
    return {
      enableDetailedErrors: false,
      maxLogLength: 500
    };
  }

  static createDevelopmentConfig() {
    return {
      enableDetailedErrors: true,
      maxLogLength: 2000
    };
  }
}

export function createSanitizedErrorResponse(messageId, internalReason, severity, violationType, options = {}) {
  const sanitizer = new ErrorSanitizer(options);
  return sanitizer.createSanitizedErrorResponse(messageId, internalReason, severity, violationType);
}