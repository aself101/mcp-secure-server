// tests/unit/layers/validation-layer-base.test.js
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ValidationLayer, ValidationResult } from '../../../src/security/layers/validation-layer-base.js';

// Mock ErrorSanitizer
vi.mock('../../../src/security/utils/error-sanitizer.js', () => {
  const ErrorSanitizerMock = vi.fn().mockImplementation(() => ({
    redact: vi.fn((text) => `REDACTED: ${text}`)
  }));
  
  ErrorSanitizerMock.createProductionConfig = vi.fn(() => ({
    enableDetailedErrors: false,
    maxLogLength: 1000
  }));
  
  return { ErrorSanitizer: ErrorSanitizerMock };
});

// Concrete implementation for testing abstract base class
class TestValidationLayer extends ValidationLayer {
  async validate(message, context) {
    return this.createSuccessResult();
  }
}

describe('ValidationResult', () => {
  describe('Constructor', () => {
    it('creates result with default values', () => {
      const result = new ValidationResult();
      
      expect(result.passed).toBe(true);
      expect(result.severity).toBe('LOW');
      expect(result.reason).toBe(null);
      expect(result.violationType).toBe(null);
      expect(result.confidence).toBe(1.0);
      expect(typeof result.timestamp).toBe('number');
      expect(result.timestamp).toBeGreaterThan(0);
      expect(result.layerName).toBe(null);
    });

    it('creates result with custom values', () => {
      const result = new ValidationResult({
        passed: false,
        severity: 'HIGH',
        reason: 'XSS detected',
        violationType: 'XSS_ATTACK',
        confidence: 0.9
      });
      
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('HIGH');
      expect(result.reason).toBe('XSS detected');
      expect(result.violationType).toBe('XSS_ATTACK');
      expect(result.confidence).toBe(0.9);
    });

    it('sets backward compatibility aliases', () => {
      const successResult = new ValidationResult({ passed: true });
      expect(successResult.allowed).toBe(true);
      expect(successResult.valid).toBe(true);
      
      const failureResult = new ValidationResult({ passed: false });
      expect(failureResult.allowed).toBe(false);
      expect(failureResult.valid).toBe(false);
    });

    it('includes timestamp', () => {
      const before = Date.now();
      const result = new ValidationResult();
      const after = Date.now();
      
      expect(result.timestamp).toBeGreaterThanOrEqual(before);
      expect(result.timestamp).toBeLessThanOrEqual(after);
    });

    it('initializes layerName as null', () => {
      const result = new ValidationResult();
      expect(result.layerName).toBe(null);
    });
  });
});

describe('ValidationLayer', () => {
  let layer;

  beforeEach(() => {
    layer = new TestValidationLayer();
  });

  describe('Constructor', () => {
    it('initializes with default options enabled true', () => {
      const defaultLayer = new TestValidationLayer();
      expect(defaultLayer.options.enabled).toBe(true);
      expect(defaultLayer.isEnabled()).toBe(true);
    });

    it('initializes with custom options enabled false', () => {
      const disabledLayer = new TestValidationLayer({ enabled: false });
      expect(disabledLayer.options.enabled).toBe(false);
      expect(disabledLayer.isEnabled()).toBe(false);
    });
  });

  describe('Abstract Method Contract', () => {
    it('validate throws error when not implemented', async () => {
      class AbstractLayer extends ValidationLayer {}
      const abstractLayer = new AbstractLayer();
      
      await expect(abstractLayer.validate({})).rejects.toThrow('validate() method must be implemented');
    });
  });

  describe('Result Creation Methods', () => {
    it('createSuccessResult returns valid success result', () => {
      const result = layer.createSuccessResult();
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.layerName).toBe('TestValidationLayer');
    });

    it('createFailureResult returns valid failure result', () => {
      const result = layer.createFailureResult(
        'Path traversal detected',
        'HIGH',
        'PATH_TRAVERSAL',
        0.95
      );
      
      expect(result.passed).toBe(false);
      expect(result.allowed).toBe(false);
      expect(result.valid).toBe(false);
      expect(result.severity).toBe('HIGH');
      expect(result.violationType).toBe('PATH_TRAVERSAL');
      expect(result.confidence).toBe(0.95);
      expect(result.layerName).toBe('TestValidationLayer');
    });

    it('createFailureResult sanitizes reason with ErrorSanitizer', () => {
      const result = layer.createFailureResult(
        'Attack containing password123',
        'MEDIUM'
      );
      
      expect(result.reason).toContain('REDACTED');
    });
  });

  describe('Helper Methods', () => {
    it('getMessageSize returns correct JSON length', () => {
      const message = {
        jsonrpc: "2.0",
        method: "tools/call",
        id: "1"
      };
      
      const size = layer.getMessageSize(message);
      const expectedSize = JSON.stringify(message).length;
      
      expect(size).toBe(expectedSize);
    });

    it('extractStrings finds all strings in nested object', () => {
      const message = {
        method: "tools/call",
        params: {
          name: "calculator",
          arguments: {
            expression: "2+2"
          }
        }
      };
      
      const strings = layer.extractStrings(message);
      
      expect(strings).toContain("tools/call");
      expect(strings).toContain("calculator");
      expect(strings).toContain("2+2");
      expect(strings.length).toBe(3);
    });

    it('extractStrings handles arrays and nested structures', () => {
      const message = {
        data: ["first", "second"],
        nested: {
          deep: {
            value: "third"
          },
          list: ["fourth", "fifth"]
        }
      };
      
      const strings = layer.extractStrings(message);
      
      expect(strings).toContain("first");
      expect(strings).toContain("second");
      expect(strings).toContain("third");
      expect(strings).toContain("fourth");
      expect(strings).toContain("fifth");
      expect(strings.length).toBe(5);
    });
  });
});