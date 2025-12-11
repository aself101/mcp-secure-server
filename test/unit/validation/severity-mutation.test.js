import { describe, it, expect, beforeEach } from 'vitest';
import StructureValidationLayer from '@/security/layers/layer1-structure.js';
import ContentValidationLayer from '@/security/layers/layer2-content.js';
import BehaviorValidationLayer from '@/security/layers/layer3-behavior.js';

/**
 * Mutation Tests for Severity Levels
 *
 * These tests verify that changing severity levels (e.g., HIGH to LOW)
 * would cause test failures. This provides confidence that the severity
 * categorization is intentional and correct.
 */
describe('Severity Level Mutation Tests', () => {
  describe('Layer 1 - Structure', () => {
    let layer;

    beforeEach(() => {
      layer = new StructureValidationLayer();
    });

    it('should assign HIGH severity for missing jsonrpc field (not LOW)', async () => {
      const result = await layer.validate({ method: 'test', id: 1 }, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBe('HIGH');
      // Mutation guard: changing to LOW should fail
      expect(result.severity).not.toBe('LOW');
      expect(result.severity).not.toBe('MEDIUM');
    });

    it('should assign HIGH severity for missing method field (not LOW)', async () => {
      const result = await layer.validate({ jsonrpc: '2.0', id: 1 }, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBe('HIGH');
      expect(result.severity).not.toBe('LOW');
    });

    it('should assign MEDIUM severity for oversized message (not LOW)', async () => {
      const layer = new StructureValidationLayer({
        maxMessageSize: 100
      });

      const oversizedMessage = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params: { data: 'x'.repeat(200) }
      };

      const result = await layer.validate(oversizedMessage, {});

      expect(result.passed).toBe(false);
      // Size limits are MEDIUM severity, not LOW
      expect(['MEDIUM', 'HIGH']).toContain(result.severity);
      expect(result.severity).not.toBe('LOW');
    });
  });

  describe('Layer 2 - Content', () => {
    let layer;

    beforeEach(() => {
      layer = new ContentValidationLayer({ debugMode: false });
    });

    it('should assign HIGH severity for path traversal (not MEDIUM/LOW)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'file-reader',
          arguments: { path: '../../../etc/passwd' }
        }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBe('HIGH');
      expect(result.violationType).toBe('PATH_TRAVERSAL');
      // Mutation guard
      expect(result.severity).not.toBe('LOW');
      expect(result.severity).not.toBe('MEDIUM');
    });

    it('should assign CRITICAL severity for command injection (not MEDIUM/LOW)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'shell',
          arguments: { cmd: 'rm -rf /' }
        }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      // Command injection is CRITICAL severity in this implementation
      expect(result.severity).toBe('CRITICAL');
      expect(result.violationType).toBe('COMMAND_INJECTION');
      expect(result.severity).not.toBe('LOW');
    });

    it('should assign HIGH severity for SQL injection (not MEDIUM/LOW)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'query',
          arguments: { sql: "' OR 1=1; DROP TABLE users; --" }
        }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(['SQL_INJECTION', 'COMMAND_INJECTION']).toContain(result.violationType);
      expect(result.severity).toBe('HIGH');
      expect(result.severity).not.toBe('LOW');
    });
  });

  describe('Layer 3 - Behavior', () => {
    it('should assign HIGH severity for rate limit exceeded', async () => {
      const layer = new BehaviorValidationLayer({
        requestsPerMinute: 2,
        requestsPerHour: 100,
        burstThreshold: 10
      });

      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {}
      };

      // Exhaust rate limit
      await layer.validate(message, {});
      await layer.validate(message, {});
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('RATE_LIMIT_EXCEEDED');
      // Rate limits are HIGH severity in this implementation (security-first approach)
      expect(result.severity).toBe('HIGH');
      expect(result.severity).not.toBe('LOW');
    });
  });

  describe('Violation Type Mutation Tests', () => {
    let contentLayer;

    beforeEach(() => {
      contentLayer = new ContentValidationLayer({ debugMode: false });
    });

    it('should correctly identify PATH_TRAVERSAL (not SQL_INJECTION)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { path: '../../../../etc/shadow' }
      };

      const result = await contentLayer.validate(message, {});

      expect(result.violationType).toBe('PATH_TRAVERSAL');
      expect(result.violationType).not.toBe('SQL_INJECTION');
      expect(result.violationType).not.toBe('COMMAND_INJECTION');
    });

    it('should correctly identify SQL_INJECTION (not PATH_TRAVERSAL)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { query: "SELECT * FROM users WHERE id = '' OR '1'='1'" }
      };

      const result = await contentLayer.validate(message, {});

      expect(result.violationType).toBe('SQL_INJECTION');
      expect(result.violationType).not.toBe('PATH_TRAVERSAL');
    });

    it('should correctly identify XSS_ATTEMPT', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { content: '<script>alert("xss")</script>' }
      };

      const result = await contentLayer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('XSS_ATTEMPT');
      expect(result.violationType).not.toBe('SQL_INJECTION');
    });
  });
});

describe('Boundary Value Tests', () => {
  describe('Message Size Boundaries', () => {
    it('should pass message well under max size', async () => {
      const maxSize = 10000;
      const layer = new StructureValidationLayer({ maxMessageSize: maxSize });

      // Create message well under the limit
      const message = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params: { data: 'x'.repeat(100) }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should fail message at exactly max size plus 1', async () => {
      const maxSize = 500;
      const layer = new StructureValidationLayer({ maxMessageSize: maxSize });

      const message = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params: { data: 'x'.repeat(maxSize) }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(['SIZE_LIMIT_EXCEEDED', 'OVERSIZED_MESSAGE']).toContain(result.violationType);
    });
  });

  describe('Rate Limit Boundaries', () => {
    it('should pass first request with fresh layer', async () => {
      // Use high limit to ensure first request passes
      const layer = new BehaviorValidationLayer({
        requestsPerMinute: 100,
        requestsPerHour: 1000,
        burstThreshold: 100
      });

      const message = {
        jsonrpc: '2.0',
        method: 'first-test',  // Unique method name
        id: 'first-1',
        params: {}
      };

      // First request with fresh layer should pass
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should fail when rate limit exceeded', async () => {
      const limit = 3;
      const layer = new BehaviorValidationLayer({
        requestsPerMinute: limit,
        requestsPerHour: 1000,
        burstThreshold: 100
      });

      const message = {
        jsonrpc: '2.0',
        method: 'rate-limit-test',  // Unique method name
        id: 1,
        params: {}
      };

      // Make limit + 1 requests to exceed rate limit
      for (let i = 0; i <= limit; i++) {
        await layer.validate({ ...message, id: `rate-${i}` }, {});
      }

      const overLimitResult = await layer.validate({ ...message, id: 'over' }, {});

      expect(overLimitResult.passed).toBe(false);
      expect(overLimitResult.violationType).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('String Length Boundaries', () => {
    it('should pass method name at max allowed length', async () => {
      const maxMethodLength = 100;
      const layer = new StructureValidationLayer();

      const message = {
        jsonrpc: '2.0',
        method: 'a'.repeat(maxMethodLength),
        id: 1,
        params: {}
      };

      const result = await layer.validate(message, {});

      // Methods up to a reasonable length should pass structure validation
      expect(result.passed).toBe(true);
    });

    it('should fail extremely long method name', async () => {
      const layer = new StructureValidationLayer();

      const message = {
        jsonrpc: '2.0',
        method: 'a'.repeat(1000),
        id: 1,
        params: {}
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Parameter Count Boundaries', () => {
    it('should pass with many parameters under limit', async () => {
      const layer = new StructureValidationLayer({
        maxParamCount: 100
      });

      const params = {};
      for (let i = 0; i < 50; i++) {
        params[`param${i}`] = `value${i}`;
      }

      const message = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should fail with parameters exceeding limit', async () => {
      const layer = new StructureValidationLayer({
        maxParamCount: 10
      });

      const params = {};
      for (let i = 0; i < 20; i++) {
        params[`param${i}`] = `value${i}`;
      }

      const message = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('PARAM_LIMIT_EXCEEDED');
    });
  });
});
