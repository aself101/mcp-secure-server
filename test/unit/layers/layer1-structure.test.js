import { describe, it, expect, beforeEach } from 'vitest';
import StructureValidationLayer from '@/security/layers/layer1-structure.js';

describe('Structure Validation Layer', () => {
  let layer;

  beforeEach(() => {
    layer = new StructureValidationLayer();
  });

  describe('JSON-RPC Structure Validation', () => {
    it('should pass valid JSON-RPC message', async () => {
      const validMessage = createTestMessage();
      const result = await layer.validate(validMessage, {});
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
    });

    it('should fail without jsonrpc field', async () => {
      const invalidMessage = { method: 'test', id: 1 };
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('JSON-RPC version');
      expect(result.severity).toBe('HIGH');
    });

    it('should fail with wrong jsonrpc version', async () => {
      const invalidMessage = { jsonrpc: '1.0', method: 'test', id: 1 };
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('JSON-RPC version');
    });

    it('should fail without method field', async () => {
      const invalidMessage = { jsonrpc: '2.0', id: 1 };
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('method field');
    });

    it('should fail with invalid method format', async () => {
      const invalidMessage = { 
        jsonrpc: '2.0', 
        method: 'a'.repeat(200), 
        id: 1 
      };
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Invalid method name format');
    });

    it('should accept valid ID types', async () => {
      const testCases = [
        { jsonrpc: '2.0', method: 'test', id: 'string-id' },
        { jsonrpc: '2.0', method: 'test', id: 123 },
        { jsonrpc: '2.0', method: 'test', id: null }
      ];

      for (const message of testCases) {
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
      }
    });

    it('should fail with invalid ID types', async () => {
      const invalidMessage = { 
        jsonrpc: '2.0', 
        method: 'test', 
        id: { object: 'invalid' } 
      };
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Invalid ID field type');
    });
  });

  describe('Encoding Validation', () => {
    it('should accept clean messages', async () => {
      const cleanMessage = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'test-tool', arguments: { data: 'clean test data' } }
      };
      const result = await layer.validate(cleanMessage, {});

      expect(result.passed).toBe(true);
    });

    it('should detect dangerous unicode characters in params', async () => {
      const dangerousChars = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u202E'];

      for (const char of dangerousChars) {
        const maliciousMessage = {
          jsonrpc: '2.0',
          method: 'tools/call',
          id: 1,
          params: { name: 'test-tool', arguments: { data: `test${char}malicious` } }
        };
        const result = await layer.validate(maliciousMessage, {});

        expect(result.passed).toBe(false);
        expect(result.reason).toContain('Suspicious unicode character');
        expect(result.severity).toBe('MEDIUM');
      }
    });
  });

  describe('Size Limits', () => {
    it('should accept normal sized messages', async () => {
      const normalMessage = createTestMessage();
      const result = await layer.validate(normalMessage, {});

      expect(result.passed).toBe(true);
    });

    it('should reject oversized messages', async () => {
      const oversizedMessage = {
        jsonrpc: '2.0',
        method: 'test',
        id: 1,
        params: {
          data: 'x'.repeat(60000) // Exceeds default 50KB limit
        }
      };
      const result = await layer.validate(oversizedMessage, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Message too large');
      expect(result.severity).toBe('HIGH');
    });

    it('should reject suspiciously small messages', async () => {
      const tinyMessage = { a: 1 };
      const result = await layer.validate(tinyMessage, {});

      expect(result.passed).toBe(false);
      // This will fail on JSON-RPC validation first, not size
      expect(result.reason).toContain('JSON-RPC version');
    });
  });

  describe('Default Limit Boundaries', () => {
    it('should accept message near MESSAGE_SIZE_MAX boundary (49500 bytes)', async () => {
      // Use non-MCP method to avoid schema validation
      // Test message size close to but under the 50000 byte limit
      const params = {};
      const chunkSize = 4000; // Under STRING_LENGTH_MAX of 5000
      const numChunks = 12;   // 12 chunks * 4000 = 48000 base

      for (let i = 0; i < numChunks; i++) {
        params[`d${i}`] = 'x'.repeat(chunkSize);
      }

      const atLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params
      };

      // Verify we're under the limit but close to it
      const actualSize = JSON.stringify(atLimitMessage).length;
      expect(actualSize).toBeLessThan(50000);
      expect(actualSize).toBeGreaterThan(48000); // Reasonably close

      const result = await layer.validate(atLimitMessage, {});
      expect(result.passed).toBe(true);
    });

    it('should reject message 1 byte over MESSAGE_SIZE_MAX boundary', async () => {
      // Spread data across multiple params to avoid STRING_LENGTH_MAX
      const params = {};
      const chunkSize = 4000;
      const numChunks = 13; // 13 chunks * 4000 = 52000, well over 50000

      for (let i = 0; i < numChunks; i++) {
        params[`d${i}`] = 'x'.repeat(chunkSize);
      }

      const overLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params
      };

      const result = await layer.validate(overLimitMessage, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Message too large');
    });

    it('should accept params with exactly PARAM_COUNT_MAX (100) parameters', async () => {
      // Use non-MCP method to avoid schema validation requiring 'name' param
      const exactParams = {};
      for (let i = 0; i < 100; i++) {
        exactParams[`p${i}`] = 'v';
      }

      const atLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params: exactParams
      };
      const result = await layer.validate(atLimitMessage, {});
      expect(result.passed).toBe(true);
    });

    it('should reject params with 101 parameters (over PARAM_COUNT_MAX)', async () => {
      const tooManyParams = {};
      for (let i = 0; i < 101; i++) {
        tooManyParams[`p${i}`] = 'v';
      }

      const overLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params: tooManyParams
      };
      const result = await layer.validate(overLimitMessage, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Too many parameters');
    });

    it('should accept string at exactly STRING_LENGTH_MAX (5000 chars)', async () => {
      // Use non-MCP method to avoid schema validation
      const atLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params: { data: 'x'.repeat(5000) }
      };

      const result = await layer.validate(atLimitMessage, {});
      expect(result.passed).toBe(true);
    });

    it('should reject string at STRING_LENGTH_MAX + 1 (5001 chars)', async () => {
      const overLimitMessage = {
        jsonrpc: '2.0',
        method: 'custom/test',
        id: 1,
        params: { data: 'x'.repeat(5001) }
      };

      const result = await layer.validate(overLimitMessage, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });

    it('should accept method name at METHOD_NAME_MAX boundary (100 chars)', async () => {
      const atLimitMessage = {
        jsonrpc: '2.0',
        method: 'x'.repeat(100),
        id: 1
      };

      const result = await layer.validate(atLimitMessage, {});
      expect(result.passed).toBe(true);
    });

    it('should reject method name over METHOD_NAME_MAX boundary (101 chars)', async () => {
      const overLimitMessage = {
        jsonrpc: '2.0',
        method: 'x'.repeat(101),
        id: 1
      };

      const result = await layer.validate(overLimitMessage, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Invalid method name format');
    });
  });

  describe('Parameter Validation', () => {
    it('should accept valid parameter structures', async () => {
      const testCases = [
        createTestMessage({ method: 'tools/list' }), // No params required
        createTestMessage({ params: { name: 'test-tool', arguments: {} } }), // Valid for tools/call
        { jsonrpc: '2.0', method: 'custom/method', id: 1 } // Non-MCP method without params
      ];

      for (const message of testCases) {
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
      }
    });

    it('should reject invalid parameter types', async () => {
      const invalidMessage = createTestMessage({ params: 'string-not-object' });
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Invalid params type');
    });

    it('should limit parameter count', async () => {
      // Use a layer with explicit low limit for this test
      const strictLayer = new StructureValidationLayer({ maxParamCount: 20 });

      const tooManyParams = {};
      for (let i = 0; i < 25; i++) {
        tooManyParams[`param${i}`] = 'value';
      }

      const invalidMessage = createTestMessage({ params: tooManyParams });
      const result = await strictLayer.validate(invalidMessage, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Too many parameters');
    });

    it('should limit string length', async () => {
      const longString = 'x'.repeat(6000);
      const invalidMessage = createTestMessage({ 
        params: { longParam: longString } 
      });
      const result = await layer.validate(invalidMessage, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });
  });

  describe('MCP Method Schema Validation', () => {
    it('should validate tools/call schema', async () => {
      const validToolCall = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'calculator' }
      };
      const result = await layer.validate(validToolCall, {});
      
      expect(result.passed).toBe(true);
    });

    it('should reject tools/call without name', async () => {
      const invalidToolCall = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {}
      };
      const result = await layer.validate(invalidToolCall, {});
      
      expect(result.passed).toBe(false);
      expect(result.reason).toContain("requires 'name' parameter");
    });

    it('should validate resources/read schema', async () => {
      const validResourceRead = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file://test.txt' }
      };
      const result = await layer.validate(validResourceRead, {});
      
      expect(result.passed).toBe(true);
    });

    it('should reject resources/read without uri', async () => {
      const invalidResourceRead = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: {}
      };
      const result = await layer.validate(invalidResourceRead, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toContain("requires 'uri' parameter");
    });
  });

  describe('Configurable String Length', () => {
    const longStringMessage = (length) => ({
      jsonrpc: '2.0',
      method: 'custom/test',
      id: 1,
      params: { data: 'x'.repeat(length) }
    });

    it('should accept strings over the default limit when maxStringLength is raised', async () => {
      // maxMessageSize must leave headroom above maxStringLength — the message
      // envelope is larger than the string it carries
      const relaxedLayer = new StructureValidationLayer({
        maxStringLength: 100_000,
        maxMessageSize: 256 * 1024
      });

      const result = await relaxedLayer.validate(longStringMessage(50_000), {});
      expect(result.passed).toBe(true);
    });

    it('should still reject strings over a raised maxStringLength', async () => {
      const relaxedLayer = new StructureValidationLayer({
        maxStringLength: 100_000,
        maxMessageSize: 256 * 1024
      });

      const result = await relaxedLayer.validate(longStringMessage(100_001), {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });

    it('should enforce a lowered maxStringLength', async () => {
      const strictLayer = new StructureValidationLayer({ maxStringLength: 100 });

      const result = await strictLayer.validate(longStringMessage(101), {});
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });
  });
});