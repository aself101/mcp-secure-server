import { describe, it, expect, beforeEach } from 'vitest';
import SemanticsValidationLayer from '@/security/layers/layer4-semantics.js';

describe('Semantics Validation Layer', () => {
  let layer;

  beforeEach(() => {
    // Use the default policies which are well-configured
    // The default policies already include:
    // - denyGlobs for *.key, *.pem, .env, id_rsa, etc.
    // - rootDirs pointing to test-data
    layer = new SemanticsValidationLayer({
      toolRegistry: [
        {
          name: 'allowed-tool',
          sideEffects: 'none',
          argsShape: { input: { type: 'string' } }
        },
        {
          name: 'read-file',
          sideEffects: 'read',
          argsShape: { path: { type: 'string' } }
        },
        {
          name: 'write-file',
          sideEffects: 'write',
          argsShape: {
            path: { type: 'string' },
            content: { type: 'string' }
          }
        }
      ]
      // Let resourcePolicy use defaults which have properly configured paths
    });
  });

  describe('Method Validation', () => {
    it('should pass valid MCP methods', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: { name: 'allowed-tool', arguments: { input: 'test' } }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should reject unknown methods', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'unknown/dangerous',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/unknown|disallowed/i);
    });

    it('should reject messages without method', async () => {
      const message = { jsonrpc: '2.0', id: 1 };
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Tool Contract Enforcement', () => {
    it('should pass when tool is registered', async () => {
      const message = createToolCallMessage('allowed-tool', { input: 'test data' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should reject calls to unregistered tools', async () => {
      const message = createToolCallMessage('unregistered-tool', { data: 'test' });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/not.*allowed|unknown/i);
    });

    it('should validate args shape when defined', async () => {
      // allowed-tool expects { input: string }
      const message = createToolCallMessage('allowed-tool', { wrong: 'field' });
      const result = await layer.validate(message, {});

      // Should fail because 'input' is missing
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/input|required|missing/i);
    });
  });

  describe('Resource Access Policies', () => {
    it('should block reading outside allowed roots', async () => {
      // /etc/passwd is definitely outside test-data root
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///etc/passwd' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/not.*under.*allowed|root/i);
    });

    it('should block non-file schemes', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'http://evil.com/malware' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/scheme.*not.*allowed/i);
    });

    it('should block reading .key files (deny glob)', async () => {
      // Uses deny glob pattern **/*.key
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///proc/self/creds.key' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should block reading /proc paths (deny glob)', async () => {
      // Uses deny glob pattern /proc/**
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///proc/self/environ' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should block reading .env files (deny glob)', async () => {
      // Uses deny glob pattern **/.env
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///var/app/.env' }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });
  });

  describe('Side Effects and Egress Detection', () => {
    it('should block write tools without permission', async () => {
      // write-file requires policy.allowWrites
      const message = createToolCallMessage('write-file', {
        path: '/tmp/output.txt',
        content: 'data'
      });

      // Without allowWrites in context, should fail
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/write.*permission|requires.*write/i);
    });

    it('should allow write tools with permission', async () => {
      const message = createToolCallMessage('write-file', {
        path: '/tmp/output.txt',
        content: 'data'
      });

      // With allowWrites in context, should pass
      const result = await layer.validate(message, { policy: { allowWrites: true } });
      expect(result.passed).toBe(true);
    });

    it('should pass read operations for registered tools', async () => {
      const message = createToolCallMessage('read-file', {
        path: '/some/file.txt'
      });

      // read-file has sideEffects: 'read' which is always allowed
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });
  });

  describe('Valid Semantic Patterns', () => {
    it('should pass initialize method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'initialize',
        id: 1,
        params: {
          protocolVersion: '2024-11-05',
          capabilities: {},
          clientInfo: { name: 'test', version: '1.0' }
        }
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should pass tools/list method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/list',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should pass resources/list method', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'resources/list',
        id: 1
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null message', async () => {
      const result = await layer.validate(null, {});
      expect(result.passed).toBe(false);
    });

    it('should handle message with null params', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: null
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });

    it('should handle tools/call without tool name', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {}
      };

      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
    });
  });
});

function createToolCallMessage(toolName, args = {}) {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: toolName,
      arguments: args
    }
  };
}
