import { describe, it, expect, beforeEach } from 'vitest';
import path from 'node:path';
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
        },
        {
          name: 'egress-limited-tool',
          sideEffects: 'none',
          maxEgressBytes: 1000000,
          argsShape: { data: { type: 'object' } }
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

  describe('Quota enforcement', () => {
    const createQuotaProvider = () => {
      const counts = new Map();
      return {
        incrementAndCheck(key, limits) {
          const next = (counts.get(key) ?? 0) + 1;
          counts.set(key, next);
          if (limits?.minute && next > limits.minute) {
            return {
              passed: false,
              reason: 'Quota exceeded',
              violationType: 'QUOTA_EXCEEDED'
            };
          }
          return { passed: true };
        }
      };
    };

    it('enforces per-tool quotas', async () => {
      const layerWithQuotas = new SemanticsValidationLayer({
        toolRegistry: [
          {
            name: 'limited-tool',
            sideEffects: 'none',
            argsShape: { input: { type: 'string' } },
            quotaPerMinute: 1
          }
        ],
        quotaProvider: createQuotaProvider()
      });

      const message = createToolCallMessage('limited-tool', { input: 'hello' });
      const first = await layerWithQuotas.validate(message, {});
      expect(first.passed).toBe(true);

      const second = await layerWithQuotas.validate(message, {});
      expect(second.passed).toBe(false);
      expect(second.violationType).toBe('QUOTA_EXCEEDED');
      expect(second.reason).toMatch(/quota/i);
    });

    it('enforces resource read quotas', async () => {
      const baseDir = path.resolve(process.cwd(), 'test-data');
      const uri = `file://${path.join(baseDir, 'example.txt')}`;

      const layerWithQuotas = new SemanticsValidationLayer({
        resourcePolicy: {
          allowedSchemes: ['file'],
          rootDirs: [baseDir],
          denyGlobs: [],
          maxPathLength: 4096,
          maxUriLength: 2048,
          maxReadBytes: 2_000_000
        },
        quotas: {
          'resources/read': { minute: 1 }
        },
        quotaProvider: createQuotaProvider()
      });

      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri }
      };

      const first = await layerWithQuotas.validate(message, {});
      expect(first.passed).toBe(true);

      const second = await layerWithQuotas.validate(message, {});
      expect(second.passed).toBe(false);
      expect(second.violationType).toBe('QUOTA_EXCEEDED');
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

    it('should handle circular reference in tool arguments (safeSizeOrFail)', async () => {
      // Create a circular reference that will cause JSON.stringify to fail
      const circularObj = { name: 'test' };
      circularObj.self = circularObj;

      // Use egress-limited-tool which has maxEgressBytes, triggering safeSizeOrFail
      const message = createToolCallMessage('egress-limited-tool', { data: circularObj });
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('ARG_SERIALIZATION_ERROR');
      expect(result.reason).toMatch(/serialization error/i);
    });

    it('should report policy validation failure with proper fields (wrapPolicyResult)', async () => {
      // Trigger a policy validation failure - accessing outside allowed roots
      const message = {
        jsonrpc: '2.0',
        method: 'resources/read',
        id: 1,
        params: { uri: 'file:///etc/shadow' }
      };

      const result = await layer.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.severity).toBeDefined();
      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
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

describe('Method Chaining Validation', () => {
  let layer;

  beforeEach(() => {
    layer = new SemanticsValidationLayer({
      enforceChaining: true,
      toolRegistry: [
        { name: 'test-tool', sideEffects: 'none' }
      ]
    });
  });

  it('should be disabled by default', async () => {
    const defaultLayer = new SemanticsValidationLayer({
      toolRegistry: [{ name: 'test-tool', sideEffects: 'none' }]
    });

    // Calling tools/list without initialize should pass when chaining disabled
    const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };
    const result = await defaultLayer.validate(message, { sessionId: 'default-test' });
    expect(result.passed).toBe(true);
  });

  it('should allow initialize as first method', async () => {
    const message = {
      jsonrpc: '2.0',
      method: 'initialize',
      id: 1,
      params: {}
    };

    const result = await layer.validate(message, { sessionId: 'init-test' });
    expect(result.passed).toBe(true);
  });

  it('should block tools/list before initialize', async () => {
    const message = { jsonrpc: '2.0', method: 'tools/list', id: 1 };

    const result = await layer.validate(message, { sessionId: 'chain-test-1' });
    expect(result.passed).toBe(false);
    expect(result.violationType).toBe('CHAIN_VIOLATION');
    expect(result.reason).toMatch(/Transition denied.*\*.*tools\/list/);
  });

  it('should allow tools/list after initialize', async () => {
    const sessionId = 'chain-test-2';

    // First: initialize
    const initMsg = { jsonrpc: '2.0', method: 'initialize', id: 1, params: {} };
    const initResult = await layer.validate(initMsg, { sessionId });
    expect(initResult.passed).toBe(true);

    // Then: tools/list
    const listMsg = { jsonrpc: '2.0', method: 'tools/list', id: 2 };
    const listResult = await layer.validate(listMsg, { sessionId });
    expect(listResult.passed).toBe(true);
  });

  it('should allow tools/call after tools/list', async () => {
    const sessionId = 'chain-test-3';

    // initialize → tools/list → tools/call
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });
    await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });

    const callMsg = createToolCallMessage('test-tool');
    const result = await layer.validate(callMsg, { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should allow repeated tools/call', async () => {
    const sessionId = 'chain-test-4';

    // initialize → tools/list → tools/call → tools/call
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });
    await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });
    await layer.validate(createToolCallMessage('test-tool'), { sessionId });

    const result = await layer.validate(createToolCallMessage('test-tool'), { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should allow ping from any state', async () => {
    const sessionId = 'ping-test';

    // ping is allowed from * (any state)
    const pingMsg = { jsonrpc: '2.0', method: 'ping', id: 1 };
    const result = await layer.validate(pingMsg, { sessionId });
    expect(result.passed).toBe(true);
  });

  it('should track sessions independently', async () => {
    // Session A initializes
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId: 'session-a' });

    // Session B tries tools/list without initialize - should fail
    const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 1 }, { sessionId: 'session-b' });
    expect(result.passed).toBe(false);
    expect(result.violationType).toBe('CHAIN_VIOLATION');
  });

  it('should use clientId as fallback for session key', async () => {
    // Using clientId instead of sessionId
    await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { clientId: 'client-1' });
    const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { clientId: 'client-1' });
    expect(result.passed).toBe(true);
  });
});

describe('Extended Chaining Rules', () => {
  describe('simpleGlobMatch', () => {
    // Import the function for direct testing
    let simpleGlobMatch;
    beforeEach(async () => {
      const module = await import('@/security/layers/layer-utils/semantics/semantic-policies.js');
      simpleGlobMatch = module.simpleGlobMatch;
    });

    it('should match undefined pattern to anything', () => {
      expect(simpleGlobMatch(undefined, 'anything')).toBe(true);
      expect(simpleGlobMatch(undefined, undefined)).toBe(true);
    });

    it('should match * pattern to anything', () => {
      expect(simpleGlobMatch('*', 'file-reader')).toBe(true);
      expect(simpleGlobMatch('*', 'http-client')).toBe(true);
      expect(simpleGlobMatch('*', '')).toBe(true);
    });

    it('should match exact names', () => {
      expect(simpleGlobMatch('file-reader', 'file-reader')).toBe(true);
      expect(simpleGlobMatch('file-reader', 'file-writer')).toBe(false);
    });

    it('should match prefix patterns', () => {
      expect(simpleGlobMatch('file-*', 'file-reader')).toBe(true);
      expect(simpleGlobMatch('file-*', 'file-writer')).toBe(true);
      expect(simpleGlobMatch('file-*', 'http-client')).toBe(false);
    });

    it('should match suffix patterns', () => {
      expect(simpleGlobMatch('*-reader', 'file-reader')).toBe(true);
      expect(simpleGlobMatch('*-reader', 'config-reader')).toBe(true);
      expect(simpleGlobMatch('*-reader', 'file-writer')).toBe(false);
    });

    it('should match contains patterns', () => {
      expect(simpleGlobMatch('*-http-*', 'api-http-client')).toBe(true);
      expect(simpleGlobMatch('*-http-*', 'my-http-fetch')).toBe(true);
      expect(simpleGlobMatch('*-http-*', 'file-reader')).toBe(false);
    });

    it('should match single character wildcard', () => {
      expect(simpleGlobMatch('debug-?', 'debug-1')).toBe(true);
      expect(simpleGlobMatch('debug-?', 'debug-a')).toBe(true);
      expect(simpleGlobMatch('debug-?', 'debug-12')).toBe(false);
    });

    it('should be case insensitive', () => {
      expect(simpleGlobMatch('File-Reader', 'file-reader')).toBe(true);
      expect(simpleGlobMatch('FILE-*', 'file-reader')).toBe(true);
    });

    it('should not grow cache unboundedly', async () => {
      // Import the cache size constant
      const module = await import('@/security/layers/layer-utils/semantics/semantic-policies.js');
      const { simpleGlobMatch: globMatch, GLOB_CACHE_MAX_SIZE } = module;

      // Generate 150 unique patterns (more than MAX_CACHE_SIZE of 100)
      for (let i = 0; i < 150; i++) {
        globMatch(`pattern-${i}-*`, `pattern-${i}-test`);
      }

      // The cache should not exceed MAX_CACHE_SIZE
      // We can't directly inspect the cache, but we can verify the function still works
      // and that older patterns get evicted (they'll be recompiled on next use)
      expect(GLOB_CACHE_MAX_SIZE).toBe(100);

      // Verify matching still works after many patterns
      expect(globMatch('new-pattern-*', 'new-pattern-test')).toBe(true);
      expect(globMatch('another-*-suffix', 'another-middle-suffix')).toBe(true);
    });
  });

  describe('SideEffect-based chaining rules', () => {
    let layer;
    // Context with network permission enabled (so we can test chaining, not permission checks)
    const ctx = (sessionId) => ({ sessionId, policy: { allowNetwork: true, allowWrites: true } });

    beforeEach(() => {
      layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'file-reader', sideEffects: 'read' },
          { name: 'http-client', sideEffects: 'network' },
          { name: 'calculator', sideEffects: 'none' },
          { name: 'file-writer', sideEffects: 'write' }
        ],
        chainingRules: [
          // Block read → network (exfiltration prevention)
          {
            id: 'block-exfil',
            from: 'tools/call',
            to: 'tools/call',
            fromSideEffect: 'read',
            toSideEffect: 'network',
            action: 'deny'
          },
          // Allow standard MCP flow
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' },
          { from: 'tools/call', to: 'tools/call' },
          { from: '*', to: 'ping' }
        ]
      });
    });

    it('should block read → network transitions', async () => {
      const sessionId = 'exfil-test-1';

      // Setup: initialize → tools/list → tools/call(file-reader)
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('file-reader', { path: '/data.txt' }), ctx(sessionId));

      // Attempt: file-reader (read) → http-client (network)
      const result = await layer.validate(createToolCallMessage('http-client', { url: 'http://evil.com' }), ctx(sessionId));

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('CHAIN_VIOLATION');
      expect(result.reason).toMatch(/block-exfil/);
      expect(result.reason).toMatch(/read.*network/);
    });

    it('should allow read → none transitions', async () => {
      const sessionId = 'exfil-test-2';

      // Setup
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('file-reader', { path: '/data.txt' }), ctx(sessionId));

      // file-reader (read) → calculator (none) should be allowed
      const result = await layer.validate(createToolCallMessage('calculator', { expr: '1+1' }), ctx(sessionId));
      expect(result.passed).toBe(true);
    });

    it('should allow none → network transitions', async () => {
      const sessionId = 'exfil-test-3';

      // Setup
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('calculator', { expr: '1+1' }), ctx(sessionId));

      // calculator (none) → http-client (network) should be allowed
      const result = await layer.validate(createToolCallMessage('http-client', { url: 'http://api.com' }), ctx(sessionId));
      expect(result.passed).toBe(true);
    });
  });

  describe('Tool-based chaining rules', () => {
    let layer;
    // Context with policy permissions for network tools
    const ctx = (sessionId) => ({ sessionId, policy: { allowNetwork: true } });

    beforeEach(() => {
      layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'file-reader', sideEffects: 'read' },
          { name: 'config-reader', sideEffects: 'read' },
          { name: 'http-client', sideEffects: 'network' },
          { name: 'api-http-fetch', sideEffects: 'network' }
        ],
        chainingRules: [
          // Block specific tool chains
          {
            id: 'block-file-to-http',
            from: 'tools/call',
            to: 'tools/call',
            fromTool: 'file-*',
            toTool: '*-http*',
            action: 'deny'
          },
          // Allow standard flow
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' },
          { from: 'tools/call', to: 'tools/call' }
        ]
      });
    });

    it('should block file-* → *-http* transitions', async () => {
      const sessionId = 'tool-chain-1';

      // Setup
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('file-reader', {}), ctx(sessionId));

      // file-reader → api-http-fetch should be blocked (matches *-http* pattern)
      const result = await layer.validate(createToolCallMessage('api-http-fetch', {}), ctx(sessionId));
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/block-file-to-http/);
    });

    it('should block file-reader → api-http-fetch', async () => {
      const sessionId = 'tool-chain-2';

      // Setup
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('file-reader', {}), ctx(sessionId));

      // file-reader → api-http-fetch should also be blocked (glob match)
      const result = await layer.validate(createToolCallMessage('api-http-fetch', {}), ctx(sessionId));
      expect(result.passed).toBe(false);
    });

    it('should allow config-reader → config-reader', async () => {
      const sessionId = 'tool-chain-3';

      // Setup
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('config-reader', {}), ctx(sessionId));

      // config-reader → config-reader should be allowed (not file-*)
      const result = await layer.validate(createToolCallMessage('config-reader', {}), ctx(sessionId));
      expect(result.passed).toBe(true);
    });
  });

  describe('chainingDefaultAction', () => {
    it('should deny by default when no rule matches', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [{ name: 'test-tool', sideEffects: 'none' }],
        chainingRules: [
          { from: '*', to: 'initialize' }
          // No rule for initialize → tools/list
        ]
      });

      const sessionId = 'default-deny-test';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });

      // tools/list has no matching rule, should be denied (default: deny)
      const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });
      expect(result.passed).toBe(false);
    });

    it('should allow when chainingDefaultAction is allow', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        chainingDefaultAction: 'allow',
        toolRegistry: [{ name: 'test-tool', sideEffects: 'none' }],
        chainingRules: [
          { from: '*', to: 'initialize' }
          // No rule for initialize → tools/list
        ]
      });

      const sessionId = 'default-allow-test';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, { sessionId });

      // tools/list has no matching rule, should be allowed (chainingDefaultAction: allow)
      const result = await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, { sessionId });
      expect(result.passed).toBe(true);
    });
  });

  describe('First-match-wins evaluation', () => {
    // Context with policy permissions for write tools
    const ctx = (sessionId) => ({ sessionId, policy: { allowWrites: true } });

    it('should use first matching rule (deny before allow)', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'dangerous-tool', sideEffects: 'write' },
          { name: 'safe-tool', sideEffects: 'none' }
        ],
        chainingRules: [
          // Deny rule first
          {
            id: 'deny-dangerous',
            from: 'tools/call',
            to: 'tools/call',
            toTool: 'dangerous-*',
            action: 'deny'
          },
          // Allow rule second (would match if deny didn't)
          { from: 'tools/call', to: 'tools/call', action: 'allow' },
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' }
        ]
      });

      const sessionId = 'first-match-test';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('safe-tool', {}), ctx(sessionId));

      // safe-tool → dangerous-tool should be denied (first rule matches)
      const result = await layer.validate(createToolCallMessage('dangerous-tool', {}), ctx(sessionId));
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/deny-dangerous/);
    });

    it('should use first matching rule (allow before deny)', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'special-tool', sideEffects: 'write' },
          { name: 'other-tool', sideEffects: 'none' }
        ],
        chainingRules: [
          // Allow rule first for special case
          {
            id: 'allow-special',
            from: 'tools/call',
            to: 'tools/call',
            toTool: 'special-tool',
            action: 'allow'
          },
          // Deny rule second (would block if allow didn't match)
          {
            id: 'deny-all-writes',
            from: 'tools/call',
            to: 'tools/call',
            toSideEffect: 'write',
            action: 'deny'
          },
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' }
        ]
      });

      const sessionId = 'first-match-test-2';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('other-tool', {}), ctx(sessionId));

      // other-tool → special-tool should be allowed (first rule matches)
      const result = await layer.validate(createToolCallMessage('special-tool', {}), ctx(sessionId));
      expect(result.passed).toBe(true);
    });
  });

  describe('Rule metadata in error messages', () => {
    // Context with policy permissions for network tools
    const ctx = (sessionId) => ({ sessionId, policy: { allowNetwork: true } });

    it('should include rule id in denial message', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'blocked-tool', sideEffects: 'network' },
          { name: 'safe-tool', sideEffects: 'none' }
        ],
        chainingRules: [
          {
            id: 'my-custom-rule-id',
            from: 'tools/call',
            to: 'tools/call',
            toSideEffect: 'network',
            action: 'deny',
            description: 'Block all network tools'
          },
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' },
          { from: 'tools/call', to: 'tools/call' }
        ]
      });

      const sessionId = 'rule-id-test';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      // First call a safe tool to set previous method to tools/call
      await layer.validate(createToolCallMessage('safe-tool', {}), ctx(sessionId));

      // Now blocked-tool should trigger the deny rule (from: tools/call, toSideEffect: network)
      const result = await layer.validate(createToolCallMessage('blocked-tool', {}), ctx(sessionId));
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('my-custom-rule-id');
    });

    it('should include side effect info in denial message', async () => {
      const layer = new SemanticsValidationLayer({
        enforceChaining: true,
        toolRegistry: [
          { name: 'reader', sideEffects: 'read' },
          { name: 'sender', sideEffects: 'network' }
        ],
        chainingRules: [
          {
            id: 'exfil-block',
            from: 'tools/call',
            to: 'tools/call',
            fromSideEffect: 'read',
            toSideEffect: 'network',
            action: 'deny'
          },
          { from: '*', to: 'initialize' },
          { from: 'initialize', to: 'tools/list' },
          { from: 'tools/list', to: 'tools/call' },
          { from: 'tools/call', to: 'tools/call' }
        ]
      });

      const sessionId = 'sideeffect-msg-test';
      await layer.validate({ jsonrpc: '2.0', method: 'initialize', id: 1, params: {} }, ctx(sessionId));
      await layer.validate({ jsonrpc: '2.0', method: 'tools/list', id: 2 }, ctx(sessionId));
      await layer.validate(createToolCallMessage('reader', {}), ctx(sessionId));

      const result = await layer.validate(createToolCallMessage('sender', {}), ctx(sessionId));
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/read.*network/);
    });
  });
});
