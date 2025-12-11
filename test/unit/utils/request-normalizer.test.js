import { describe, it, expect } from 'vitest';
import { normalizeRequest, mapSdkMethod } from '@/security/utils/request-normalizer.js';

describe('Request Normalizer', () => {
  describe('normalizeRequest', () => {
    describe('Case 1: JSON-RPC messages', () => {
      it('should pass through complete JSON-RPC message unchanged', () => {
        const message = {
          jsonrpc: '2.0',
          method: 'tools/call',
          params: { name: 'test' },
          id: 1
        };

        const result = normalizeRequest(message);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('tools/call');
        expect(result.params).toEqual({ name: 'test' });
        expect(result.id).toBe(1);
      });

      it('should handle JSON-RPC message without params', () => {
        const message = {
          jsonrpc: '2.0',
          method: 'ping',
          id: 'abc-123'
        };

        const result = normalizeRequest(message);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('ping');
        expect(result.id).toBe('abc-123');
      });

      it('should handle JSON-RPC notification (no id)', () => {
        const message = {
          jsonrpc: '2.0',
          method: 'notifications/cancelled',
          params: { requestId: 'x' }
        };

        const result = normalizeRequest(message);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('notifications/cancelled');
      });
    });

    describe('Case 2: SDK request objects', () => {
      it('should normalize SDK request with method and params', () => {
        const request = {
          method: 'tools/call',
          params: { name: 'calculator', arguments: { a: 1 } }
        };

        const result = normalizeRequest(request);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('tools/call');
        expect(result.params).toEqual({ name: 'calculator', arguments: { a: 1 } });
        expect(typeof result.id).toBe('string');
        expect(result.id.length).toBeGreaterThan(0);
      });

      it('should preserve existing id from SDK request', () => {
        const request = {
          method: 'resources/read',
          params: { uri: 'file://test.txt' },
          id: 'custom-id-123'
        };

        const result = normalizeRequest(request);

        expect(result.id).toBe('custom-id-123');
      });

      it('should generate id when missing from SDK request', () => {
        const request = {
          method: 'tools/list',
          params: {}
        };

        const result = normalizeRequest(request);

        expect(typeof result.id).toBe('string');
        expect(result.id.length).toBeGreaterThan(0);
      });
    });

    describe('Case 3: HTTP request body', () => {
      it('should extract JSON-RPC message from HTTP body', () => {
        const httpRequest = {
          body: {
            jsonrpc: '2.0',
            method: 'prompts/get',
            params: { name: 'greeting' },
            id: 42
          },
          headers: { 'content-type': 'application/json' }
        };

        const result = normalizeRequest(httpRequest);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('prompts/get');
        expect(result.params).toEqual({ name: 'greeting' });
        expect(result.id).toBe(42);
      });

      it('should handle HTTP request with nested body object', () => {
        const httpRequest = {
          body: {
            jsonrpc: '2.0',
            method: 'tools/call',
            params: {
              name: 'test-tool',
              arguments: { nested: { value: 'deep' } }
            },
            id: 'http-1'
          }
        };

        const result = normalizeRequest(httpRequest);

        expect(result.method).toBe('tools/call');
        expect(result.params.arguments.nested.value).toBe('deep');
      });
    });

    describe('Case 4: Raw object fallback', () => {
      it('should convert raw object to JSON-RPC format', () => {
        const rawObject = {
          someField: 'value',
          anotherField: 123
        };

        const result = normalizeRequest(rawObject);

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('unknown');
        expect(result.params).toEqual(rawObject);
        expect(typeof result.id).toBe('string');
        expect(result.id.length).toBeGreaterThan(0);
      });

      it('should use provided method in raw object', () => {
        const rawObject = {
          method: 'custom/method',
          data: 'test'
        };

        const result = normalizeRequest(rawObject);

        expect(result.method).toBe('custom/method');
      });

      it('should use provided params in raw object', () => {
        const rawObject = {
          method: 'test',
          params: { specific: 'params' },
          extra: 'ignored'
        };

        const result = normalizeRequest(rawObject);

        expect(result.params).toEqual({ specific: 'params' });
      });

      it('should handle empty object', () => {
        const result = normalizeRequest({});

        expect(result.jsonrpc).toBe('2.0');
        expect(result.method).toBe('unknown');
        expect(typeof result.id).toBe('string');
        expect(result.id.length).toBeGreaterThan(0);
      });
    });

    describe('Edge cases', () => {
      it('should handle request with null body', () => {
        const request = {
          body: null,
          method: 'test',
          params: {}
        };

        const result = normalizeRequest(request);

        // Should fall through to Case 2 (SDK request)
        expect(result.method).toBe('test');
      });

      it('should handle request with non-object body', () => {
        const request = {
          body: 'string-body',
          method: 'test',
          params: { a: 1 }
        };

        const result = normalizeRequest(request);

        // Should fall through to Case 2 (SDK request)
        expect(result.method).toBe('test');
        expect(result.params).toEqual({ a: 1 });
      });

      it('should handle numeric id values', () => {
        const message = {
          jsonrpc: '2.0',
          method: 'test',
          id: 0
        };

        const result = normalizeRequest(message);

        expect(result.id).toBe(0);
      });

      it('should handle string id values', () => {
        const message = {
          jsonrpc: '2.0',
          method: 'test',
          id: 'uuid-style-id'
        };

        const result = normalizeRequest(message);

        expect(result.id).toBe('uuid-style-id');
      });
    });
  });

  describe('mapSdkMethod', () => {
    it('should map known SDK methods', () => {
      expect(mapSdkMethod('tools/call')).toBe('tools/call');
      expect(mapSdkMethod('tools/list')).toBe('tools/list');
      expect(mapSdkMethod('resources/read')).toBe('resources/read');
      expect(mapSdkMethod('resources/list')).toBe('resources/list');
      expect(mapSdkMethod('prompts/get')).toBe('prompts/get');
      expect(mapSdkMethod('prompts/list')).toBe('prompts/list');
      expect(mapSdkMethod('initialize')).toBe('initialize');
      expect(mapSdkMethod('ping')).toBe('ping');
    });

    it('should pass through unknown methods unchanged', () => {
      expect(mapSdkMethod('custom/method')).toBe('custom/method');
      expect(mapSdkMethod('unknown')).toBe('unknown');
      expect(mapSdkMethod('')).toBe('');
    });

    it('should handle case-sensitive method names', () => {
      // SDK methods are case-sensitive
      expect(mapSdkMethod('Tools/Call')).toBe('Tools/Call');
      expect(mapSdkMethod('TOOLS/CALL')).toBe('TOOLS/CALL');
    });
  });
});
