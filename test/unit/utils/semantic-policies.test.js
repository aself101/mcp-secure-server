import { describe, it, expect } from 'vitest';
import {
  validateToolCall,
  validateResourceAccess,
  isUnderAllowedRoots,
  matchesDenyGlobs,
  getDefaultPolicies,
  normalizePolicies
} from '@/security/layers/layer-utils/semantics/semantic-policies.js';

describe('Semantic Policies', () => {
  describe('validateToolCall', () => {
    const basicTool = {
      name: 'calculator',
      description: 'Basic calculator'
    };

    it('should pass valid tool call with correct arguments', () => {
      const result = validateToolCall(
        basicTool,
        { operation: 'add', numbers: [1, 2, 3] },
        'tools/call'
      );

      expect(result.passed).toBe(true);
    });

    it('should pass with null params when no args required', () => {
      const noArgsTool = {
        name: 'ping',
        description: 'Simple ping'
      };

      const result = validateToolCall(noArgsTool, null, 'tools/call');

      expect(result.passed).toBe(true);
    });

    it('should pass with undefined params when no args required', () => {
      const noArgsTool = {
        name: 'status',
        description: 'Get status'
      };

      const result = validateToolCall(noArgsTool, undefined, 'tools/call');

      expect(result.passed).toBe(true);
    });

    it('should handle tool with quotas', () => {
      const toolWithQuotas = {
        name: 'expensive-tool',
        description: 'Resource-intensive tool',
        maxCallsPerMinute: 5,
        maxCallsPerHour: 20
      };

      const result = validateToolCall(toolWithQuotas, {}, 'tools/call');

      expect(result.passed).toBe(true);
    });

    it('should handle tool with side effects declaration', () => {
      const toolWithSideEffects = {
        name: 'file-writer',
        description: 'Writes files',
        sideEffects: ['write', 'network']
      };

      const result = validateToolCall(toolWithSideEffects, {}, 'tools/call');

      expect(result.passed).toBe(true);
    });
  });

  describe('validateResourceAccess', () => {
    // Full policy with all required fields - use regex for reliable deny patterns
    const defaultPolicy = {
      rootDirs: ['/home/user/projects'],
      denyGlobs: [/\.env$/, /secret/i],
      allowedSchemes: ['file', 'https'],
      maxUriLength: 2000
    };

    it('should allow access to files under allowed roots', () => {
      const result = validateResourceAccess(
        'file:///home/user/projects/test.txt',
        defaultPolicy
      );

      expect(result.passed).toBe(true);
    });

    it('should deny access to files outside allowed roots', () => {
      const result = validateResourceAccess(
        'file:///etc/passwd',
        defaultPolicy
      );

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('RESOURCE_POLICY_VIOLATION');
    });

    it('should deny access to files matching deny globs', () => {
      const result = validateResourceAccess(
        'file:///home/user/projects/.env',
        defaultPolicy
      );

      expect(result.passed).toBe(false);
    });

    it('should handle URLs with different schemes', () => {
      const result = validateResourceAccess(
        'https://example.com/api/data',
        defaultPolicy
      );

      // HTTPS is in allowedSchemes, should pass scheme check
      expect(result.passed).toBe(true);
    });

    it('should deny disallowed schemes', () => {
      const result = validateResourceAccess(
        'ftp://example.com/file.txt',
        defaultPolicy
      );

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('Scheme');
    });

    it('should handle empty root dirs (deny by default)', () => {
      const strictPolicy = {
        rootDirs: [],
        denyGlobs: [],
        allowedSchemes: ['file'],
        maxUriLength: 2000
      };

      const result = validateResourceAccess(
        'file:///any/path/file.txt',
        strictPolicy
      );

      // With empty rootDirs, files are denied (strict security)
      expect(result.passed).toBe(false);
    });
  });

  describe('isUnderAllowedRoots', () => {
    it('should return true for path under allowed root', () => {
      const result = isUnderAllowedRoots(
        '/home/user/projects/file.txt',
        ['/home/user/projects']
      );

      expect(result).toBe(true);
    });

    it('should return false for path outside allowed roots', () => {
      const result = isUnderAllowedRoots(
        '/etc/passwd',
        ['/home/user/projects']
      );

      expect(result).toBe(false);
    });

    it('should handle multiple allowed roots', () => {
      const roots = ['/home/user/projects', '/var/data', '/tmp'];

      expect(isUnderAllowedRoots('/home/user/projects/test.txt', roots)).toBe(true);
      expect(isUnderAllowedRoots('/var/data/file.json', roots)).toBe(true);
      expect(isUnderAllowedRoots('/tmp/cache.txt', roots)).toBe(true);
      expect(isUnderAllowedRoots('/etc/config', roots)).toBe(false);
    });

    it('should handle empty roots array (deny all)', () => {
      // With empty roots, no path is under allowed roots (strict security)
      const result = isUnderAllowedRoots('/any/path', []);

      expect(result).toBe(false);
    });

    it('should handle path traversal attempts', () => {
      const result = isUnderAllowedRoots(
        '/home/user/projects/../../../etc/passwd',
        ['/home/user/projects']
      );

      // After normalization, should be outside allowed roots
      expect(result).toBe(false);
    });
  });

  describe('matchesDenyGlobs', () => {
    it('should handle regex patterns for secret files', () => {
      const globs = [/secret/i, /password/i];

      expect(matchesDenyGlobs('/path/to/SECRET_FILE', globs)).toBe(true);
      expect(matchesDenyGlobs('/path/to/passwords.txt', globs)).toBe(true);
      expect(matchesDenyGlobs('/path/to/normal.txt', globs)).toBe(false);
    });

    it('should return false for empty globs array', () => {
      const result = matchesDenyGlobs('/any/path', []);

      expect(result).toBe(false);
    });

    it('should handle regex patterns for env files', () => {
      const globs = [/\.env$/, /credential/i];

      expect(matchesDenyGlobs('/path/.env', globs)).toBe(true);
      expect(matchesDenyGlobs('/path/credentials.json', globs)).toBe(true);
      expect(matchesDenyGlobs('/path/config.json', globs)).toBe(false);
    });
  });

  describe('getDefaultPolicies', () => {
    it('should return default policies object', () => {
      const policies = getDefaultPolicies();

      expect(policies).not.toBeNull();
      expect(typeof policies).toBe('object');
    });

    it('should include resource policy', () => {
      const policies = getDefaultPolicies();

      expect(policies.resourcePolicy).not.toBeNull();
      expect(typeof policies.resourcePolicy).toBe('object');
    });

    it('should include method spec', () => {
      const policies = getDefaultPolicies();

      expect(policies.methodSpec).not.toBeNull();
      expect(typeof policies.methodSpec).toBe('object');
    });
  });

  describe('normalizePolicies', () => {
    it('should normalize partial policy input', () => {
      const result = normalizePolicies({
        resourcePolicy: { rootDirs: ['/test'] }
      });

      expect(result).not.toBeNull();
      expect(result.resourcePolicy).not.toBeNull();
    });

    it('should handle empty resource policy', () => {
      const result = normalizePolicies({
        resourcePolicy: {}
      });

      expect(result).not.toBeNull();
      expect(result.resourcePolicy).not.toBeNull();
    });

    it('should preserve provided values', () => {
      const customRoots = ['/custom/path'];
      const result = normalizePolicies({
        resourcePolicy: { rootDirs: customRoots }
      });

      expect(result.resourcePolicy?.rootDirs).toContain('/custom/path');
    });
  });

  describe('Edge cases for coverage', () => {
    // Full policy for edge case tests
    const fullPolicy = {
      rootDirs: ['/'],
      denyGlobs: [],
      allowedSchemes: ['file'],
      maxUriLength: 2000
    };

    it('should handle file:// URI parsing edge cases', () => {
      // Test various file URI formats
      const uris = [
        'file:///absolute/path',
        'file://localhost/path',
        'file:/path/without/triple-slash'
      ];

      for (const uri of uris) {
        const result = validateResourceAccess(uri, fullPolicy);
        // All should pass - under root '/' and no deny globs
        expect(result.passed).toBe(true);
      }
    });

    it('should handle tool without args definition', () => {
      // Tools without explicit args should accept any params
      const simpleTool = {
        name: 'simple-tool',
        description: 'A simple tool'
      };

      const validResult = validateToolCall(
        simpleTool,
        {
          str: 'hello',
          num: 42,
          bool: true,
          arr: [1, 2, 3],
          obj: { key: 'value' }
        },
        'tools/call'
      );
      expect(validResult.passed).toBe(true);
    });

    it('should handle serialization errors gracefully', () => {
      const tool = {
        name: 'test-tool',
        argsShape: { value: { type: 'object', optional: true } },
        maxArgsSize: 100
      };

      // Create circular reference that can't be serialized
      const circular = { a: 1 };
      circular.self = circular;

      // Should handle gracefully without throwing
      const result = validateToolCall(tool, { arguments: circular }, 'tools/call');
      expect(result.passed).toBe(false);
      expect(result.reason).toContain('serialization');
    });
  });

  describe('typeMatches coverage via argsShape validation', () => {
    it('should validate string type arguments', () => {
      const tool = {
        name: 'typed-tool',
        argsShape: {
          message: { type: 'string' }
        }
      };

      // params.arguments is where args are extracted from
      const validResult = validateToolCall(tool, { arguments: { message: 'hello' } }, 'tools/call');
      expect(validResult.passed).toBe(true);

      const invalidResult = validateToolCall(tool, { arguments: { message: 123 } }, 'tools/call');
      expect(invalidResult.passed).toBe(false);
      expect(invalidResult.reason).toContain('type');
    });

    it('should validate number type arguments', () => {
      const tool = {
        name: 'numeric-tool',
        argsShape: {
          count: { type: 'number' }
        }
      };

      const validResult = validateToolCall(tool, { arguments: { count: 42 } }, 'tools/call');
      expect(validResult.passed).toBe(true);

      const invalidResult = validateToolCall(tool, { arguments: { count: 'forty-two' } }, 'tools/call');
      expect(invalidResult.passed).toBe(false);
    });

    it('should validate boolean type arguments', () => {
      const tool = {
        name: 'flag-tool',
        argsShape: {
          enabled: { type: 'boolean' }
        }
      };

      const validResult = validateToolCall(tool, { arguments: { enabled: true } }, 'tools/call');
      expect(validResult.passed).toBe(true);

      const invalidResult = validateToolCall(tool, { arguments: { enabled: 'yes' } }, 'tools/call');
      expect(invalidResult.passed).toBe(false);
    });

    it('should validate array type arguments', () => {
      const tool = {
        name: 'list-tool',
        argsShape: {
          items: { type: 'array' }
        }
      };

      const validResult = validateToolCall(tool, { arguments: { items: [1, 2, 3] } }, 'tools/call');
      expect(validResult.passed).toBe(true);

      const invalidResult = validateToolCall(tool, { arguments: { items: { not: 'array' } } }, 'tools/call');
      expect(invalidResult.passed).toBe(false);
    });

    it('should validate object type arguments', () => {
      const tool = {
        name: 'config-tool',
        argsShape: {
          settings: { type: 'object' }
        }
      };

      const validResult = validateToolCall(tool, { arguments: { settings: { key: 'value' } } }, 'tools/call');
      expect(validResult.passed).toBe(true);

      // Arrays are not objects for this validation
      const invalidResult = validateToolCall(tool, { arguments: { settings: [1, 2, 3] } }, 'tools/call');
      expect(invalidResult.passed).toBe(false);
    });
  });

  describe('hostEquals coverage via allowedHosts validation', () => {
    it('should allow access to hosts in allowedHosts list', () => {
      const policyWithHosts = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['https'],
        allowedHosts: ['example.com', 'api.example.com'],
        maxUriLength: 2000
      };

      const validResult = validateResourceAccess('https://example.com/api', policyWithHosts);
      expect(validResult.passed).toBe(true);

      const validApiResult = validateResourceAccess('https://api.example.com/data', policyWithHosts);
      expect(validApiResult.passed).toBe(true);
    });

    it('should deny access to hosts not in allowedHosts list', () => {
      const policyWithHosts = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['https'],
        allowedHosts: ['example.com'],
        maxUriLength: 2000
      };

      const invalidResult = validateResourceAccess('https://evil.com/api', policyWithHosts);
      expect(invalidResult.passed).toBe(false);
      expect(invalidResult.reason).toContain('Host');
    });

    it('should normalize port numbers when comparing hosts', () => {
      const policyWithHosts = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['https'],
        allowedHosts: ['example.com'],
        maxUriLength: 2000
      };

      // Port 443 is default for HTTPS, should match example.com
      const resultWithPort = validateResourceAccess('https://example.com:443/api', policyWithHosts);
      expect(resultWithPort.passed).toBe(true);
    });

    it('should handle case-insensitive host matching', () => {
      const policyWithHosts = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['https'],
        allowedHosts: ['Example.COM'],
        maxUriLength: 2000
      };

      const result = validateResourceAccess('https://example.com/api', policyWithHosts);
      expect(result.passed).toBe(true);
    });
  });

  describe('estimateReadBytes coverage via maxReadBytes validation', () => {
    it('should enforce maxReadBytes limit on resources', () => {
      // estimateReadBytes calculates uri.length * 1024
      // For 'file:///a.txt' (13 chars) = 13312 bytes estimated
      const policyWithReadLimit = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['file'],
        maxUriLength: 5000,
        maxReadBytes: 10000  // 10KB limit - smaller than estimated
      };

      // Short URI 'file:///a.txt' = 13 chars * 1024 = 13312 estimated bytes
      // This exceeds 10000, should fail
      const shortUri = 'file:///a.txt';
      const shortResult = validateResourceAccess(shortUri, policyWithReadLimit);
      expect(shortResult.passed).toBe(false);
      expect(shortResult.reason).toContain('exceeds');

      // With higher limit, should pass
      const policyWithHigherLimit = {
        rootDirs: ['/'],
        denyGlobs: [],
        allowedSchemes: ['file'],
        maxUriLength: 5000,
        maxReadBytes: 100000  // 100KB limit - higher than estimated
      };
      const passResult = validateResourceAccess(shortUri, policyWithHigherLimit);
      expect(passResult.passed).toBe(true);
    });
  });
});
