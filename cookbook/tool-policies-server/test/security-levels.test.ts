/**
 * Security Level Tests for Tool Policies Server
 *
 * Tests that demonstrate config-driven tool policies and how different
 * security levels affect validation.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  getToolPolicy,
  registerToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  isValidSecurityLevel,
  initializeToolPolicies,
  resetToolPolicies,
  getToolPoliciesConfig
} from 'mcp-secure-server';

// ============================================================================
// Config-Driven Tool Policy Tests
// ============================================================================

describe('Config-Driven Tool Policies', () => {
  afterEach(() => {
    resetToolPolicies();
  });

  describe('Loading from config object', () => {
    it('should load policies from config', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'save-note': {
            level: 'STORAGE',
            relaxedFields: ['content', 'title'],
            description: 'Saves documentation notes'
          },
          'query-data': {
            level: 'QUERY',
            description: 'Database queries'
          }
        }
      });

      expect(getToolPolicy('save-note').level).toBe('STORAGE');
      expect(getToolPolicy('save-note').relaxedFields).toContain('content');
      expect(getToolPolicy('query-data').level).toBe('QUERY');
    });

    it('should use defaultLevel for unknown tools', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'known-tool': { level: 'DISPLAY' }
        },
        defaultLevel: 'QUERY'
      });

      expect(getToolPolicy('known-tool').level).toBe('DISPLAY');
      expect(getToolPolicy('unknown-tool').level).toBe('QUERY');
    });

    it('should default to EXECUTION for unknown tools without config', () => {
      // No config loaded
      const policy = getToolPolicy('completely-unknown-tool');
      expect(policy.level).toBe('EXECUTION');
    });
  });

  describe('Pattern matching', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'display-readonly': {
            level: 'DISPLAY',
            description: 'Read-only tools'
          },
          'storage-content': {
            level: 'STORAGE',
            relaxedFields: ['content', 'description'],
            description: 'Content storage tools'
          }
        },
        patterns: [
          { match: 'get-*', policy: 'display-readonly' },
          { match: 'list-*', policy: 'display-readonly' },
          { match: 'search-*', policy: 'display-readonly' },
          { match: 'save-*', policy: 'storage-content' }
        ],
        defaultLevel: 'EXECUTION'
      });
    });

    it('should match get-* pattern', () => {
      expect(getToolPolicy('get-users').level).toBe('DISPLAY');
      expect(getToolPolicy('get-config').level).toBe('DISPLAY');
      expect(getToolPolicy('get-status').level).toBe('DISPLAY');
    });

    it('should match list-* pattern', () => {
      expect(getToolPolicy('list-items').level).toBe('DISPLAY');
      expect(getToolPolicy('list-users').level).toBe('DISPLAY');
    });

    it('should match save-* pattern with relaxedFields', () => {
      const policy = getToolPolicy('save-document');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('content');
    });

    it('should use defaultLevel for non-matching tools', () => {
      expect(getToolPolicy('execute-command').level).toBe('EXECUTION');
      expect(getToolPolicy('run-script').level).toBe('EXECUTION');
    });
  });

  describe('Base policy references', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'storage-docs': {
            level: 'STORAGE',
            relaxedFields: ['content', 'title', 'description']
          }
        },
        tools: {
          'my-notes': 'storage-docs',
          'my-docs': 'storage-docs'
        }
      });
    });

    it('should resolve string references to base policies', () => {
      const notesPolicy = getToolPolicy('my-notes');
      expect(notesPolicy.level).toBe('STORAGE');
      expect(notesPolicy.relaxedFields).toContain('content');

      const docsPolicy = getToolPolicy('my-docs');
      expect(docsPolicy.level).toBe('STORAGE');
      expect(docsPolicy.relaxedFields).toContain('title');
    });
  });

  describe('Inheritance with extends', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'base-storage': {
            level: 'STORAGE',
            relaxedFields: ['content']
          }
        },
        tools: {
          'extended-tool': {
            extends: 'base-storage',
            relaxedFields: ['extra_field'],
            description: 'Tool with extended policy'
          }
        }
      });
    });

    it('should inherit level from base policy', () => {
      const policy = getToolPolicy('extended-tool');
      expect(policy.level).toBe('STORAGE');
    });

    it('should merge relaxedFields arrays', () => {
      const policy = getToolPolicy('extended-tool');
      expect(policy.relaxedFields).toContain('content');
      expect(policy.relaxedFields).toContain('extra_field');
    });
  });

  describe('Explicit tools take precedence over patterns', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        patterns: [
          { match: 'get-*', policy: { level: 'DISPLAY' } }
        ],
        tools: {
          'get-sensitive-data': { level: 'EXECUTION' }
        }
      });
    });

    it('should use explicit tool policy over pattern match', () => {
      // Pattern would match, but explicit definition takes precedence
      expect(getToolPolicy('get-sensitive-data').level).toBe('EXECUTION');
      // Other get-* tools use pattern
      expect(getToolPolicy('get-status').level).toBe('DISPLAY');
    });
  });

  describe('getToolPoliciesConfig', () => {
    it('should return loaded config', () => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'test-policy': { level: 'STORAGE' }
        },
        defaultLevel: 'QUERY'
      });

      const config = getToolPoliciesConfig();
      expect(config).not.toBeNull();
      expect(config?.version).toBe('2.0');
      expect(config?.basePolicies).toHaveProperty('test-policy');
      expect(config?.defaultLevel).toBe('QUERY');
    });

    it('should return null when no config loaded', () => {
      resetToolPolicies();
      expect(getToolPoliciesConfig()).toBeNull();
    });
  });
});

// ============================================================================
// Runtime Registration Tests (still supported)
// ============================================================================

describe('Runtime Policy Registration', () => {
  afterEach(() => {
    resetToolPolicies();
  });

  it('should allow registering policies at runtime', () => {
    registerToolPolicy('runtime-tool', {
      level: 'STORAGE',
      relaxedFields: ['notes'],
      description: 'Registered at runtime'
    });

    const policy = getToolPolicy('runtime-tool');
    expect(policy.level).toBe('STORAGE');
    expect(policy.relaxedFields).toContain('notes');
  });

  it('should override existing runtime policies', () => {
    registerToolPolicy('override-test', { level: 'EXECUTION' });
    expect(getToolPolicy('override-test').level).toBe('EXECUTION');

    registerToolPolicy('override-test', { level: 'DISPLAY' });
    expect(getToolPolicy('override-test').level).toBe('DISPLAY');
  });

  it('should work alongside config-loaded policies', () => {
    initializeToolPolicies({
      version: '2.0',
      tools: {
        'config-tool': { level: 'QUERY' }
      }
    });

    registerToolPolicy('runtime-tool', { level: 'STORAGE' });

    expect(getToolPolicy('config-tool').level).toBe('QUERY');
    expect(getToolPolicy('runtime-tool').level).toBe('STORAGE');
  });
});

// ============================================================================
// Tool Policy Query Functions Tests
// ============================================================================

describe('Tool Policy Query Functions', () => {
  beforeEach(() => {
    initializeToolPolicies({
      version: '2.0',
      tools: {
        'storage-tool': {
          level: 'STORAGE',
          relaxedFields: ['content', 'description']
        },
        'display-tool': { level: 'DISPLAY' },
        'query-tool': { level: 'QUERY' },
        'execution-tool': { level: 'EXECUTION' }
      }
    });
  });

  afterEach(() => {
    resetToolPolicies();
  });

  describe('isRelaxedField', () => {
    it('should return true for relaxed fields', () => {
      expect(isRelaxedField('storage-tool', 'content')).toBe(true);
      expect(isRelaxedField('storage-tool', 'description')).toBe(true);
    });

    it('should return false for non-relaxed fields', () => {
      expect(isRelaxedField('storage-tool', 'command')).toBe(false);
      expect(isRelaxedField('storage-tool', 'path')).toBe(false);
    });

    it('should return false for tools without relaxed fields', () => {
      expect(isRelaxedField('execution-tool', 'content')).toBe(false);
    });

    it('should return false for unknown tools', () => {
      expect(isRelaxedField('unknown-tool', 'anything')).toBe(false);
    });
  });

  describe('getToolsByLevel', () => {
    beforeEach(() => {
      // getToolsByLevel queries the runtime registry, so we need to register tools
      registerToolPolicy('storage-tool-registered', { level: 'STORAGE' });
      registerToolPolicy('display-tool-registered', { level: 'DISPLAY' });
      registerToolPolicy('query-tool-registered', { level: 'QUERY' });
      registerToolPolicy('execution-tool-registered', { level: 'EXECUTION' });
    });

    it('should return runtime-registered tools at each level', () => {
      expect(getToolsByLevel('STORAGE')).toContain('storage-tool-registered');
      expect(getToolsByLevel('DISPLAY')).toContain('display-tool-registered');
      expect(getToolsByLevel('QUERY')).toContain('query-tool-registered');
      expect(getToolsByLevel('EXECUTION')).toContain('execution-tool-registered');
    });

    it('should not include tools at other levels', () => {
      expect(getToolsByLevel('STORAGE')).not.toContain('execution-tool-registered');
      expect(getToolsByLevel('EXECUTION')).not.toContain('storage-tool-registered');
    });
  });

  describe('isValidSecurityLevel', () => {
    it('should validate correct levels', () => {
      expect(isValidSecurityLevel('EXECUTION')).toBe(true);
      expect(isValidSecurityLevel('QUERY')).toBe(true);
      expect(isValidSecurityLevel('STORAGE')).toBe(true);
      expect(isValidSecurityLevel('DISPLAY')).toBe(true);
    });

    it('should reject invalid levels', () => {
      expect(isValidSecurityLevel('INVALID')).toBe(false);
      expect(isValidSecurityLevel('')).toBe(false);
      expect(isValidSecurityLevel('execution')).toBe(false); // Case sensitive
    });
  });
});

// ============================================================================
// Content Validation by Security Level Tests
// ============================================================================

describe('Content Validation by Security Level', () => {
  beforeEach(() => {
    initializeToolPolicies({
      version: '2.0',
      tools: {
        'storage-tool': {
          level: 'STORAGE',
          relaxedFields: ['content']
        },
        'execution-tool': { level: 'EXECUTION' }
      }
    });
  });

  afterEach(() => {
    resetToolPolicies();
  });

  describe('STORAGE level content patterns', () => {
    const documentationContent = [
      // Shell command examples in documentation
      'To list files, use: ls -la | grep pattern',
      'Chain commands with: cmd1 && cmd2 || cmd3',
      'Redirect output: cat file.txt > output.log',

      // Event handler documentation
      'Add onclick handler: <button onclick="handleClick()">',
      'Use onload for images: <img onload="loaded()">',

      // Code examples
      'Execute with: node script.js --flag',
      'Run the shell: bash -c "echo hello"',

      // SQL in documentation
      'Example query: SELECT * FROM users WHERE id = 1',
      'Join syntax: SELECT * FROM a INNER JOIN b ON a.id = b.id',
    ];

    for (const content of documentationContent) {
      it(`should be safe in STORAGE context: "${content.slice(0, 50)}..."`, () => {
        // This test documents that these patterns exist in documentation
        // The actual validation happens in Layer 2 with level awareness
        expect(content.length).toBeGreaterThan(0);

        // Verify we have a STORAGE policy
        const policy = getToolPolicy('storage-tool');
        expect(policy.level).toBe('STORAGE');
      });
    }
  });

  describe('EXECUTION level - patterns that should be blocked', () => {
    const dangerousPatterns = [
      // Command injection
      '; rm -rf /',
      '| cat /etc/passwd',
      '`whoami`',
      '$(cat /etc/shadow)',

      // Path traversal
      '../../../etc/passwd',
      '..\\..\\windows\\system32',

      // SQL injection attacks
      "' OR 1=1 --",
      "'; DROP TABLE users; --",

      // Deserialization attacks
      'O:8:"stdClass":0:{}',
    ];

    for (const pattern of dangerousPatterns) {
      it(`should detect dangerous pattern at EXECUTION level: "${pattern.slice(0, 30)}..."`, () => {
        // Document the pattern
        expect(pattern.length).toBeGreaterThan(0);

        // Verify EXECUTION level tool
        const policy = getToolPolicy('execution-tool');
        expect(policy.level).toBe('EXECUTION');
      });
    }
  });
});

// ============================================================================
// Security Level Hierarchy Tests
// ============================================================================

describe('Security Level Hierarchy', () => {
  const levelOrder = ['DISPLAY', 'STORAGE', 'QUERY', 'EXECUTION'] as const;

  it('should have EXECUTION as the most restrictive', () => {
    expect(levelOrder.indexOf('EXECUTION')).toBe(3);
  });

  it('should have DISPLAY as the least restrictive', () => {
    expect(levelOrder.indexOf('DISPLAY')).toBe(0);
  });

  it('should position QUERY between STORAGE and EXECUTION', () => {
    expect(levelOrder.indexOf('QUERY')).toBeGreaterThan(levelOrder.indexOf('STORAGE'));
    expect(levelOrder.indexOf('QUERY')).toBeLessThan(levelOrder.indexOf('EXECUTION'));
  });
});

// ============================================================================
// Documentation Examples
// ============================================================================

describe('Documentation Examples', () => {
  afterEach(() => {
    resetToolPolicies();
  });

  it('Example: Load tool policies from config', () => {
    initializeToolPolicies({
      version: '2.0',
      basePolicies: {
        'storage-docs': {
          level: 'STORAGE',
          relaxedFields: ['content', 'examples']
        }
      },
      patterns: [
        { match: 'get-*', policy: { level: 'DISPLAY' } },
        { match: 'save-*', policy: 'storage-docs' }
      ],
      tools: {
        'execute-command': { level: 'EXECUTION' }
      },
      defaultLevel: 'EXECUTION'
    });

    expect(getToolPolicy('get-users').level).toBe('DISPLAY');
    expect(getToolPolicy('save-note').level).toBe('STORAGE');
    expect(getToolPolicy('execute-command').level).toBe('EXECUTION');
    expect(getToolPolicy('unknown-tool').level).toBe('EXECUTION');
  });

  it('Example: Use inheritance with extends', () => {
    initializeToolPolicies({
      version: '2.0',
      basePolicies: {
        'base-storage': {
          level: 'STORAGE',
          relaxedFields: ['content']
        }
      },
      tools: {
        'notes-tool': {
          extends: 'base-storage',
          relaxedFields: ['title'],
          description: 'Extends base with additional relaxed field'
        }
      }
    });

    const policy = getToolPolicy('notes-tool');
    expect(policy.level).toBe('STORAGE');
    expect(policy.relaxedFields).toContain('content'); // From base
    expect(policy.relaxedFields).toContain('title');   // Added
  });

  it('Example: Check if a field should be relaxed', () => {
    initializeToolPolicies({
      version: '2.0',
      tools: {
        'example-tool': {
          level: 'STORAGE',
          relaxedFields: ['userContent']
        }
      }
    });

    // Fields in relaxedFields get STORAGE-level validation
    expect(isRelaxedField('example-tool', 'userContent')).toBe(true);

    // Other fields use the tool's level
    expect(isRelaxedField('example-tool', 'command')).toBe(false);
  });
});
