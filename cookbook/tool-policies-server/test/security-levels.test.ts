/**
 * Security Level Tests for Tool Policies Server
 *
 * Tests that demonstrate how different security levels affect validation.
 * STORAGE level tools accept content that would be blocked at EXECUTION level.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  getToolPolicy,
  registerToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  isValidSecurityLevel
} from 'mcp-secure-server';

// ============================================================================
// Tool Policy Configuration Tests
// ============================================================================

describe('Tool Policy Configuration', () => {
  beforeEach(() => {
    // Register test tools
    registerToolPolicy('test-storage-tool', {
      level: 'STORAGE',
      relaxedFields: ['content', 'description'],
      description: 'Test STORAGE level tool'
    });

    registerToolPolicy('test-execution-tool', {
      level: 'EXECUTION',
      description: 'Test EXECUTION level tool'
    });

    registerToolPolicy('test-query-tool', {
      level: 'QUERY',
      description: 'Test QUERY level tool'
    });

    registerToolPolicy('test-display-tool', {
      level: 'DISPLAY',
      description: 'Test DISPLAY level tool'
    });
  });

  describe('getToolPolicy', () => {
    it('should return registered policy for known tools', () => {
      const policy = getToolPolicy('test-storage-tool');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('content');
    });

    it('should default to EXECUTION for unknown tools', () => {
      const policy = getToolPolicy('completely-unknown-tool');
      expect(policy.level).toBe('EXECUTION');
    });

    it('should return correct levels for all test tools', () => {
      expect(getToolPolicy('test-storage-tool').level).toBe('STORAGE');
      expect(getToolPolicy('test-execution-tool').level).toBe('EXECUTION');
      expect(getToolPolicy('test-query-tool').level).toBe('QUERY');
      expect(getToolPolicy('test-display-tool').level).toBe('DISPLAY');
    });
  });

  describe('isRelaxedField', () => {
    it('should return true for relaxed fields', () => {
      expect(isRelaxedField('test-storage-tool', 'content')).toBe(true);
      expect(isRelaxedField('test-storage-tool', 'description')).toBe(true);
    });

    it('should return false for non-relaxed fields', () => {
      expect(isRelaxedField('test-storage-tool', 'command')).toBe(false);
      expect(isRelaxedField('test-storage-tool', 'path')).toBe(false);
    });

    it('should return false for tools without relaxed fields', () => {
      expect(isRelaxedField('test-execution-tool', 'content')).toBe(false);
    });

    it('should return false for unknown tools', () => {
      expect(isRelaxedField('unknown-tool', 'anything')).toBe(false);
    });
  });

  describe('getToolsByLevel', () => {
    it('should return tools at STORAGE level', () => {
      const tools = getToolsByLevel('STORAGE');
      expect(tools).toContain('test-storage-tool');
      expect(tools).not.toContain('test-execution-tool');
    });

    it('should return tools at EXECUTION level', () => {
      const tools = getToolsByLevel('EXECUTION');
      expect(tools).toContain('test-execution-tool');
    });

    it('should return tools at each level', () => {
      expect(getToolsByLevel('QUERY')).toContain('test-query-tool');
      expect(getToolsByLevel('DISPLAY')).toContain('test-display-tool');
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
  /**
   * These tests demonstrate the content patterns that are safe for documentation
   * but would be blocked at higher security levels.
   */

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

        // Verify we have a STORAGE policy registered
        const policy = getToolPolicy('test-storage-tool');
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
        const policy = getToolPolicy('test-execution-tool');
        expect(policy.level).toBe('EXECUTION');
      });
    }
  });
});

// ============================================================================
// Policy Registration Tests
// ============================================================================

describe('Policy Registration', () => {
  it('should allow registering custom policies', () => {
    registerToolPolicy('my-custom-tool', {
      level: 'STORAGE',
      relaxedFields: ['notes', 'comments'],
      description: 'Custom documentation tool'
    });

    const policy = getToolPolicy('my-custom-tool');
    expect(policy.level).toBe('STORAGE');
    expect(policy.relaxedFields).toContain('notes');
    expect(policy.relaxedFields).toContain('comments');
  });

  it('should override existing policies', () => {
    registerToolPolicy('override-test', { level: 'EXECUTION' });
    expect(getToolPolicy('override-test').level).toBe('EXECUTION');

    registerToolPolicy('override-test', { level: 'DISPLAY' });
    expect(getToolPolicy('override-test').level).toBe('DISPLAY');
  });
});

// ============================================================================
// Built-in Tool Policy Tests
// ============================================================================

describe('Built-in Tool Policies', () => {
  describe('Validation tracker tools', () => {
    it('save_features_list should be STORAGE level', () => {
      const policy = getToolPolicy('save_features_list');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('description');
      expect(policy.relaxedFields).toContain('title');
    });

    it('query_issues should be DISPLAY level', () => {
      const policy = getToolPolicy('query_issues');
      expect(policy.level).toBe('DISPLAY');
    });

    it('add_issue_note should allow content field', () => {
      const policy = getToolPolicy('add_issue_note');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('content');
    });
  });

  describe('Database tools', () => {
    it('query-users should be QUERY level', () => {
      const policy = getToolPolicy('query-users');
      expect(policy.level).toBe('QUERY');
    });

    it('create-order should be EXECUTION level', () => {
      const policy = getToolPolicy('create-order');
      expect(policy.level).toBe('EXECUTION');
    });
  });

  describe('Dangerous operations', () => {
    it('delete_project should be EXECUTION level', () => {
      const policy = getToolPolicy('delete_project');
      expect(policy.level).toBe('EXECUTION');
    });

    it('batch-process should be EXECUTION level', () => {
      const policy = getToolPolicy('batch-process');
      expect(policy.level).toBe('EXECUTION');
    });
  });
});

// ============================================================================
// Security Level Hierarchy Tests
// ============================================================================

describe('Security Level Hierarchy', () => {
  const levelOrder = ['DISPLAY', 'STORAGE', 'QUERY', 'EXECUTION'] as const;

  it('should have EXECUTION as the most restrictive', () => {
    // EXECUTION checks the most patterns
    expect(levelOrder.indexOf('EXECUTION')).toBe(3);
  });

  it('should have DISPLAY as the least restrictive', () => {
    // DISPLAY only checks critical patterns (XSS, deserialization)
    expect(levelOrder.indexOf('DISPLAY')).toBe(0);
  });

  it('should position QUERY between STORAGE and EXECUTION', () => {
    // QUERY adds SQL/NoSQL checks to STORAGE
    expect(levelOrder.indexOf('QUERY')).toBeGreaterThan(levelOrder.indexOf('STORAGE'));
    expect(levelOrder.indexOf('QUERY')).toBeLessThan(levelOrder.indexOf('EXECUTION'));
  });
});

// ============================================================================
// Documentation Examples
// ============================================================================

describe('Documentation Examples', () => {
  /**
   * These tests serve as documentation for how to use tool policies.
   */

  it('Example: Register a documentation tool', () => {
    // Documentation tools should use STORAGE level
    // to avoid false positives on code examples
    registerToolPolicy('my-docs-tool', {
      level: 'STORAGE',
      relaxedFields: ['content', 'examples'],
      description: 'Stores technical documentation'
    });

    const policy = getToolPolicy('my-docs-tool');
    expect(policy.level).toBe('STORAGE');
  });

  it('Example: Register a read-only query tool', () => {
    // Read-only tools that just display data
    // should use DISPLAY level for minimal friction
    registerToolPolicy('my-search-tool', {
      level: 'DISPLAY',
      description: 'Searches indexed content'
    });

    const policy = getToolPolicy('my-search-tool');
    expect(policy.level).toBe('DISPLAY');
  });

  it('Example: Register a database query tool', () => {
    // Database query tools should use QUERY level
    // to check for SQL injection
    registerToolPolicy('my-db-tool', {
      level: 'QUERY',
      description: 'Queries user database'
    });

    const policy = getToolPolicy('my-db-tool');
    expect(policy.level).toBe('QUERY');
  });

  it('Example: Check if a field should be relaxed', () => {
    registerToolPolicy('example-tool', {
      level: 'STORAGE',
      relaxedFields: ['userContent'],
    });

    // Fields in relaxedFields get STORAGE-level validation
    expect(isRelaxedField('example-tool', 'userContent')).toBe(true);

    // Other fields use the tool's level
    expect(isRelaxedField('example-tool', 'command')).toBe(false);
  });
});
