import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  getToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  registerToolPolicy,
  isValidSecurityLevel,
  defaultToolPolicies
} from '@/security/config/tool-policies.js';
import {
  initializeToolPolicies,
  resetToolPolicies
} from '@/security/config/tool-policies-config.js';
import {
  getCategoriesForLevel,
  shouldCheckCategory,
  getLevelDescription,
  ALWAYS_CHECK_CATEGORIES,
  EXECUTION_ONLY_CATEGORIES
} from '@/security/config/pattern-categories.js';

describe('Tool Policies', () => {
  beforeEach(() => {
    // Clear any loaded config and runtime registrations
    resetToolPolicies();
    Object.keys(defaultToolPolicies).forEach(key => delete defaultToolPolicies[key]);
  });

  afterEach(() => {
    resetToolPolicies();
    Object.keys(defaultToolPolicies).forEach(key => delete defaultToolPolicies[key]);
  });

  describe('getToolPolicy', () => {
    it('should return EXECUTION level for unknown tools (secure default)', () => {
      const policy = getToolPolicy('unknown_dangerous_tool');
      expect(policy.level).toBe('EXECUTION');
    });

    it('should use config-loaded policies when available', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'save_features_list': {
            level: 'STORAGE',
            relaxedFields: ['description', 'title'],
            description: 'Test tool'
          }
        }
      });

      const policy = getToolPolicy('save_features_list');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('description');
      expect(policy.relaxedFields).toContain('title');
    });

    it('should use pattern matching from config', () => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'display-readonly': {
            level: 'DISPLAY',
            description: 'Read-only tools'
          }
        },
        patterns: [
          { match: 'get_*', policy: 'display-readonly' },
          { match: 'list_*', policy: 'display-readonly' }
        ]
      });

      expect(getToolPolicy('get_issues').level).toBe('DISPLAY');
      expect(getToolPolicy('get_project_summary').level).toBe('DISPLAY');
      expect(getToolPolicy('list_validators').level).toBe('DISPLAY');
      // Non-matching tool uses default
      expect(getToolPolicy('create_order').level).toBe('EXECUTION');
    });

    it('should use config defaultLevel for unmatched tools', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'known_tool': { level: 'STORAGE' }
        },
        defaultLevel: 'QUERY'
      });

      expect(getToolPolicy('known_tool').level).toBe('STORAGE');
      expect(getToolPolicy('unknown_tool').level).toBe('QUERY');
    });

    it('should resolve base policy references', () => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'storage-content': {
            level: 'STORAGE',
            relaxedFields: ['content', 'description']
          }
        },
        tools: {
          'my_tool': 'storage-content'
        }
      });

      const policy = getToolPolicy('my_tool');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('content');
    });
  });

  describe('isRelaxedField', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'save_features_list': {
            level: 'STORAGE',
            relaxedFields: ['description', 'title']
          }
        }
      });
    });

    it('should return true for relaxed fields on configured tools', () => {
      expect(isRelaxedField('save_features_list', 'description')).toBe(true);
      expect(isRelaxedField('save_features_list', 'title')).toBe(true);
    });

    it('should return false for non-relaxed fields', () => {
      expect(isRelaxedField('save_features_list', 'project')).toBe(false);
      expect(isRelaxedField('save_features_list', 'validators')).toBe(false);
    });

    it('should return false for unknown tools', () => {
      expect(isRelaxedField('unknown_tool', 'anything')).toBe(false);
    });
  });

  describe('getToolsByLevel', () => {
    beforeEach(() => {
      // Register some test policies
      registerToolPolicy('storage_tool_1', { level: 'STORAGE' });
      registerToolPolicy('storage_tool_2', { level: 'STORAGE' });
      registerToolPolicy('display_tool', { level: 'DISPLAY' });
      registerToolPolicy('execution_tool', { level: 'EXECUTION' });
    });

    it('should return tools at specified level', () => {
      expect(getToolsByLevel('STORAGE')).toContain('storage_tool_1');
      expect(getToolsByLevel('STORAGE')).toContain('storage_tool_2');
      expect(getToolsByLevel('DISPLAY')).toContain('display_tool');
      expect(getToolsByLevel('EXECUTION')).toContain('execution_tool');
    });

    it('should return empty array when no tools at level', () => {
      expect(getToolsByLevel('QUERY')).toEqual([]);
    });
  });

  describe('registerToolPolicy', () => {
    it('should allow registering custom tool policies at runtime', () => {
      registerToolPolicy('my_custom_tool', {
        level: 'STORAGE',
        relaxedFields: ['data'],
        description: 'Custom tool for testing'
      });

      const policy = getToolPolicy('my_custom_tool');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('data');
    });

    it('should override existing policies', () => {
      registerToolPolicy('my_tool', { level: 'EXECUTION' });
      expect(getToolPolicy('my_tool').level).toBe('EXECUTION');

      registerToolPolicy('my_tool', { level: 'DISPLAY' });
      expect(getToolPolicy('my_tool').level).toBe('DISPLAY');
    });
  });

  describe('isValidSecurityLevel', () => {
    it('should validate security levels', () => {
      expect(isValidSecurityLevel('EXECUTION')).toBe(true);
      expect(isValidSecurityLevel('QUERY')).toBe(true);
      expect(isValidSecurityLevel('STORAGE')).toBe(true);
      expect(isValidSecurityLevel('DISPLAY')).toBe(true);
      expect(isValidSecurityLevel('INVALID')).toBe(false);
      expect(isValidSecurityLevel('')).toBe(false);
    });
  });
});

describe('Pattern Categories', () => {
  describe('getCategoriesForLevel', () => {
    it('should return minimal categories for DISPLAY level', () => {
      const categories = getCategoriesForLevel('DISPLAY');
      // Should only have ALWAYS_CHECK categories
      expect(categories.length).toBe(ALWAYS_CHECK_CATEGORIES.length);
      expect(categories).toContain('xss.basicVectors');
      expect(categories).toContain('deserialization.markers');
      // Should NOT have EXECUTION_ONLY categories
      expect(categories).not.toContain('command.basicInjection');
    });

    it('should return STORAGE categories (same as DISPLAY for now)', () => {
      const categories = getCategoriesForLevel('STORAGE');
      expect(categories).toContain('xss.basicVectors');
      expect(categories).not.toContain('command.basicInjection');
    });

    it('should return more categories for QUERY level', () => {
      const categories = getCategoriesForLevel('QUERY');
      expect(categories).toContain('xss.basicVectors');
      expect(categories).toContain('sql.basicInjection');
      expect(categories).toContain('nosql.operators');
      // Should still NOT have EXECUTION_ONLY
      expect(categories).not.toContain('command.basicInjection');
    });

    it('should return all categories for EXECUTION level', () => {
      const categories = getCategoriesForLevel('EXECUTION');
      expect(categories).toContain('xss.basicVectors');
      expect(categories).toContain('sql.basicInjection');
      expect(categories).toContain('command.basicInjection');
      expect(categories).toContain('css.expressions');
    });
  });

  describe('shouldCheckCategory', () => {
    it('should always check critical patterns', () => {
      expect(shouldCheckCategory('xss.basicVectors', 'DISPLAY')).toBe(true);
      expect(shouldCheckCategory('xss.basicVectors', 'STORAGE')).toBe(true);
      expect(shouldCheckCategory('xss.basicVectors', 'QUERY')).toBe(true);
      expect(shouldCheckCategory('xss.basicVectors', 'EXECUTION')).toBe(true);
    });

    it('should only check command injection at EXECUTION level', () => {
      expect(shouldCheckCategory('command.basicInjection', 'DISPLAY')).toBe(false);
      expect(shouldCheckCategory('command.basicInjection', 'STORAGE')).toBe(false);
      expect(shouldCheckCategory('command.basicInjection', 'QUERY')).toBe(false);
      expect(shouldCheckCategory('command.basicInjection', 'EXECUTION')).toBe(true);
    });

    it('should check SQL injection at QUERY and EXECUTION levels', () => {
      expect(shouldCheckCategory('sql.basicInjection', 'DISPLAY')).toBe(false);
      expect(shouldCheckCategory('sql.basicInjection', 'STORAGE')).toBe(false);
      expect(shouldCheckCategory('sql.basicInjection', 'QUERY')).toBe(true);
      expect(shouldCheckCategory('sql.basicInjection', 'EXECUTION')).toBe(true);
    });
  });

  describe('getLevelDescription', () => {
    it('should return descriptions for each level', () => {
      expect(getLevelDescription('DISPLAY')).toContain('Minimal');
      expect(getLevelDescription('STORAGE')).toContain('Relaxed');
      expect(getLevelDescription('QUERY')).toContain('Standard');
      expect(getLevelDescription('EXECUTION')).toContain('Full');
    });
  });
});

describe('Config-driven Policy Resolution', () => {
  afterEach(() => {
    resetToolPolicies();
  });

  it('should support inheritance with extends', () => {
    initializeToolPolicies({
      version: '2.0',
      basePolicies: {
        'base-storage': {
          level: 'STORAGE',
          relaxedFields: ['content']
        }
      },
      tools: {
        'my_tool': {
          extends: 'base-storage',
          relaxedFields: ['extra_field']
        }
      }
    });

    const policy = getToolPolicy('my_tool');
    expect(policy.level).toBe('STORAGE');
    expect(policy.relaxedFields).toContain('content');
    expect(policy.relaxedFields).toContain('extra_field');
  });

  it('should support glob patterns in pattern matching', () => {
    initializeToolPolicies({
      version: '2.0',
      patterns: [
        { match: '{get,list,search}_*', policy: { level: 'DISPLAY' } }
      ]
    });

    expect(getToolPolicy('get_users').level).toBe('DISPLAY');
    expect(getToolPolicy('list_items').level).toBe('DISPLAY');
    expect(getToolPolicy('search_docs').level).toBe('DISPLAY');
    expect(getToolPolicy('delete_user').level).toBe('EXECUTION');
  });

  it('explicit tools should take precedence over patterns', () => {
    initializeToolPolicies({
      version: '2.0',
      patterns: [
        { match: 'get_*', policy: { level: 'DISPLAY' } }
      ],
      tools: {
        'get_sensitive_data': { level: 'EXECUTION' }
      }
    });

    expect(getToolPolicy('get_issues').level).toBe('DISPLAY');
    expect(getToolPolicy('get_sensitive_data').level).toBe('EXECUTION');
  });
});
