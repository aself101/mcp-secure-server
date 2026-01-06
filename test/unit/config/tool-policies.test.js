import { describe, it, expect } from 'vitest';
import {
  getToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  registerToolPolicy,
  isValidSecurityLevel,
  defaultToolPolicies
} from '@/security/config/tool-policies.js';
import {
  getCategoriesForLevel,
  shouldCheckCategory,
  getLevelDescription,
  ALWAYS_CHECK_CATEGORIES,
  EXECUTION_ONLY_CATEGORIES
} from '@/security/config/pattern-categories.js';

describe('Tool Policies', () => {
  describe('getToolPolicy', () => {
    it('should return STORAGE level for save_features_list', () => {
      const policy = getToolPolicy('save_features_list');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('description');
      expect(policy.relaxedFields).toContain('title');
    });

    it('should return DISPLAY level for query_issues', () => {
      const policy = getToolPolicy('query_issues');
      expect(policy.level).toBe('DISPLAY');
    });

    it('should return EXECUTION level for unknown tools', () => {
      const policy = getToolPolicy('unknown_dangerous_tool');
      expect(policy.level).toBe('EXECUTION');
    });

    it('should return EXECUTION level for create-order', () => {
      const policy = getToolPolicy('create-order');
      expect(policy.level).toBe('EXECUTION');
    });

    it('should return QUERY level for query-users', () => {
      const policy = getToolPolicy('query-users');
      expect(policy.level).toBe('QUERY');
    });
  });

  describe('isRelaxedField', () => {
    it('should return true for relaxed fields on STORAGE tools', () => {
      expect(isRelaxedField('save_features_list', 'description')).toBe(true);
      expect(isRelaxedField('save_features_list', 'title')).toBe(true);
      expect(isRelaxedField('add_issue_note', 'content')).toBe(true);
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
    it('should return STORAGE level tools', () => {
      const storageTools = getToolsByLevel('STORAGE');
      expect(storageTools).toContain('save_features_list');
      expect(storageTools).toContain('update_status');
      expect(storageTools).toContain('add_issue_note');
    });

    it('should return DISPLAY level tools', () => {
      const displayTools = getToolsByLevel('DISPLAY');
      expect(displayTools).toContain('query_issues');
      expect(displayTools).toContain('get_project_summary');
    });

    it('should return EXECUTION level tools', () => {
      const executionTools = getToolsByLevel('EXECUTION');
      expect(executionTools).toContain('create-order');
      expect(executionTools).toContain('delete_project');
    });
  });

  describe('registerToolPolicy', () => {
    it('should allow registering custom tool policies', () => {
      registerToolPolicy('my_custom_tool', {
        level: 'STORAGE',
        relaxedFields: ['data'],
        description: 'Custom tool for testing'
      });

      const policy = getToolPolicy('my_custom_tool');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('data');
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

describe('Tool Policy Coverage', () => {
  it('should have known validation tracker tools configured', () => {
    const validationTrackerTools = [
      'save_features_list',
      'update_status',
      'add_issue_note',
      'bulk_update_status',
      'query_issues',
      'get_project_summary'
    ];

    for (const tool of validationTrackerTools) {
      const policy = getToolPolicy(tool);
      expect(policy.level).toBeDefined();
      expect(['STORAGE', 'DISPLAY', 'QUERY', 'EXECUTION']).toContain(policy.level);
    }
  });

  it('should have all defined tools with valid levels', () => {
    for (const [toolName, policy] of Object.entries(defaultToolPolicies)) {
      expect(isValidSecurityLevel(policy.level)).toBe(true);
    }
  });
});
