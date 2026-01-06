/**
 * Tests for Tool Policies Configuration System (v2)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFile, mkdir, rm } from 'node:fs/promises';
import {
  loadToolPoliciesConfig,
  initializeToolPolicies,
  resetToolPolicies,
  getToolPoliciesConfig,
  matchesPattern,
  resolvePolicy,
  resolveToolPolicyFromConfig,
  ToolPolicyError
} from '@/security/config/tool-policies-config.js';
import { getToolPolicy, defaultToolPolicies } from '@/security/config/tool-policies.js';

describe('Tool Policies Config v2', () => {
  // Clean up after each test
  afterEach(() => {
    resetToolPolicies();
  });

  describe('matchesPattern', () => {
    it('should match exact tool names', () => {
      expect(matchesPattern('save_features_list', 'save_features_list')).toBe(true);
      expect(matchesPattern('save_features_list', 'query_issues')).toBe(false);
    });

    it('should match prefix patterns with *', () => {
      expect(matchesPattern('get_issues', 'get_*')).toBe(true);
      expect(matchesPattern('get_run_details', 'get_*')).toBe(true);
      expect(matchesPattern('save_features_list', 'get_*')).toBe(false);
    });

    it('should match suffix patterns with *', () => {
      expect(matchesPattern('query_issues', '*_issues')).toBe(true);
      expect(matchesPattern('search_issues', '*_issues')).toBe(true);
      expect(matchesPattern('query_runs', '*_issues')).toBe(false);
    });

    it('should match patterns with * in middle', () => {
      expect(matchesPattern('validation-tracker-save', 'validation-*-save')).toBe(true);
      expect(matchesPattern('validation-tracker-query', 'validation-*-save')).toBe(false);
    });

    it('should match single character with ?', () => {
      expect(matchesPattern('v1_tool', 'v?_tool')).toBe(true);
      expect(matchesPattern('v2_tool', 'v?_tool')).toBe(true);
      expect(matchesPattern('v12_tool', 'v?_tool')).toBe(false);
    });

    it('should be case-insensitive', () => {
      expect(matchesPattern('Get_Issues', 'get_*')).toBe(true);
      expect(matchesPattern('GET_ISSUES', 'get_*')).toBe(true);
    });

    it('should handle special regex characters safely', () => {
      expect(matchesPattern('tool.name', 'tool.name')).toBe(true);
      expect(matchesPattern('tool[0]', 'tool[0]')).toBe(true);
    });
  });

  describe('resolvePolicy', () => {
    const basePolicies = {
      'storage-base': {
        level: 'STORAGE',
        relaxedFields: ['content', 'description'],
        description: 'Base storage policy'
      },
      'display-base': {
        level: 'DISPLAY',
        description: 'Base display policy'
      }
    };

    it('should resolve string references to base policies', () => {
      const result = resolvePolicy('storage-base', basePolicies);
      expect(result.level).toBe('STORAGE');
      expect(result.relaxedFields).toEqual(['content', 'description']);
    });

    it('should return inline policies as-is', () => {
      const inlinePolicy = { level: 'QUERY', description: 'Custom policy' };
      const result = resolvePolicy(inlinePolicy, basePolicies);
      expect(result).toEqual(inlinePolicy);
    });

    it('should return default EXECUTION for unknown references', () => {
      const result = resolvePolicy('unknown-policy', basePolicies);
      expect(result.level).toBe('EXECUTION');
    });

    it('should resolve extends and merge fields', () => {
      const extendedPolicy = {
        level: 'STORAGE',
        extends: 'storage-base',
        relaxedFields: ['title', 'raw_markdown']
      };
      const result = resolvePolicy(extendedPolicy, basePolicies);
      expect(result.level).toBe('STORAGE');
      // Should merge relaxedFields from base and extension
      expect(result.relaxedFields).toContain('content');
      expect(result.relaxedFields).toContain('description');
      expect(result.relaxedFields).toContain('title');
      expect(result.relaxedFields).toContain('raw_markdown');
    });
  });

  describe('initializeToolPolicies', () => {
    it('should accept valid v2.0 config', () => {
      const config = {
        version: '2.0',
        tools: {
          'custom_tool': { level: 'DISPLAY', description: 'Custom tool' }
        }
      };
      expect(() => initializeToolPolicies(config)).not.toThrow();
      expect(getToolPoliciesConfig()).toEqual(config);
    });

    it('should reject invalid version', () => {
      const config = {
        version: '1.0',
        tools: {}
      };
      expect(() => initializeToolPolicies(config)).toThrow(ToolPolicyError);
    });

    it('should reject invalid tool policy level', () => {
      const config = {
        version: '2.0',
        tools: {
          'bad_tool': { level: 'INVALID' }
        }
      };
      expect(() => initializeToolPolicies(config)).toThrow(ToolPolicyError);
    });

    it('should reject references to missing base policies', () => {
      const config = {
        version: '2.0',
        tools: {
          'my_tool': 'nonexistent-base'
        }
      };
      expect(() => initializeToolPolicies(config)).toThrow(ToolPolicyError);
      try {
        initializeToolPolicies(config);
      } catch (e) {
        expect(e.code).toBe('INVALID_REFERENCE');
      }
    });

    it('should reject extends to missing base policies', () => {
      const config = {
        version: '2.0',
        tools: {
          'my_tool': {
            level: 'STORAGE',
            extends: 'nonexistent-base'
          }
        }
      };
      expect(() => initializeToolPolicies(config)).toThrow(ToolPolicyError);
    });
  });

  describe('resetToolPolicies', () => {
    it('should clear loaded configuration', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: { 'test': { level: 'DISPLAY' } }
      });
      expect(getToolPoliciesConfig()).not.toBeNull();

      resetToolPolicies();
      expect(getToolPoliciesConfig()).toBeNull();
    });
  });

  describe('resolveToolPolicyFromConfig', () => {
    beforeEach(() => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'storage-with-content': {
            level: 'STORAGE',
            relaxedFields: ['content', 'description']
          }
        },
        patterns: [
          { match: 'get_*', policy: { level: 'DISPLAY' } },
          { match: '*_issues', policy: { level: 'DISPLAY' } }
        ],
        tools: {
          'custom_tool': { level: 'QUERY', description: 'Explicit tool' },
          'storage_tool': 'storage-with-content'
        },
        defaultLevel: 'STORAGE'
      });
    });

    it('should prioritize explicit tool definitions', () => {
      const result = resolveToolPolicyFromConfig('custom_tool', defaultToolPolicies);
      expect(result?.level).toBe('QUERY');
    });

    it('should resolve string references', () => {
      const result = resolveToolPolicyFromConfig('storage_tool', defaultToolPolicies);
      expect(result?.level).toBe('STORAGE');
      expect(result?.relaxedFields).toContain('content');
    });

    it('should match patterns for unknown tools', () => {
      const result = resolveToolPolicyFromConfig('get_something_new', defaultToolPolicies);
      expect(result?.level).toBe('DISPLAY');
    });

    it('should use first matching pattern', () => {
      // 'get_issues' matches both 'get_*' and '*_issues', but 'get_*' comes first
      const result = resolveToolPolicyFromConfig('get_issues', defaultToolPolicies);
      expect(result?.level).toBe('DISPLAY');
    });

    it('should return null for tools in built-in defaults', () => {
      // save_features_list is in defaultToolPolicies
      const result = resolveToolPolicyFromConfig('save_features_list', defaultToolPolicies);
      expect(result).toBeNull();
    });

    it('should use defaultLevel for completely unknown tools', () => {
      const result = resolveToolPolicyFromConfig('completely_unknown_xyz', defaultToolPolicies);
      expect(result?.level).toBe('STORAGE');
    });

    it('should return null when no config loaded', () => {
      resetToolPolicies();
      const result = resolveToolPolicyFromConfig('any_tool', defaultToolPolicies);
      expect(result).toBeNull();
    });
  });

  describe('getToolPolicy integration', () => {
    it('should use config when loaded', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {
          'custom_configured_tool': {
            level: 'DISPLAY',
            description: 'From config'
          }
        }
      });

      const policy = getToolPolicy('custom_configured_tool');
      expect(policy.level).toBe('DISPLAY');
      expect(policy.description).toBe('From config');
    });

    it('should fall back to built-in defaults', () => {
      initializeToolPolicies({
        version: '2.0',
        tools: {}
      });

      // save_features_list is in built-in defaults
      const policy = getToolPolicy('save_features_list');
      expect(policy.level).toBe('STORAGE');
    });

    it('should use pattern matching', () => {
      initializeToolPolicies({
        version: '2.0',
        patterns: [
          { match: 'my_app_*', policy: { level: 'QUERY' } }
        ]
      });

      const policy = getToolPolicy('my_app_search');
      expect(policy.level).toBe('QUERY');
    });

    it('should default to EXECUTION for unknown tools without config', () => {
      resetToolPolicies();
      const policy = getToolPolicy('completely_unknown_tool');
      expect(policy.level).toBe('EXECUTION');
    });
  });

  describe('loadToolPoliciesConfig', () => {
    let testDir;

    beforeEach(async () => {
      testDir = join(tmpdir(), `tool-policies-test-${Date.now()}`);
      await mkdir(testDir, { recursive: true });
    });

    afterEach(async () => {
      try {
        await rm(testDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    });

    it('should load valid config from file', async () => {
      const configPath = join(testDir, 'tool-policies.json');
      const config = {
        version: '2.0',
        tools: {
          'test_tool': { level: 'DISPLAY' }
        }
      };
      await writeFile(configPath, JSON.stringify(config));

      const loaded = await loadToolPoliciesConfig(configPath);
      expect(loaded).not.toBeNull();
      expect(loaded?.tools?.test_tool).toBeDefined();
    });

    it('should return null for non-existent file', async () => {
      const result = await loadToolPoliciesConfig(join(testDir, 'nonexistent.json'));
      expect(result).toBeNull();
    });

    it('should throw on invalid JSON', async () => {
      const configPath = join(testDir, 'invalid.json');
      await writeFile(configPath, '{ invalid json }');

      await expect(loadToolPoliciesConfig(configPath)).rejects.toThrow(ToolPolicyError);
      try {
        await loadToolPoliciesConfig(configPath);
      } catch (e) {
        expect(e.code).toBe('PARSE_ERROR');
      }
    });

    it('should throw on invalid schema', async () => {
      const configPath = join(testDir, 'bad-schema.json');
      await writeFile(configPath, JSON.stringify({
        version: '3.0',  // Invalid version
        tools: {}
      }));

      await expect(loadToolPoliciesConfig(configPath)).rejects.toThrow(ToolPolicyError);
      try {
        await loadToolPoliciesConfig(configPath);
      } catch (e) {
        expect(e.code).toBe('INVALID_CONFIG');
      }
    });

    it('should validate base policy references', async () => {
      const configPath = join(testDir, 'bad-ref.json');
      await writeFile(configPath, JSON.stringify({
        version: '2.0',
        patterns: [
          { match: 'get_*', policy: 'nonexistent-base' }
        ]
      }));

      await expect(loadToolPoliciesConfig(configPath)).rejects.toThrow(ToolPolicyError);
      try {
        await loadToolPoliciesConfig(configPath);
      } catch (e) {
        expect(e.code).toBe('INVALID_REFERENCE');
      }
    });
  });

  describe('ToolPolicyError', () => {
    it('should have correct name and code', () => {
      const error = new ToolPolicyError('Test error', 'INVALID_CONFIG');
      expect(error.name).toBe('ToolPolicyError');
      expect(error.code).toBe('INVALID_CONFIG');
      expect(error.message).toBe('Test error');
    });
  });

  describe('Complex inheritance scenarios', () => {
    it('should handle multi-level field merging', () => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'base-policy': {
            level: 'STORAGE',
            relaxedFields: ['content'],
            skipPatterns: ['pattern1']
          }
        },
        tools: {
          'extended_tool': {
            level: 'STORAGE',
            extends: 'base-policy',
            relaxedFields: ['title'],
            skipPatterns: ['pattern2']
          }
        }
      });

      const policy = getToolPolicy('extended_tool');
      expect(policy.level).toBe('STORAGE');
      expect(policy.relaxedFields).toContain('content');
      expect(policy.relaxedFields).toContain('title');
      expect(policy.skipPatterns).toContain('pattern1');
      expect(policy.skipPatterns).toContain('pattern2');
    });

    it('should allow pattern policies to use base references', () => {
      initializeToolPolicies({
        version: '2.0',
        basePolicies: {
          'display-readonly': {
            level: 'DISPLAY',
            description: 'Read-only display'
          }
        },
        patterns: [
          { match: 'list_*', policy: 'display-readonly' }
        ]
      });

      const policy = getToolPolicy('list_users');
      expect(policy.level).toBe('DISPLAY');
      expect(policy.description).toBe('Read-only display');
    });
  });
});
