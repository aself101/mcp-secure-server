// tests/unit/utils/glob-utils.test.js
import { describe, it, expect, beforeEach } from 'vitest';
import {
  globToRegExp,
  simpleGlobMatch,
  clearGlobCache,
  getGlobCacheSize,
  GLOB_CACHE_MAX_SIZE
} from '../../../src/security/layers/layer-utils/semantics/glob-utils.js';

describe('globToRegExp', () => {
  describe('basic pattern conversion', () => {
    it('returns RegExp unchanged', () => {
      const regex = /^test$/;
      expect(globToRegExp(regex)).toBe(regex);
    });

    it('converts simple string to anchored regex', () => {
      const regex = globToRegExp('test');
      expect(regex.test('test')).toBe(true);
      expect(regex.test('TEST')).toBe(true); // case insensitive
      expect(regex.test('testing')).toBe(false);
      expect(regex.test('atest')).toBe(false);
    });

    it('escapes regex special characters', () => {
      const regex = globToRegExp('file.txt');
      expect(regex.test('file.txt')).toBe(true);
      expect(regex.test('filextxt')).toBe(false); // dot should be literal
    });

    it('handles backslash to forward slash normalization', () => {
      const regex = globToRegExp('path\\to\\file');
      expect(regex.test('path/to/file')).toBe(true);
    });
  });

  describe('glob wildcard patterns', () => {
    it('converts ** to match any path', () => {
      const regex = globToRegExp('/proc/**');
      expect(regex.test('/proc/')).toBe(true);
      expect(regex.test('/proc/cpuinfo')).toBe(true);
      expect(regex.test('/proc/sys/kernel')).toBe(true);
      expect(regex.test('/sys/proc')).toBe(false);
    });

    it('converts * to match single segment', () => {
      const regex = globToRegExp('*.txt');
      expect(regex.test('file.txt')).toBe(true);
      expect(regex.test('document.txt')).toBe(true);
      expect(regex.test('path/file.txt')).toBe(false); // * doesn't match /
    });

    it('converts ? to match single character', () => {
      const regex = globToRegExp('file?.txt');
      expect(regex.test('file1.txt')).toBe(true);
      expect(regex.test('fileA.txt')).toBe(true);
      expect(regex.test('file12.txt')).toBe(false);
      expect(regex.test('file/.txt')).toBe(false); // ? doesn't match /
    });

    it('handles complex glob patterns', () => {
      const regex = globToRegExp('**/node_modules/**/*.js');
      expect(regex.test('project/node_modules/pkg/index.js')).toBe(true);
      expect(regex.test('node_modules/lodash/lodash.js')).toBe(true);
      expect(regex.test('src/index.js')).toBe(false);
    });
  });

  describe('security-relevant patterns', () => {
    it('matches sensitive file patterns', () => {
      const keyPattern = globToRegExp('**/*.key');
      expect(keyPattern.test('/home/user/.ssh/id_rsa.key')).toBe(true);
      expect(keyPattern.test('secrets/private.key')).toBe(true);
      expect(keyPattern.test('file.txt')).toBe(false);
    });

    it('matches dot-prefixed files', () => {
      const envPattern = globToRegExp('**/.env');
      expect(envPattern.test('/app/.env')).toBe(true);
      expect(envPattern.test('.env')).toBe(true);
      expect(envPattern.test('env')).toBe(false);
    });

    it('matches system directories', () => {
      const procPattern = globToRegExp('/proc/**');
      expect(procPattern.test('/proc/self/environ')).toBe(true);
      expect(procPattern.test('/proc/1/cmdline')).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('handles empty string', () => {
      const regex = globToRegExp('');
      expect(regex.test('')).toBe(true);
      expect(regex.test('anything')).toBe(false);
    });

    it('handles whitespace-only string', () => {
      const regex = globToRegExp('   ');
      expect(regex.test('')).toBe(true); // trimmed
    });

    it('handles multiple consecutive wildcards', () => {
      const regex = globToRegExp('***');
      expect(regex.test('')).toBe(true);
      expect(regex.test('anything')).toBe(true);
    });

    it('handles patterns with special regex chars', () => {
      const regex = globToRegExp('file[1].txt');
      expect(regex.test('file[1].txt')).toBe(true);
      expect(regex.test('file1.txt')).toBe(false); // [ should be literal
    });

    it('handles patterns with parentheses', () => {
      const regex = globToRegExp('file(1).txt');
      expect(regex.test('file(1).txt')).toBe(true);
    });

    it('handles patterns with dollar sign', () => {
      const regex = globToRegExp('$HOME/*.txt');
      expect(regex.test('$HOME/file.txt')).toBe(true);
    });
  });
});

describe('simpleGlobMatch', () => {
  describe('undefined handling', () => {
    it('undefined pattern matches everything', () => {
      expect(simpleGlobMatch(undefined, 'anything')).toBe(true);
      expect(simpleGlobMatch(undefined, '')).toBe(true);
    });

    it('undefined value only matches * or undefined pattern', () => {
      expect(simpleGlobMatch('*', undefined)).toBe(true);
      expect(simpleGlobMatch(undefined, undefined)).toBe(true);
      expect(simpleGlobMatch('specific', undefined)).toBe(false);
      expect(simpleGlobMatch('file-*', undefined)).toBe(false);
    });
  });

  describe('star wildcard edge cases', () => {
    it('standalone * matches any value', () => {
      expect(simpleGlobMatch('*', '')).toBe(true);
      expect(simpleGlobMatch('*', 'anything')).toBe(true);
      expect(simpleGlobMatch('*', 'with-special-chars!@#')).toBe(true);
    });

    it('multiple stars work correctly', () => {
      expect(simpleGlobMatch('*-*-*', 'a-b-c')).toBe(true);
      expect(simpleGlobMatch('*-*-*', 'one-two-three')).toBe(true);
      expect(simpleGlobMatch('*-*-*', 'ab-c')).toBe(false);
    });
  });
});

describe('Glob Cache', () => {
  beforeEach(() => {
    clearGlobCache();
  });

  it('exports correct max cache size constant', () => {
    expect(GLOB_CACHE_MAX_SIZE).toBe(100);
  });

  it('starts with empty cache after clear', () => {
    expect(getGlobCacheSize()).toBe(0);
  });

  it('populates cache on pattern use', () => {
    simpleGlobMatch('pattern-1', 'pattern-1');
    expect(getGlobCacheSize()).toBe(1);

    simpleGlobMatch('pattern-2', 'pattern-2');
    expect(getGlobCacheSize()).toBe(2);
  });

  it('reuses cached patterns', () => {
    simpleGlobMatch('cached-pattern', 'value1');
    simpleGlobMatch('cached-pattern', 'value2');
    simpleGlobMatch('cached-pattern', 'value3');
    // Should only have one entry despite multiple uses
    expect(getGlobCacheSize()).toBe(1);
  });

  it('does not cache undefined or star patterns', () => {
    simpleGlobMatch(undefined, 'value');
    simpleGlobMatch('*', 'value');
    // These special cases bypass caching
    expect(getGlobCacheSize()).toBe(0);
  });

  it('evicts oldest entry when cache exceeds max size (FIFO)', () => {
    // Fill cache to max
    for (let i = 0; i < GLOB_CACHE_MAX_SIZE; i++) {
      simpleGlobMatch(`eviction-test-${i}`, 'test');
    }
    expect(getGlobCacheSize()).toBe(GLOB_CACHE_MAX_SIZE);

    // Add one more - should trigger eviction
    simpleGlobMatch('new-pattern', 'test');
    expect(getGlobCacheSize()).toBe(GLOB_CACHE_MAX_SIZE);
  });

  it('handles many patterns without memory issues', () => {
    // Generate 200 unique patterns (2x max size)
    for (let i = 0; i < 200; i++) {
      simpleGlobMatch(`stress-test-${i}-*`, `stress-test-${i}-value`);
    }
    // Cache should never exceed max size
    expect(getGlobCacheSize()).toBeLessThanOrEqual(GLOB_CACHE_MAX_SIZE);
  });

  it('clearGlobCache resets cache completely', () => {
    for (let i = 0; i < 50; i++) {
      simpleGlobMatch(`clear-test-${i}`, 'test');
    }
    expect(getGlobCacheSize()).toBe(50);

    clearGlobCache();
    expect(getGlobCacheSize()).toBe(0);
  });
});
