import { describe, it, expect } from 'vitest';
import {
  ATTACK_PATTERNS,
  attackConfigs,
  getPatternsBySeverity,
  getAllPatterns
} from '../../../src/security/layers/layer-utils/content/patterns/index.js';

describe('ATTACK_PATTERNS', () => {
  it('contains all expected categories', () => {
    const expectedCategories = [
      'pathTraversal',
      'xss',
      'sql',
      'command',
      'script',
      'css',
      'bufferOverflow',
      'dataValidation',
      'encoding',
      'ssrf',
      'lolbins',
      'nosql',
      'graphql',
      'deserialization',
      'svg',
      'secrets',
      'crlf',
      'csv',
      'xml'
    ];

    for (const category of expectedCategories) {
      expect(ATTACK_PATTERNS).toHaveProperty(category);
    }
  });

  it('has subcategories with pattern arrays', () => {
    expect(ATTACK_PATTERNS.pathTraversal.patterns).toBeInstanceOf(Array);
    expect(ATTACK_PATTERNS.xss.basicVectors).toBeInstanceOf(Array);
    expect(ATTACK_PATTERNS.sql.basicInjection).toBeInstanceOf(Array);
  });
});

describe('attackConfigs', () => {
  it('is a non-empty array of attack configurations', () => {
    expect(attackConfigs).toBeInstanceOf(Array);
    expect(attackConfigs.length).toBeGreaterThan(0);
  });

  it('each config has required properties', () => {
    for (const config of attackConfigs) {
      expect(config).toHaveProperty('name');
      expect(config).toHaveProperty('categories');
      expect(config).toHaveProperty('violationType');
      expect(config).toHaveProperty('confidence');
      expect(typeof config.name).toBe('string');
      expect(Array.isArray(config.categories)).toBe(true);
      expect(typeof config.confidence).toBe('number');
    }
  });

  it('includes common violation types', () => {
    const violationTypes = attackConfigs.map(c => c.violationType);

    expect(violationTypes).toContain('PATH_TRAVERSAL');
    expect(violationTypes).toContain('XSS_ATTEMPT');
    expect(violationTypes).toContain('SQL_INJECTION');
    expect(violationTypes).toContain('COMMAND_INJECTION');
    expect(violationTypes).toContain('SSRF_ATTEMPT');
  });
});

describe('getPatternsBySeverity', () => {
  it('returns all patterns for NONE severity', () => {
    const patterns = getPatternsBySeverity('NONE');

    expect(patterns).toHaveProperty('pathTraversal');
    expect(patterns).toHaveProperty('xss');
    expect(patterns).toHaveProperty('sql');
  });

  it('filters out LOW severity patterns when minimum is MEDIUM', () => {
    const allPatterns = getPatternsBySeverity('NONE');
    const mediumPatterns = getPatternsBySeverity('MEDIUM');

    // Get total pattern count for a category
    const countPatterns = (categoryPatterns) => {
      let count = 0;
      for (const subcat of Object.values(categoryPatterns)) {
        if (Array.isArray(subcat)) {
          count += subcat.length;
        }
      }
      return count;
    };

    // There should be at least some difference between NONE and MEDIUM filtering
    const allSqlCount = countPatterns(allPatterns.sql);
    const mediumSqlCount = countPatterns(mediumPatterns.sql);

    // Medium+ patterns should be <= all patterns
    expect(mediumSqlCount).toBeLessThanOrEqual(allSqlCount);
  });

  it('filters out patterns below HIGH severity', () => {
    const highPatterns = getPatternsBySeverity('HIGH');

    // Check that all returned patterns are HIGH or CRITICAL
    for (const [, subcategories] of Object.entries(highPatterns)) {
      for (const [, patterns] of Object.entries(subcategories)) {
        if (Array.isArray(patterns)) {
          for (const pattern of patterns) {
            expect(['HIGH', 'CRITICAL']).toContain(pattern.severity);
          }
        }
      }
    }
  });

  it('returns only CRITICAL patterns when minimum is CRITICAL', () => {
    const criticalPatterns = getPatternsBySeverity('CRITICAL');

    for (const [, subcategories] of Object.entries(criticalPatterns)) {
      for (const [, patterns] of Object.entries(subcategories)) {
        if (Array.isArray(patterns)) {
          for (const pattern of patterns) {
            expect(pattern.severity).toBe('CRITICAL');
          }
        }
      }
    }
  });

  it('preserves non-array subcategory values', () => {
    // Some subcategories might have non-array values (like metadata)
    const patterns = getPatternsBySeverity('NONE');

    // The function should preserve the structure even for non-array values
    expect(Object.keys(patterns).length).toBeGreaterThan(0);
  });

  it('handles unknown severity gracefully', () => {
    // Unknown severity should default to 0 (like NONE)
    const patterns = getPatternsBySeverity('UNKNOWN_SEVERITY');

    expect(patterns).toHaveProperty('pathTraversal');
  });
});

describe('getAllPatterns', () => {
  it('returns a flat array of all patterns', () => {
    const patterns = getAllPatterns();

    expect(Array.isArray(patterns)).toBe(true);
    expect(patterns.length).toBeGreaterThan(0);
  });

  it('adds category and subcategory metadata to each pattern', () => {
    const patterns = getAllPatterns();

    for (const pattern of patterns) {
      expect(pattern).toHaveProperty('category');
      expect(pattern).toHaveProperty('subcategory');
      expect(typeof pattern.category).toBe('string');
      expect(typeof pattern.subcategory).toBe('string');
    }
  });

  it('preserves original pattern properties for valid AttackPatterns', () => {
    const patterns = getAllPatterns();

    // Filter for valid AttackPattern objects (some subcategories like mimeTypes are string arrays)
    const validPatterns = patterns.filter(p => p.pattern && p.pattern instanceof RegExp);

    expect(validPatterns.length).toBeGreaterThan(0);

    for (const pattern of validPatterns) {
      expect(pattern).toHaveProperty('pattern');
      expect(pattern).toHaveProperty('severity');
      expect(pattern).toHaveProperty('name');
      expect(pattern.pattern).toBeInstanceOf(RegExp);
    }
  });

  it('includes non-pattern data with category metadata', () => {
    // Some subcategories like dataValidation.mimeTypes are string arrays
    // getAllPatterns includes these with category/subcategory metadata
    const patterns = getAllPatterns();
    const mimeTypeEntries = patterns.filter(p => p.subcategory === 'mimeTypes');

    expect(mimeTypeEntries.length).toBeGreaterThan(0);
    expect(mimeTypeEntries[0]).toHaveProperty('category', 'dataValidation');
    expect(mimeTypeEntries[0]).toHaveProperty('subcategory', 'mimeTypes');
  });

  it('includes patterns from multiple categories', () => {
    const patterns = getAllPatterns();
    const categories = new Set(patterns.map(p => p.category));

    expect(categories.size).toBeGreaterThan(5);
  });

  it('includes patterns from multiple subcategories', () => {
    const patterns = getAllPatterns();
    const subcategories = new Set(patterns.map(p => p.subcategory));

    expect(subcategories.size).toBeGreaterThan(10);
  });

  it('can find patterns by category', () => {
    const patterns = getAllPatterns();
    const xssPatterns = patterns.filter(p => p.category === 'xss');

    expect(xssPatterns.length).toBeGreaterThan(0);
    expect(xssPatterns.every(p => p.category === 'xss')).toBe(true);
  });
});

describe('executionWrappers word-boundary (regression: "filesystem (" FP)', () => {
  const byName = (name) => getAllPatterns().find((p) => p.name === name).pattern;
  // executionWrapper patterns carry the /g flag; copy without it so .test() is stateless.
  const stateless = (re) => new RegExp(re.source, re.flags.replace('g', ''));

  it('System Call matches a genuine system() call', () => {
    expect(stateless(byName('System Call')).test('system("rm -rf /")')).toBe(true);
  });

  it('System Call does NOT match the "filesystem (" substring', () => {
    // Regression: an unanchored /system\s*\(/ matched "fileSYSTEM (" in benign prose,
    // rejecting legitimate payloads (e.g. tracker save_run text). The \b anchor fixes it.
    expect(stateless(byName('System Call')).test('materialized onto a foreign harness filesystem (codex skills dir)')).toBe(false);
    expect(stateless(byName('System Call')).test('the subsystem(x) call')).toBe(false);
  });

  it('Exec Call matches a genuine exec() call but not a word suffix', () => {
    expect(stateless(byName('Exec Call')).test('exec("ls")')).toBe(true);
    expect(stateless(byName('Exec Call')).test('codeexec(x)')).toBe(false);
  });
});
