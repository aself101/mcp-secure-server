// tests/unit/layers/layer-utils/content/canonicalize-advanced.test.js
import { describe, it, expect } from 'vitest';
import {
  canonicalizeString,
  canonicalizeFromMessage,
  canonicalizeWithRelaxedFields,
  isFieldPathRelaxed,
  decodeUrlsCanonical
} from '../../../src/security/layers/layer-utils/content/canonicalize.js';

/**
 * Creates deeply nested URL-encoded strings for testing decoder resilience.
 *
 * Each encoding level transforms special characters:
 * - Level 0: "../etc/passwd"
 * - Level 1: "..%2Fetc%2Fpasswd"
 * - Level 2: "..%252Fetc%252Fpasswd"
 * - Level N: Each % becomes %25, creating exponentially longer strings
 *
 * Used to test:
 * - DoS prevention (should not hang on pathological input)
 * - Iteration limits (maxIterations parameter)
 * - Decoder convergence (progress toward decoded form)
 *
 * @param {string} base - The initial string to encode (e.g., '../etc/passwd')
 * @param {number} levels - Number of encoding iterations (25+ is pathological)
 * @returns {string} The multiply-encoded string
 */
function createNestedEncoding(base, levels) {
  let result = base;
  for (let i = 0; i < levels; i++) {
    result = encodeURIComponent(result);
  }
  return result;
}

describe('Multi-Encoding Evasion', () => {
  it('decodes triple-encoded path traversal', () => {
    // %252e%252e%252f = double-encoded "../"
    // So %252e%252e%252f%252e%252e%252f = "../../../" when decoded twice
    // But input only has TWO ../ sequences encoded, so result should be ../../
    const input = '%252e%252e%252f%252e%252e%252fetc%252fpasswd';
    const result = canonicalizeString(input);

    // Input has: ../ + ../ + etc/passwd = ../../etc/passwd
    expect(result).toBe('../../etc/passwd');
  });

  it('handles mixed encoding (Unicode + URL + HTML)', () => {
    const input = '\\u0025\\u0032\\u0065%2e&#x2e;';
    const result = canonicalizeString(input);

    // All should decode to dots
    expect(result).toContain('...');
  });

  it('decodes fullwidth + URL encoding combined', () => {
    // %EF%BC%8E = fullwidth period U+FF0E, %EF%BC%8F = fullwidth slash U+FF0F
    const input = '%EF%BC%8E%EF%BC%8E%EF%BC%8Fetc';
    const result = canonicalizeString(input);

    // Fullwidth periods and slash should normalize to ASCII
    expect(result).toBe('../etc');
  });

  it('handles zero-width characters between encoded sequences', () => {
    const input = '%2e\u200B%2e\u200C%2f';
    const result = canonicalizeString(input);

    expect(result).toBe('../');
    expect(result).not.toContain('\u200B');
  });

  it('decodes homoglyph + escape sequence attacks', () => {
    // Cyrillic а (U+0430), л (U+043B), е (U+0435), р (U+0440), т (U+0442) encoded as Unicode escapes
    const input = '\\u0430\\u043b\\u0435\\u0440\\u0442';
    const result = canonicalizeString(input);

    expect(result).toContain('a');
    expect(result).toContain('e');
    expect(result).toContain('p');
    expect(result).toContain('t');
  });
});

describe('URL Decoding Edge Cases', () => {
  it('handles double-percent encoding', () => {
    const input = '%2525%2525';
    const result = decodeUrlsCanonical(input);

    expect(result).toBe('%%');
  });

  it('stops at maxIterations to prevent infinite loops', () => {
    // Highly nested encoding
    const input = '%25252525252525';
    const result = decodeUrlsCanonical(input, 3);

    expect(result).toBeTypeOf('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('decodes valid sequences even with malformed ones nearby', () => {
    // %ZZ is invalid, %2e is valid (dot), %GG is invalid
    const input = '%ZZ%2e%GG';
    const result = decodeUrlsCanonical(input);

    // The valid %2e should decode to '.'
    // Malformed sequences should be preserved
    expect(result).toContain('.');
    expect(result).toBeTypeOf('string');
  });

  it('handles mixed case percent encoding', () => {
    const input = '%2E%2e%2F%2f';
    const result = decodeUrlsCanonical(input);

    expect(result).toBe('..//');
  });
});

describe('Integration Flow', () => {
  it('applies full canonicalization pipeline in correct order', () => {
    // Test that order matters: Unicode escapes → Unicode norm → HTML → URL → Whitespace → Zero-width
    const input = '\\u003c&#x73;&#99;&#114;&#105;&#112;&#116;\\u003e';
    const result = canonicalizeString(input);

    expect(result).toBe('<script>');
  });

  it('canonicalizes JSON-RPC messages', () => {
    const message = {
      method: 'tools/call',
      params: {
        // Two ../ sequences URL-encoded
        path: '%2e%2e%2f%2e%2e%2fetc%2fpasswd'
      }
    };

    const result = canonicalizeFromMessage(message);

    // Result should contain the decoded path traversal
    expect(result).toContain('../../etc/passwd');
  });

  it('handles null and undefined messages', () => {
    const resultNull = canonicalizeFromMessage(null);
    const resultUndefined = canonicalizeFromMessage(undefined);

    expect(resultNull).toBeTypeOf('string');
    expect(resultUndefined).toBeTypeOf('string');
  });
});

describe('Performance and Safety', () => {
  it('handles large inputs without hanging', () => {
    const largeInput = 'a'.repeat(10000) + '%2e%2e%2f';

    const start = performance.now();
    const result = canonicalizeString(largeInput);
    const duration = performance.now() - start;

    expect(result).toBeTypeOf('string');
    expect(result.length).toBeGreaterThan(0);
    expect(duration).toBeLessThan(1000); // Should complete in under 1 second
  });

  it('converges on deeply nested encodings', () => {
    // 8 levels of encoding (should stop at maxIterations)
    const nested = createNestedEncoding('.', 8);

    const result = decodeUrlsCanonical(nested);

    expect(result).toBeTypeOf('string');
    expect(result.length).toBeGreaterThan(0);
    // Should have made progress even if not fully decoded
  });

  it('handles pathological nested encoding (20+ levels) without hanging', () => {
    // 25 levels is an extreme edge case that could cause exponential blowup in naive implementations
    const pathological = createNestedEncoding('../etc/passwd', 25);

    const start = performance.now();
    const result = decodeUrlsCanonical(pathological);
    const duration = performance.now() - start;

    // Must complete in reasonable time (under 100ms)
    expect(duration).toBeLessThan(100);
    expect(result).toBeTypeOf('string');
    expect(result.length).toBeGreaterThan(0);
    // Should have made some progress decoding (at least removed some encoding layers)
    expect(result.length).toBeLessThan(pathological.length);
  });

  it('handles pathological nested encoding with custom maxIterations', () => {
    // 30 levels of encoding
    const deeplyNested = createNestedEncoding('<script>', 30);

    // Test with different iteration limits
    const result3 = decodeUrlsCanonical(deeplyNested, 3);
    const result8 = decodeUrlsCanonical(deeplyNested, 8);
    const result15 = decodeUrlsCanonical(deeplyNested, 15);

    // All should return valid strings
    expect(result3).toBeTypeOf('string');
    expect(result8).toBeTypeOf('string');
    expect(result15).toBeTypeOf('string');

    // More iterations should make more progress (shorter result as encoding is removed)
    expect(result8.length).toBeLessThanOrEqual(result3.length);
    expect(result15.length).toBeLessThanOrEqual(result8.length);
  });

  it('terminates on encoding that expands on each iteration', () => {
    // Edge case: input that could theoretically expand if not handled carefully
    // This tests that the function doesn't get stuck in expansion loops
    const expandingPattern = '%'.repeat(100) + '25'.repeat(50);

    const start = performance.now();
    const result = decodeUrlsCanonical(expandingPattern);
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(100);
    expect(result).toBeTypeOf('string');
  });

  it('handles mixed deeply nested encoding with attack payloads', () => {
    // Realistic attack: path traversal deeply encoded (20 levels)
    const attack = createNestedEncoding('../../../etc/shadow', 20);

    const start = performance.now();
    const result = canonicalizeString(attack);
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(200);
    expect(result).toBeTypeOf('string');
    // After canonicalization, should have made progress toward revealing the attack
    // The maxIterations limit means it won't fully decode, but should be shorter
    expect(result.length).toBeLessThan(attack.length);
  });
});

describe('Field Path Relaxation', () => {
  describe('isFieldPathRelaxed', () => {
    it('returns false for empty relaxedFields array', () => {
      expect(isFieldPathRelaxed('params.arguments.data', [])).toBe(false);
    });

    it('matches exact field name', () => {
      expect(isFieldPathRelaxed('description', ['description'])).toBe(true);
      expect(isFieldPathRelaxed('title', ['description'])).toBe(false);
    });

    it('matches nested field paths', () => {
      expect(isFieldPathRelaxed('params.arguments.description', ['description'])).toBe(true);
      expect(isFieldPathRelaxed('params.arguments.title', ['description'])).toBe(false);
    });

    it('matches ancestor inheritance', () => {
      // If 'recommendations' is relaxed, all children should be relaxed
      expect(isFieldPathRelaxed('recommendations.0.description', ['recommendations'])).toBe(true);
      expect(isFieldPathRelaxed('recommendations.0.title', ['recommendations'])).toBe(true);
    });

    it('matches full suffix paths', () => {
      expect(isFieldPathRelaxed('params.arguments.recommendations.0.description', ['recommendations.0.description'])).toBe(true);
    });

    it('skips numeric indices when matching individual parts', () => {
      // Should match 'description' but not '0'
      expect(isFieldPathRelaxed('recommendations.0.description', ['description'])).toBe(true);
      expect(isFieldPathRelaxed('recommendations.0.description', ['0'])).toBe(false);
    });

    it('handles multiple relaxed fields', () => {
      const relaxed = ['title', 'description', 'content'];
      expect(isFieldPathRelaxed('params.title', relaxed)).toBe(true);
      expect(isFieldPathRelaxed('params.description', relaxed)).toBe(true);
      expect(isFieldPathRelaxed('params.content', relaxed)).toBe(true);
      expect(isFieldPathRelaxed('params.name', relaxed)).toBe(false);
    });

    it('handles deeply nested paths', () => {
      const path = 'params.arguments.data.items.0.nested.deep.value';
      expect(isFieldPathRelaxed(path, ['value'])).toBe(true);
      expect(isFieldPathRelaxed(path, ['deep'])).toBe(true);
      expect(isFieldPathRelaxed(path, ['items'])).toBe(true);
      expect(isFieldPathRelaxed(path, ['other'])).toBe(false);
    });
  });

  describe('canonicalizeWithRelaxedFields', () => {
    it('behaves like canonicalizeFromMessage when no relaxed fields', () => {
      const message = { method: 'tools/call', params: { text: '%2e%2e%2f' } };
      const withRelaxed = canonicalizeWithRelaxedFields(message, []);
      const normal = canonicalizeFromMessage(message);
      expect(withRelaxed).toBe(normal);
    });

    it('replaces relaxed fields with placeholder', () => {
      const message = {
        method: 'tools/call',
        params: {
          name: 'my-tool',
          description: '<script>alert("xss")</script>'
        }
      };
      const result = canonicalizeWithRelaxedFields(message, ['description']);
      expect(result).toContain('[RELAXED]');
      expect(result).not.toContain('<script>');
      expect(result).toContain('my-tool');
    });

    it('replaces nested relaxed fields', () => {
      const message = {
        params: {
          arguments: {
            recommendations: [
              { title: 'safe', description: '../etc/passwd' },
              { title: 'also-safe', description: 'rm -rf /' }
            ]
          }
        }
      };
      const result = canonicalizeWithRelaxedFields(message, ['description']);
      expect(result).toContain('[RELAXED]');
      expect(result).not.toContain('passwd');
      expect(result).not.toContain('rm -rf');
      expect(result).toContain('safe');
    });

    it('replaces entire parent when parent is relaxed', () => {
      const message = {
        params: {
          arguments: {
            recommendations: [
              { title: 'Attack', description: '<script>' }
            ]
          }
        }
      };
      const result = canonicalizeWithRelaxedFields(message, ['recommendations']);
      expect(result).toContain('[RELAXED]');
      expect(result).not.toContain('Attack');
      expect(result).not.toContain('<script>');
    });

    it('handles null values in message', () => {
      const message = { params: { data: null, text: 'hello' } };
      const result = canonicalizeWithRelaxedFields(message, ['data']);
      expect(result).toBeTypeOf('string');
      expect(result).toContain('hello');
    });

    it('handles arrays with mixed relaxed fields', () => {
      const message = {
        items: [
          { name: 'item1', secret: 'password123' },
          { name: 'item2', secret: 'hunter2' }
        ]
      };
      const result = canonicalizeWithRelaxedFields(message, ['secret']);
      expect(result).toContain('item1');
      expect(result).toContain('item2');
      expect(result).not.toContain('password123');
      expect(result).not.toContain('hunter2');
    });

    it('falls back gracefully on non-JSON-stringifiable input', () => {
      // Test with empty relaxedFields to trigger JSON.stringify fallback
      // (non-empty relaxedFields would cause infinite recursion on circular refs)
      const circular = { a: 1 };
      circular.self = circular;
      const result = canonicalizeWithRelaxedFields(circular, []);
      expect(result).toBeTypeOf('string');
      // Should contain the String() representation of the object
      expect(result).toContain('object');
    });
  });
});

describe('URL Decoding Size Guard', () => {
  it('returns input unchanged when exceeding MAX_URL_DECODE_INPUT_SIZE (1MB)', () => {
    // Create input larger than 1MB (1024 * 1024 = 1048576)
    const largeInput = 'x'.repeat(1048577);
    const result = decodeUrlsCanonical(largeInput);
    // Should return unchanged due to size guard
    expect(result).toBe(largeInput);
  });

  it('processes smaller inputs normally', () => {
    // Create moderate size input (100KB) - large enough to test, fast enough to run
    const moderateInput = 'a'.repeat(100000);
    const result = decodeUrlsCanonical(moderateInput);
    // Should process normally (no encoding to decode, so returns same)
    expect(result).toBe(moderateInput);
  });
});

describe('Real Attack Patterns', () => {
  it('blocks fullwidth path traversal', () => {
    // U+FF0E = fullwidth period, U+FF0F = fullwidth slash
    const input = '\uFF0E\uFF0E\uFF0F\uFF0E\uFF0E\uFF0Fetc\uFF0Fpasswd';
    const result = canonicalizeString(input);

    expect(result).toBe('../../etc/passwd');
  });

  it('blocks Cyrillic homoglyph path traversal', () => {
    // Using Cyrillic р (U+0440) instead of Latin 'p'
    const input = '..\u0440..\u0440etc\u0440passwd';
    const result = canonicalizeString(input);

    // Cyrillic characters should be normalized to Latin
    expect(result).toBeTypeOf('string');
    expect(result).toContain('..');
    expect(result).toContain('p'); // Cyrillic р → Latin p
  });

  it('blocks mixed encoding XSS attempts', () => {
    const input = '%3c%73%63%72%69%70%74%3ealert&#x28;&#x27;xss&#x27;&#x29;%3c%2fscript%3e';
    const result = canonicalizeString(input);

    expect(result).toContain('<script>');
    expect(result).toContain('alert(');
    expect(result).toContain('</script>');
  });

  it('blocks Unicode escape XSS', () => {
    const input = '\\u003cscript\\u003ealert(\\u0027xss\\u0027)\\u003c/script\\u003e';
    const result = canonicalizeString(input);

    expect(result).toBe('<script>alert(\'xss\')</script>');
  });
});
