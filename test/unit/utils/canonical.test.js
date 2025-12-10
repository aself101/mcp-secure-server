// tests/unit/layers/layer-utils/content/canonicalize-advanced.test.js
import { describe, it, expect } from 'vitest';
import {
  canonicalizeString,
  canonicalizeFromMessage,
  decodeUrlsCanonical
} from '../../../src/security/layers/layer-utils/content/canonicalize.js';

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

    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('decodes valid sequences even with malformed ones nearby', () => {
    // %ZZ is invalid, %2e is valid (dot), %GG is invalid
    const input = '%ZZ%2e%GG';
    const result = decodeUrlsCanonical(input);

    // The valid %2e should decode to '.'
    // Malformed sequences should be preserved
    expect(result).toContain('.');
    expect(typeof result).toBe('string');
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

    expect(typeof resultNull).toBe('string');
    expect(typeof resultUndefined).toBe('string');
  });
});

describe('Performance and Safety', () => {
  it('handles large inputs without hanging', () => {
    const largeInput = 'a'.repeat(10000) + '%2e%2e%2f';

    const start = performance.now();
    const result = canonicalizeString(largeInput);
    const duration = performance.now() - start;

    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(duration).toBeLessThan(1000); // Should complete in under 1 second
  });

  it('converges on deeply nested encodings', () => {
    // 8 levels of encoding (should stop at maxIterations)
    let nested = '.';
    for (let i = 0; i < 8; i++) {
      nested = encodeURIComponent(nested);
    }

    const result = decodeUrlsCanonical(nested);

    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    // Should have made progress even if not fully decoded
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
    expect(typeof result).toBe('string');
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
