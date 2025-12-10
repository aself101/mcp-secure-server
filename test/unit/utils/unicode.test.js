// tests/unit/layers/layer-utils/content/unicode.test.js
import { describe, it, expect } from 'vitest';
import {
  normalizeUnicode,
  decodeUnicodeEscapes,
  removePostDecodingZeroWidth,
  decodeEntities,
  normalizeCJKCompatibility
} from '../../../src/security/layers/layer-utils/content/unicode.js';

describe('normalizeUnicode', () => {
  it('converts fullwidth ASCII to halfwidth', () => {
    // Fullwidth ABCDE: U+FF21 to U+FF25
    const input = '\uFF21\uFF22\uFF23\uFF24\uFF25';
    const result = normalizeUnicode(input);

    expect(result).toBe('ABCDE');
  });

  it('normalizes fullwidth punctuation', () => {
    // Fullwidth < > ( ' ) using Unicode escapes
    // U+FF1C = <, U+FF1E = >, U+FF08 = (, U+FF07 = ', U+FF09 = )
    const input = '\uFF1Cscript\uFF1Ealert\uFF08\uFF07xss\uFF07\uFF09\uFF1C/script\uFF1E';
    const result = normalizeUnicode(input);

    expect(result).toContain('<script>');
    expect(result).toContain('alert(');
    expect(result).toContain('</script>');
  });

  it('converts Cyrillic homoglyphs to Latin', () => {
    // Cyrillic: а (U+0430), л (U+043B), е (U+0435), р (U+0440), т (U+0442)
    const input = '\u0430\u043B\u0435\u0440\u0442'; // "алерт" in Cyrillic
    const result = normalizeUnicode(input);

    expect(result).toContain('a'); // Cyrillic а → Latin a
    expect(result).toContain('e'); // Cyrillic е → Latin e
  });

  it('converts Greek homoglyphs to Latin', () => {
    // Greek: α (U+03B1), β (U+03B2), γ (U+03B3)
    const input = '\u03B1\u03B2\u03B3';
    const result = normalizeUnicode(input);

    expect(result).toContain('a'); // Greek α → Latin a
    expect(result).toContain('b'); // Greek β → Latin b
    expect(result).toContain('y'); // Greek γ → Latin y
  });

  it('handles mathematical script variants', () => {
    // Mathematical script: 𝒽 (U+1D4BD), 𝓉 (U+1D4C9), 𝓂 (U+1D4C2), 𝓁 (U+1D4C1)
    const input = '\uD835\uDCBD\uD835\uDCC9\uD835\uDCC2\uD835\uDCC1'; // Surrogate pairs
    const result = normalizeUnicode(input);

    expect(result).toContain('h');
    expect(result).toContain('t');
    expect(result).toContain('m');
    expect(result).toContain('l');
  });

  it('applies NFKC normalization', () => {
    // fi ligature (U+FB01) should normalize to 'fi'
    const input = '\uFB01';
    const result = normalizeUnicode(input);

    expect(result).toBe('fi');
  });

  it('removes zero-width characters during normalization', () => {
    const input = 'test\u200Bstring\u200C';
    const result = normalizeUnicode(input);

    expect(result).toBe('teststring');
    expect(result).not.toContain('\u200B');
    expect(result).not.toContain('\u200C');
  });

  it('handles mixed fullwidth and homoglyphs', () => {
    // Fullwidth dots U+FF0E, fullwidth slash U+FF0F, then Cyrillic р (U+0440 = p), а (U+0430 = a)
    const input = '\uFF0E\uFF0E\uFF0F\u0440\u0430sswd';
    const result = normalizeUnicode(input);

    expect(result).toContain('..');
    expect(result).toContain('passwd');
  });
});

describe('decodeUnicodeEscapes', () => {
  it('decodes \\uXXXX sequences', () => {
    const input = '\\u003cscript\\u003e';
    const result = decodeUnicodeEscapes(input);

    expect(result).toBe('<script>');
  });

  it('decodes \\xNN hex sequences', () => {
    const input = '\\x3cscript\\x3e';
    const result = decodeUnicodeEscapes(input);

    expect(result).toBe('<script>');
  });

  it('decodes \\x{NNNNNN} extended sequences', () => {
    const input = '\\x{3c}script\\x{3e}';
    const result = decodeUnicodeEscapes(input);

    expect(result).toBe('<script>');
  });

  it('handles invalid escape sequences', () => {
    const input = '\\uZZZZ\\xGG';
    const result = decodeUnicodeEscapes(input);

    // Invalid sequences should be preserved
    expect(result).toContain('\\uZZZZ');
    expect(result).toContain('\\xGG');
  });

  it('handles out-of-range code points', () => {
    const input = '\\u{110000}'; // Beyond valid Unicode range
    const result = decodeUnicodeEscapes(input);

    // Should preserve original or handle gracefully
    expect(typeof result).toBe('string');
  });
});

describe('removePostDecodingZeroWidth', () => {
  it('removes all zero-width spaces', () => {
    const input = 'test\u200Bstring\u200Cvalue\u200D';
    const result = removePostDecodingZeroWidth(input);

    expect(result).toBe('teststringvalue');
  });

  it('removes word joiner and BOM', () => {
    const input = 'test\u2060word\uFEFF';
    const result = removePostDecodingZeroWidth(input);

    expect(result).toBe('testword');
  });

  it('preserves normal content', () => {
    const input = 'normal text with spaces';
    const result = removePostDecodingZeroWidth(input);

    expect(result).toBe('normal text with spaces');
  });
});

describe('decodeEntities', () => {
  it('decodes hex entities', () => {
    const input = '&#x3c;script&#x3e;';
    const result = decodeEntities(input);

    expect(result).toBe('<script>');
  });

  it('decodes decimal entities', () => {
    const input = '&#60;script&#62;';
    const result = decodeEntities(input);

    expect(result).toBe('<script>');
  });

  it('decodes named entities', () => {
    const input = '&lt;script&gt;&amp;&quot;&apos;';
    const result = decodeEntities(input);

    expect(result).toBe('<script>&"\'');
  });

  it('handles case-insensitive named entities', () => {
    const input = '&LT;script&GT;&AMP;';
    const result = decodeEntities(input);

    expect(result).toBe('<script>&');
  });

  it('converts fullwidth entities to halfwidth', () => {
    const input = '&#xFF1C;&#xFF1E;'; // Fullwidth < and >
    const result = decodeEntities(input);

    expect(result).toBe('<>');
  });

  it('handles entities without semicolons', () => {
    const input = '&#x3c&#62';
    const result = decodeEntities(input);

    expect(result).toContain('<');
    expect(result).toContain('>');
  });
});

describe('normalizeCJKCompatibility', () => {
  it('maps CJK compatibility forms correctly', () => {
    // Test known mappings
    expect(normalizeCJKCompatibility(0xFE30)).toBe(0x2025); // Two dots
    expect(normalizeCJKCompatibility(0xFE31)).toBe(0x2014); // Em dash
    expect(normalizeCJKCompatibility(0xFE33)).toBe(0x005F); // Underscore
    expect(normalizeCJKCompatibility(0xFE35)).toBe(0x0028); // Left paren
    expect(normalizeCJKCompatibility(0xFE36)).toBe(0x0029); // Right paren
  });

  it('returns original codepoint if no mapping exists', () => {
    const unmappedCodePoint = 0x1234;
    const result = normalizeCJKCompatibility(unmappedCodePoint);

    expect(result).toBe(unmappedCodePoint);
  });
});
