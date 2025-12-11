// tests/unit/utils/text-decoding.test.js
import { describe, it, expect } from 'vitest';
import {
  normalizeWhitespace,
  decodeSingleUrlEncoding,
  decodeURIComponentStrict,
  decodeURIComponentSafe
} from '../../../src/security/layers/layer-utils/content/utils/text-decoding.js';

describe('normalizeWhitespace', () => {
  it('normalizes various Unicode spaces to regular space', () => {
    // Non-breaking space, figure space, thin space
    const input = 'hello\u00A0world\u2007test\u2009end';
    const result = normalizeWhitespace(input);

    expect(result).toBe('hello world test end');
  });

  it('normalizes line separators to newline', () => {
    const input = 'line1\u2028line2\u2029line3';
    const result = normalizeWhitespace(input);

    expect(result).toBe('line1\nline2\nline3');
  });

  it('normalizes tabs and form feeds to space', () => {
    const input = 'a\u0009b\u000Bc\u000Cd';
    const result = normalizeWhitespace(input);

    expect(result).toBe('a b c d');
  });
});

describe('decodeSingleUrlEncoding', () => {
  it('decodes common attack characters', () => {
    expect(decodeSingleUrlEncoding('%3C')).toBe('<');
    expect(decodeSingleUrlEncoding('%3c')).toBe('<');
    expect(decodeSingleUrlEncoding('%3E')).toBe('>');
    expect(decodeSingleUrlEncoding('%3e')).toBe('>');
    expect(decodeSingleUrlEncoding('%22')).toBe('"');
    expect(decodeSingleUrlEncoding('%27')).toBe("'");
  });

  it('decodes path traversal characters', () => {
    expect(decodeSingleUrlEncoding('%2F')).toBe('/');
    expect(decodeSingleUrlEncoding('%5C')).toBe('\\');
  });

  it('decodes command injection characters', () => {
    expect(decodeSingleUrlEncoding('%3B')).toBe(';');
    expect(decodeSingleUrlEncoding('%7C')).toBe('|');
    expect(decodeSingleUrlEncoding('%26')).toBe('&');
  });

  it('preserves non-encoded content', () => {
    const input = 'normal text';
    expect(decodeSingleUrlEncoding(input)).toBe('normal text');
  });
});

describe('decodeURIComponentStrict', () => {
  it('decodes valid percent-encoded ASCII', () => {
    expect(decodeURIComponentStrict('%48%65%6C%6C%6F')).toBe('Hello');
  });

  it('decodes valid UTF-8 sequences', () => {
    // UTF-8 encoding of 'é' (U+00E9): C3 A9
    expect(decodeURIComponentStrict('%C3%A9')).toBe('é');
  });

  it('throws TypeError on null input', () => {
    expect(() => decodeURIComponentStrict(null)).toThrow(TypeError);
  });

  it('throws URIError on incomplete percent escape', () => {
    expect(() => decodeURIComponentStrict('%4')).toThrow(URIError);
    expect(() => decodeURIComponentStrict('%')).toThrow(URIError);
  });

  it('throws URIError on invalid hex in percent escape', () => {
    expect(() => decodeURIComponentStrict('%GG')).toThrow(URIError);
    expect(() => decodeURIComponentStrict('%ZZ')).toThrow(URIError);
  });

  it('throws URIError on truncated UTF-8 sequence', () => {
    // Two-byte sequence start (C3) without continuation
    expect(() => decodeURIComponentStrict('%C3')).toThrow(URIError);
  });

  it('throws URIError on invalid UTF-8 continuation byte', () => {
    // C3 followed by non-continuation byte
    expect(() => decodeURIComponentStrict('%C3%40')).toThrow(URIError);
  });

  it('throws URIError on overlong 2-byte sequences', () => {
    // C0 80 is overlong encoding of NUL - C0 starts overlong range
    expect(() => decodeURIComponentStrict('%C0%80')).toThrow(URIError);
  });

  it('throws URIError on surrogate code points', () => {
    // ED A0 80 is U+D800 (surrogate) - invalid in UTF-8
    expect(() => decodeURIComponentStrict('%ED%A0%80')).toThrow(URIError);
  });

  it('decodes 3-byte UTF-8 sequences correctly', () => {
    // E2 82 AC is € (U+20AC)
    expect(decodeURIComponentStrict('%E2%82%AC')).toBe('€');
  });

  it('decodes 4-byte UTF-8 sequences correctly', () => {
    // F0 9F 98 80 is 😀 (U+1F600)
    expect(decodeURIComponentStrict('%F0%9F%98%80')).toBe('😀');
  });

  it('throws URIError on overlong 3-byte sequences', () => {
    // E0 80 80 is overlong encoding
    expect(() => decodeURIComponentStrict('%E0%80%80')).toThrow(URIError);
  });

  it('throws URIError on overlong 4-byte sequences', () => {
    // F0 80 80 80 is overlong encoding
    expect(() => decodeURIComponentStrict('%F0%80%80%80')).toThrow(URIError);
  });

  it('throws URIError on code points beyond U+10FFFF', () => {
    // F4 90 80 80 would be U+110000 (beyond max)
    expect(() => decodeURIComponentStrict('%F4%90%80%80')).toThrow(URIError);
  });

  it('throws URIError on invalid UTF-8 leading byte', () => {
    // FE and FF are never valid in UTF-8
    expect(() => decodeURIComponentStrict('%FE')).toThrow(URIError);
    expect(() => decodeURIComponentStrict('%FF')).toThrow(URIError);
  });

  it('handles 4-byte sequence with F1-F3 leading bytes', () => {
    // F1 8F BF BF is a valid code point
    expect(() => decodeURIComponentStrict('%F1%8F%BF%BF')).not.toThrow();
  });

  it('handles ED with valid continuation (non-surrogate)', () => {
    // ED 9F BF is U+D7FF (valid, just before surrogate range)
    expect(decodeURIComponentStrict('%ED%9F%BF')).toBe('\uD7FF');
  });

  it('handles E1-EC and EE-EF 3-byte sequences', () => {
    // E1 80 80 is U+1000 (Myanmar)
    expect(() => decodeURIComponentStrict('%E1%80%80')).not.toThrow();
    // EF BF BD is U+FFFD (replacement character)
    expect(decodeURIComponentStrict('%EF%BF%BD')).toBe('\uFFFD');
  });

  it('handles F4 with valid continuation', () => {
    // F4 8F BF BF is U+10FFFF (max valid code point)
    expect(() => decodeURIComponentStrict('%F4%8F%BF%BF')).not.toThrow();
  });
});

describe('decodeURIComponentSafe', () => {
  it('decodes valid sequences like strict version', () => {
    expect(decodeURIComponentSafe('%48%65%6C%6C%6F')).toBe('Hello');
    expect(decodeURIComponentSafe('%C3%A9')).toBe('é');
  });

  it('preserves invalid sequences instead of throwing', () => {
    // Should not throw, should preserve or partially decode
    expect(() => decodeURIComponentSafe('%GG')).not.toThrow();
    expect(() => decodeURIComponentSafe('%C3')).not.toThrow();
  });

  it('handles mixed valid and invalid sequences', () => {
    const input = '%48%65%GG%6C%6F';
    const result = decodeURIComponentSafe(input);

    // Should decode valid parts
    expect(result).toContain('He');
    expect(result).toContain('lo');
  });

  it('falls back to partial decoding on malformed input', () => {
    // Incomplete UTF-8 at the end
    const result = decodeURIComponentSafe('test%C3');
    expect(result).toContain('test');
  });
});
