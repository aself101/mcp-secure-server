// tests/unit/layers/layer-utils/content/helper-utils.test.js
import { describe, it, expect } from 'vitest';
import {
  hashObject,
  getMessageCacheKey,
  calculateNestingLevel,
  countParameters,
  normalizeWhitespace
} from '../../../src/security/layers/layer-utils/content/helper-utils.js';

describe('hashObject', () => {
  it('returns consistent hash for same object', () => {
    const obj = { a: 1, b: 2, c: 3 };
    const hash1 = hashObject(obj);
    const hash2 = hashObject(obj);
    
    expect(hash1).toBe(hash2);
  });

  it('returns different hash for different objects', () => {
    const obj1 = { a: 1, b: 2 };
    const obj2 = { a: 1, b: 3 };
    const hash1 = hashObject(obj1);
    const hash2 = hashObject(obj2);
    
    expect(hash1).not.toBe(hash2);
  });

  it('handles null and undefined input', () => {
    const hashNull = hashObject(null);
    const hashUndefined = hashObject(undefined);
    
    expect(hashNull).toBe('null');
    expect(hashUndefined).toBe('undefined');
  });

  it('produces same hash regardless of key order', () => {
    const obj1 = { a: 1, b: 2, c: 3 };
    const obj2 = { c: 3, a: 1, b: 2 };
    const hash1 = hashObject(obj1);
    const hash2 = hashObject(obj2);
    
    expect(hash1).toBe(hash2);
  });
});

describe('getMessageCacheKey', () => {
  it('generates cache key with method and params hash', () => {
    const message = {
      method: 'tools/call',
      params: { name: 'calculator', arguments: { expression: '2+2' } }
    };
    
    const cacheKey = getMessageCacheKey(message);
    
    expect(cacheKey).toContain('tools/call');
    expect(typeof cacheKey).toBe('string');
  });

  it('same message produces same cache key', () => {
    const message = {
      method: 'tools/call',
      params: { name: 'test', args: { x: 1 } }
    };
    
    const key1 = getMessageCacheKey(message);
    const key2 = getMessageCacheKey(message);
    
    expect(key1).toBe(key2);
  });

  it('different messages produce different cache keys', () => {
    const message1 = {
      method: 'tools/call',
      params: { name: 'test1' }
    };
    
    const message2 = {
      method: 'tools/call',
      params: { name: 'test2' }
    };
    
    const key1 = getMessageCacheKey(message1);
    const key2 = getMessageCacheKey(message2);
    
    expect(key1).not.toBe(key2);
  });
});

describe('calculateNestingLevel', () => {
  it('returns 0 for primitive values', () => {
    expect(calculateNestingLevel('string')).toBe(0);
    expect(calculateNestingLevel(123)).toBe(0);
    expect(calculateNestingLevel(true)).toBe(0);
    expect(calculateNestingLevel(null)).toBe(0);
    expect(calculateNestingLevel(undefined)).toBe(0);
  });

  it('returns 1 for flat object', () => {
    const obj = { a: 1, b: 2, c: 3 };
    const level = calculateNestingLevel(obj);
    
    expect(level).toBe(1);
  });

  it('calculates correct depth for nested objects', () => {
    const obj = {
      a: {
        b: {
          c: 1
        }
      }
    };
    
    const level = calculateNestingLevel(obj);
    expect(level).toBe(3);
  });

  it('handles arrays correctly', () => {
    const obj = {
      a: [1, 2, 3]
    };
    
    const level = calculateNestingLevel(obj);
    expect(level).toBe(2);
  });

  it('handles deeply nested mixed structures', () => {
    const obj = {
      a: {
        b: [
          {
            c: {
              d: 1
            }
          }
        ]
      }
    };
    
    const level = calculateNestingLevel(obj);
    expect(level).toBe(5);
  });
});

describe('countParameters', () => {
  it('counts flat object keys', () => {
    const obj = { a: 1, b: 2, c: 3 };
    const count = countParameters(obj);
    
    expect(count).toBe(3);
  });

  it('counts nested object keys recursively', () => {
    const obj = {
      a: {
        b: 1,
        c: 2
      },
      d: 3
    };
    
    const count = countParameters(obj);
    expect(count).toBe(4); // a, d, b, c
  });

  it('handles circular references safely', () => {
    const obj = { a: 1, b: 2 };
    obj.self = obj;
    
    const count = countParameters(obj);
    expect(count).toBeGreaterThan(0);
    expect(count).toBeLessThan(1000); // Should not infinite loop
  });

  it('returns 0 for null and undefined', () => {
    expect(countParameters(null)).toBe(0);
    expect(countParameters(undefined)).toBe(0);
  });
});

describe('normalizeWhitespace', () => {
  it('normalizes Unicode spaces to regular space', () => {
    const input = 'hello\u00A0world\u2000test';
    const output = normalizeWhitespace(input);
    
    expect(output).toBe('hello world test');
  });

  it('normalizes line and paragraph separators', () => {
    const input = 'line1\u2028line2\u2029line3';
    const output = normalizeWhitespace(input);
    
    expect(output).toBe('line1\nline2\nline3');
  });

  it('handles mixed whitespace characters', () => {
    const input = 'test\u00A0\u1680\u2000mixed\u2028\u2029spaces';
    const output = normalizeWhitespace(input);
    
    expect(output).toContain('test');
    expect(output).toContain('mixed');
    expect(output).toContain('spaces');
    expect(output).not.toContain('\u00A0');
    expect(output).not.toContain('\u2028');
  });
});