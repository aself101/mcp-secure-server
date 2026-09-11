import { describe, it, expect } from 'vitest';
import { hashObject, getMessageCacheKey } from '../../../src/security/layers/layer-utils/content/utils/hash-utils.js';

describe('hashObject', () => {
  it('returns "null" for null input', () => {
    expect(hashObject(null)).toBe('null');
  });

  it('returns "undefined" for undefined input', () => {
    expect(hashObject(undefined)).toBe('undefined');
  });

  it('hashes primitive types with type prefix', () => {
    expect(hashObject('test')).toBe('string-test');
    expect(hashObject(42)).toBe('number-42');
    expect(hashObject(true)).toBe('boolean-true');
  });

  it('hashes objects consistently', () => {
    const obj = { a: 1, b: 2 };
    const hash1 = hashObject(obj);
    const hash2 = hashObject(obj);

    expect(hash1).toBe(hash2);
  });

  it('produces same hash for objects with same content', () => {
    const obj1 = { a: 1, b: 2 };
    const obj2 = { a: 1, b: 2 };

    expect(hashObject(obj1)).toBe(hashObject(obj2));
  });

  it('produces different hashes for different objects', () => {
    const obj1 = { a: 1 };
    const obj2 = { a: 2 };

    expect(hashObject(obj1)).not.toBe(hashObject(obj2));
  });

  it('distinguishes objects that differ only at a nested key (ship run #1 regression)', () => {
    // The old JSON.stringify(obj, Object.keys(obj).sort()) replacer whitelisted
    // the TOP-LEVEL keys at every depth, so `path` under `arguments` was dropped
    // and these two hashed identically.
    const benign = { name: 'reader', arguments: { path: '/tmp/safe-file.txt' } };
    const evil = { name: 'reader', arguments: { path: '../../etc/./passwd' } };
    expect(hashObject(benign)).not.toBe(hashObject(evil));
  });

  it('is order-insensitive at every depth, not just the top level', () => {
    const a = { outer: { x: 1, y: { p: 1, q: 2 } }, top: 'v' };
    const b = { top: 'v', outer: { y: { q: 2, p: 1 }, x: 1 } };
    expect(hashObject(a)).toBe(hashObject(b));
  });

  it('preserves array order (arrays are not sets)', () => {
    expect(hashObject({ a: [1, 2] })).not.toBe(hashObject({ a: [2, 1] }));
  });

  it('is a full-width content hash, not a 32-bit string hash', () => {
    expect(hashObject({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });

  it('handles arrays', () => {
    const arr = [1, 2, 3, { nested: true }];
    const hash = hashObject(arr);

    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });

  it('handles circular references gracefully', () => {
    const circular = { a: 1 };
    circular.self = circular; // Create circular reference

    const hash = hashObject(circular);

    // Should return error fallback format
    expect(hash).toMatch(/^error-object-/);
  });

  it('handles empty objects', () => {
    const hash = hashObject({});

    expect(typeof hash).toBe('string');
    expect(hash.length).toBeGreaterThan(0);
  });
});

describe('getMessageCacheKey', () => {
  it('returns "null-message" for null input', () => {
    expect(getMessageCacheKey(null)).toBe('null-message');
  });

  it('returns "undefined-message" for undefined input', () => {
    expect(getMessageCacheKey(undefined)).toBe('undefined-message');
  });

  it('returns "invalid-" prefix for non-object types', () => {
    expect(getMessageCacheKey('string')).toBe('invalid-string');
    expect(getMessageCacheKey(42)).toBe('invalid-number');
    expect(getMessageCacheKey(true)).toBe('invalid-boolean');
  });

  it('generates cache key from message method and params', () => {
    const message = {
      method: 'tools/call',
      params: { tool: 'test', args: { x: 1 } }
    };
    const key = getMessageCacheKey(message);

    expect(key).toContain('tools/call');
    expect(typeof key).toBe('string');
  });

  it('uses "unknown" for missing method', () => {
    const message = { params: { x: 1 } };
    const key = getMessageCacheKey(message);

    expect(key).toContain('unknown');
  });

  it('handles messages without params', () => {
    const message = { method: 'tools/list' };
    const key = getMessageCacheKey(message);

    expect(key).toContain('tools/list');
  });

  it('handles deeply nested params', () => {
    const message = {
      method: 'test',
      params: {
        deep: {
          nested: {
            value: 'data'
          }
        }
      }
    };

    const key = getMessageCacheKey(message);
    const parsed = JSON.parse(key);

    expect(parsed.method).toBe('test');
    expect(typeof parsed.paramsHash).toBe('string');
    expect(parsed.paramsHash.length).toBeGreaterThan(0);
  });

  it('uses size estimate when message contains circular reference', () => {
    const message = { method: 'test', a: 1, b: 2, c: 3, d: 4, e: 5 };
    message.self = message; // Make the whole message circular (7 keys now)

    const key = getMessageCacheKey(message);
    const parsed = JSON.parse(key);

    // Size should be estimate: 7 keys * 50 = 350
    expect(parsed.size).toBe(350);
  });

  it('handles empty message object', () => {
    const key = getMessageCacheKey({});

    expect(key).toContain('unknown');
  });

  it('includes message size in cache key', () => {
    const smallMessage = { method: 'a' };
    const largeMessage = { method: 'a', data: 'x'.repeat(1000) };

    const smallKey = getMessageCacheKey(smallMessage);
    const largeKey = getMessageCacheKey(largeMessage);

    // Keys should be different due to different sizes
    expect(smallKey).not.toBe(largeKey);
  });
});
