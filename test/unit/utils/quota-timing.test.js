import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { InMemoryQuotaProvider, QuotaProvider } from '@/security/layers/layer-utils/semantics/semantic-quotas.js';

/**
 * Quota Timing Edge Case Tests
 * Tests for window expiry boundaries, clock skew, and concurrent access
 * Coverage: semantic-quotas.js timing logic
 */

describe('InMemoryQuotaProvider', () => {
  let provider;

  beforeEach(() => {
    provider = new InMemoryQuotaProvider({ clockSkewMs: 1000, sweepIntervalMs: 60000 });
  });

  afterEach(() => {
    provider.destroy();
  });

  describe('Basic Quota Operations', () => {
    it('should pass when under limit', () => {
      const now = Date.now();
      const result = provider.incrementAndCheck('test-key', { minute: 10 }, now);

      expect(result.passed).toBe(true);
    });

    it('should track count correctly', () => {
      const now = Date.now();
      for (let i = 0; i < 5; i++) {
        provider.incrementAndCheck('test-key', { minute: 10 }, now);
      }

      // getUsage uses Date.now() internally, so we check the counter directly
      const entry = provider.counters.get('test-key');
      expect(entry.minute.count).toBe(5);
    });

    it('should fail when over limit', () => {
      const now = Date.now();
      // Hit limit (10 requests)
      for (let i = 0; i < 10; i++) {
        const result = provider.incrementAndCheck('test-key', { minute: 10 }, now);
        expect(result.passed).toBe(true);
      }

      // 11th request should fail
      const result = provider.incrementAndCheck('test-key', { minute: 10 }, now);
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/quota exceeded/i);
    });
  });

  describe('Window Expiry Boundary Tests', () => {
    it('should allow request exactly at limit', () => {
      // Use up exactly to limit
      for (let i = 0; i < 10; i++) {
        const result = provider.incrementAndCheck('test-key', { minute: 10 }, 1000);
        expect(result.passed).toBe(true);
      }

      // One more should fail
      const overLimit = provider.incrementAndCheck('test-key', { minute: 10 }, 1000);
      expect(overLimit.passed).toBe(false);
    });

    it('should NOT reset window just before expiry', () => {
      // Make requests at time 0
      for (let i = 0; i < 10; i++) {
        provider.incrementAndCheck('test-key', { minute: 10 }, 0);
      }

      // Just before window expires (60s - 1ms, within clock skew)
      // Window: 60000ms + 1000ms clock skew = 61000ms
      const result = provider.incrementAndCheck('test-key', { minute: 10 }, 60999);
      expect(result.passed).toBe(false);
    });

    it('should reset window after expiry plus clock skew', () => {
      // Make requests at time 0
      for (let i = 0; i < 10; i++) {
        provider.incrementAndCheck('test-key', { minute: 10 }, 0);
      }

      // After window + clock skew expires (61001ms)
      const result = provider.incrementAndCheck('test-key', { minute: 10 }, 61001);
      expect(result.passed).toBe(true);
    });

    it('should handle window reset at exact boundary', () => {
      // Fill up quota
      for (let i = 0; i < 5; i++) {
        provider.incrementAndCheck('test-key', { minute: 5 }, 0);
      }

      // Blocked at time 50000
      const blocked = provider.incrementAndCheck('test-key', { minute: 5 }, 50000);
      expect(blocked.passed).toBe(false);

      // Window resets at 60000 + 1000 (clock skew) = 61000
      const afterReset = provider.incrementAndCheck('test-key', { minute: 5 }, 61001);
      expect(afterReset.passed).toBe(true);
    });
  });

  describe('Clock Skew Handling', () => {
    it('should respect configurable clock skew', () => {
      const strictProvider = new InMemoryQuotaProvider({ clockSkewMs: 0, sweepIntervalMs: 60000 });

      try {
        // Fill quota at time 0
        for (let i = 0; i < 5; i++) {
          strictProvider.incrementAndCheck('test-key', { minute: 5 }, 0);
        }

        // Should reset exactly at 60000 with no clock skew
        const result = strictProvider.incrementAndCheck('test-key', { minute: 5 }, 60001);
        expect(result.passed).toBe(true);
      } finally {
        strictProvider.destroy();
      }
    });

    it('should handle large clock skew values', () => {
      const largeSkewProvider = new InMemoryQuotaProvider({ clockSkewMs: 5000, sweepIntervalMs: 60000 });

      try {
        // Fill quota
        for (let i = 0; i < 5; i++) {
          largeSkewProvider.incrementAndCheck('test-key', { minute: 5 }, 0);
        }

        // Should still be blocked at 64999 (60000 + 5000 - 1)
        const blocked = largeSkewProvider.incrementAndCheck('test-key', { minute: 5 }, 64999);
        expect(blocked.passed).toBe(false);

        // Should reset at 65001
        const passed = largeSkewProvider.incrementAndCheck('test-key', { minute: 5 }, 65001);
        expect(passed.passed).toBe(true);
      } finally {
        largeSkewProvider.destroy();
      }
    });
  });

  describe('Concurrent Access Patterns', () => {
    it('should handle rapid sequential requests correctly', () => {
      const results = [];

      // Simulate 15 rapid requests (limit is 10)
      for (let i = 0; i < 15; i++) {
        results.push(provider.incrementAndCheck('test-key', { minute: 10 }, 1000));
      }

      const passed = results.filter(r => r.passed).length;
      const failed = results.filter(r => !r.passed).length;

      expect(passed).toBe(10);
      expect(failed).toBe(5);
    });

    it('should track multiple keys independently', () => {
      // Fill quota for key1
      for (let i = 0; i < 5; i++) {
        provider.incrementAndCheck('key1', { minute: 5 }, 1000);
      }

      // key1 should be blocked
      const key1Result = provider.incrementAndCheck('key1', { minute: 5 }, 1000);
      expect(key1Result.passed).toBe(false);

      // key2 should be unaffected
      const key2Result = provider.incrementAndCheck('key2', { minute: 5 }, 1000);
      expect(key2Result.passed).toBe(true);
    });

    it('should handle interleaved requests across keys', () => {
      const keys = ['key-a', 'key-b', 'key-c'];
      const results = { 'key-a': 0, 'key-b': 0, 'key-c': 0 };

      // Make 4 requests per key (limit 3)
      for (let round = 0; round < 4; round++) {
        for (const key of keys) {
          const result = provider.incrementAndCheck(key, { minute: 3 }, 1000);
          if (result.passed) results[key]++;
        }
      }

      // Each key should have exactly 3 passed
      expect(results['key-a']).toBe(3);
      expect(results['key-b']).toBe(3);
      expect(results['key-c']).toBe(3);
    });
  });

  describe('Hour Window Tests', () => {
    it('should enforce hour limits separately from minute limits', () => {
      const now = Date.now();
      // Pass minute limit but fail hour limit
      for (let i = 0; i < 5; i++) {
        provider.incrementAndCheck('test-key', { minute: 10, hour: 5 }, now);
      }

      const result = provider.incrementAndCheck('test-key', { minute: 10, hour: 5 }, now);
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/hour.*quota/i);
    });

    it('should track minute and hour windows independently', () => {
      const baseTime = Date.now();
      // Make 3 requests in first minute
      for (let i = 0; i < 3; i++) {
        provider.incrementAndCheck('test-key', { minute: 5, hour: 20 }, baseTime);
      }

      // Make 3 more requests in second minute (after minute window resets)
      // Add 62 seconds to reset minute window
      for (let i = 0; i < 3; i++) {
        provider.incrementAndCheck('test-key', { minute: 5, hour: 20 }, baseTime + 62000);
      }

      // Check counters directly since getUsage uses Date.now()
      const entry = provider.counters.get('test-key');
      expect(entry.minute.count).toBe(3); // Current minute window (reset)
      expect(entry.hour.count).toBe(6);   // Total in hour window
    });
  });

  describe('Sweep Cleanup Tests', () => {
    it('should remove stale entries on sweep', () => {
      const now = Date.now();
      // Create entry at current time
      provider.incrementAndCheck('stale-key', { minute: 5 }, now);
      expect(provider.getActiveKeys()).toBe(1);

      // Sweep at time well past expiry (2+ hours from now)
      provider.sweep(now + 10_000_000);
      expect(provider.getActiveKeys()).toBe(0);
    });

    it('should keep active entries on sweep', () => {
      const now = Date.now();

      // Create recent entry
      provider.incrementAndCheck('active-key', { minute: 5 }, now);
      expect(provider.getActiveKeys()).toBe(1);

      // Sweep at current time + small delta
      provider.sweep(now + 1000);
      expect(provider.getActiveKeys()).toBe(1);
    });

    it('should clean up minute bucket but keep hour bucket', () => {
      const now = Date.now();
      // Create entry at current time
      provider.incrementAndCheck('mixed-key', { minute: 5, hour: 10 }, now);

      // Sweep at time that expires minute (120s + skew) but not hour (2h + skew)
      provider.sweep(now + 200_000); // 200 seconds later

      // Check counter directly - minute should be deleted, hour should remain
      const entry = provider.counters.get('mixed-key');
      expect(entry.minute).toBeUndefined();  // Minute bucket cleaned
      expect(entry.hour.count).toBe(1);      // Hour bucket retained
    });

    it('should handle sweep with mixed stale and fresh data', () => {
      const now = Date.now();

      // Create old entry (far in the past relative to sweep time)
      provider.incrementAndCheck('old-key', { minute: 5 }, now - 1000000);

      // Create new entry at current time
      provider.incrementAndCheck('new-key', { minute: 5 }, now);

      expect(provider.getActiveKeys()).toBe(2);

      // Sweep at current time - should remove old but keep new
      provider.sweep(now);

      // Old should be gone, new should remain
      expect(provider.getActiveKeys()).toBe(1);
      expect(provider.counters.has('old-key')).toBe(false);
      expect(provider.counters.get('new-key').minute.count).toBe(1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle no limits specified', () => {
      const result = provider.incrementAndCheck('test-key', {}, 1000);
      expect(result.passed).toBe(true);
    });

    it('should handle zero timestamp', () => {
      const result = provider.incrementAndCheck('test-key', { minute: 5 }, 0);
      expect(result.passed).toBe(true);
    });

    it('should handle very large timestamps', () => {
      const largeTime = Number.MAX_SAFE_INTEGER - 1000;
      const result = provider.incrementAndCheck('test-key', { minute: 5 }, largeTime);
      expect(result.passed).toBe(true);
    });

    it('should provide correct usage for non-existent key', () => {
      const usage = provider.getUsage('nonexistent');
      expect(usage.minute).toBe(0);
      expect(usage.hour).toBe(0);
    });

    it('should clear all data', () => {
      provider.incrementAndCheck('key1', { minute: 5 }, 1000);
      provider.incrementAndCheck('key2', { minute: 5 }, 1000);
      expect(provider.getActiveKeys()).toBe(2);

      provider.clear();
      expect(provider.getActiveKeys()).toBe(0);
    });
  });

  describe('QuotaProvider Base Class', () => {
    it('should throw on unimplemented incrementAndCheck', () => {
      const baseProvider = new QuotaProvider();
      expect(() => baseProvider.incrementAndCheck('key', {})).toThrow('must be implemented');
    });

    it('should have no-op sweep by default', () => {
      const baseProvider = new QuotaProvider();
      // Should not throw
      expect(() => baseProvider.sweep()).not.toThrow();
    });
  });
});
