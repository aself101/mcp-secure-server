import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ErrorRateLimiter } from '@/security/transport/error-rate-limiter.js';

describe('ErrorRateLimiter', () => {
  let limiter;

  beforeEach(() => {
    vi.useFakeTimers();
    limiter = new ErrorRateLimiter({
      errorsPerMinute: 5,
      errorsPerHour: 20,
      cleanupIntervalMs: 60000
    });
  });

  afterEach(() => {
    limiter.cleanup();
    vi.useRealTimers();
  });

  describe('shouldRateLimit', () => {
    it('should not rate limit on first error', () => {
      expect(limiter.shouldRateLimit('192.168.1.1')).toBe(false);
    });

    it('should not rate limit below minute threshold', () => {
      const ip = '192.168.1.1';
      for (let i = 0; i < 5; i++) {
        expect(limiter.shouldRateLimit(ip)).toBe(false);
        limiter.recordError(ip);
      }
    });

    it('should rate limit after exceeding minute threshold', () => {
      const ip = '192.168.1.1';
      for (let i = 0; i < 5; i++) {
        limiter.recordError(ip);
      }
      expect(limiter.shouldRateLimit(ip)).toBe(true);
    });

    it('should rate limit after exceeding hour threshold', () => {
      const ip = '192.168.1.1';
      for (let i = 0; i < 20; i++) {
        limiter.recordError(ip);
        // Advance time past minute window but within hour
        if (i % 4 === 0) {
          vi.advanceTimersByTime(61000);
        }
      }
      expect(limiter.shouldRateLimit(ip)).toBe(true);
    });

    it('should reset minute counter after window expires', () => {
      const ip = '192.168.1.1';
      for (let i = 0; i < 5; i++) {
        limiter.recordError(ip);
      }
      expect(limiter.shouldRateLimit(ip)).toBe(true);

      // Advance past minute window
      vi.advanceTimersByTime(61000);

      expect(limiter.shouldRateLimit(ip)).toBe(false);
    });

    it('should track different IPs separately', () => {
      const ip1 = '192.168.1.1';
      const ip2 = '192.168.1.2';

      for (let i = 0; i < 5; i++) {
        limiter.recordError(ip1);
      }

      expect(limiter.shouldRateLimit(ip1)).toBe(true);
      expect(limiter.shouldRateLimit(ip2)).toBe(false);
    });
  });

  describe('recordError', () => {
    it('should increment error count', () => {
      const ip = '192.168.1.1';
      limiter.recordError(ip);
      limiter.recordError(ip);
      limiter.recordError(ip);

      const stats = limiter.getStats();
      expect(stats.minuteTracked).toBe(1);
    });
  });

  describe('cleanup', () => {
    it('should clear all counters on cleanup', () => {
      limiter.recordError('192.168.1.1');
      limiter.recordError('192.168.1.2');

      limiter.cleanup();

      const stats = limiter.getStats();
      expect(stats.minuteTracked).toBe(0);
      expect(stats.hourTracked).toBe(0);
    });

    it('should remove stale entries during periodic cleanup', () => {
      limiter.recordError('192.168.1.1');

      // Advance past stale threshold (2 minutes) AND trigger cleanup interval (60s)
      // We need to advance time enough for the entry to be stale when cleanup runs
      vi.advanceTimersByTime(60000); // Trigger first cleanup - entry not stale yet
      vi.advanceTimersByTime(61000); // Trigger second cleanup - entry now stale (>120s old)
      vi.advanceTimersByTime(60000); // Trigger third cleanup to clean stale entries

      const stats = limiter.getStats();
      expect(stats.minuteTracked).toBe(0);
    });
  });

  describe('getStats', () => {
    it('should return accurate statistics', () => {
      limiter.recordError('192.168.1.1');
      limiter.recordError('192.168.1.2');
      limiter.recordError('192.168.1.3');

      const stats = limiter.getStats();
      expect(stats.minuteTracked).toBe(3);
      expect(stats.hourTracked).toBe(3);
    });
  });
});

describe('ErrorRateLimiter tracked-client cap', () => {
  it('evicts the oldest client once maxTrackedClients is reached, bounding memory', () => {
    const limiter = new ErrorRateLimiter({ errorsPerMinute: 1, maxTrackedClients: 2 });
    for (const ip of ['a', 'b', 'c']) limiter.recordError(ip);
    expect(limiter.getStats()).toEqual({ minuteTracked: 2, hourTracked: 2 });
    expect(limiter.shouldRateLimit('a')).toBe(false);
    expect(limiter.shouldRateLimit('c')).toBe(true);
    limiter.cleanup();
  });

  it('defaults to 10000 tracked clients', () => {
    const limiter = new ErrorRateLimiter();
    for (let i = 0; i < 10005; i++) limiter.recordError(`k${i}`);
    expect(limiter.getStats().minuteTracked).toBe(10000);
    limiter.cleanup();
  });
});
