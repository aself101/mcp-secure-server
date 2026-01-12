import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ErrorRateLimiter, getClientIp } from '@/security/transport/error-rate-limiter.js';

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

describe('getClientIp', () => {
  it('should extract IP from X-Forwarded-For header', () => {
    const req = {
      headers: { 'x-forwarded-for': '203.0.113.195, 70.41.3.18, 150.172.238.178' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.195');
  });

  it('should extract single IP from X-Forwarded-For', () => {
    const req = {
      headers: { 'x-forwarded-for': '203.0.113.195' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.195');
  });

  it('should extract IP from X-Real-IP header', () => {
    const req = {
      headers: { 'x-real-ip': '203.0.113.195' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.195');
  });

  it('should prefer X-Forwarded-For over X-Real-IP', () => {
    const req = {
      headers: {
        'x-forwarded-for': '203.0.113.100',
        'x-real-ip': '203.0.113.200'
      },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.100');
  });

  it('should fall back to socket remote address', () => {
    const req = {
      headers: {},
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('10.0.0.1');
  });

  it('should return "unknown" when no IP available', () => {
    const req = {
      headers: {},
      socket: {}
    };
    expect(getClientIp(req)).toBe('unknown');
  });

  it('should handle array header values', () => {
    const req = {
      headers: { 'x-forwarded-for': ['203.0.113.195', '70.41.3.18'] },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.195');
  });

  it('should trim whitespace from IP addresses', () => {
    const req = {
      headers: { 'x-forwarded-for': '  203.0.113.195  , 70.41.3.18' },
      socket: { remoteAddress: '10.0.0.1' }
    };
    expect(getClientIp(req)).toBe('203.0.113.195');
  });
});
