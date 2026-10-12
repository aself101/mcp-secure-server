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
  const req = (headers, remoteAddress = '10.0.0.1') => ({ headers, socket: { remoteAddress } });
  const chain = '203.0.113.195, 70.41.3.18, 150.172.238.178';

  describe('default (trustProxy 0): forwarding headers are client-supplied and ignored', () => {
    it('ignores X-Forwarded-For and returns the socket address', () => {
      expect(getClientIp(req({ 'x-forwarded-for': chain }))).toBe('10.0.0.1');
    });

    it('ignores X-Real-IP and returns the socket address', () => {
      expect(getClientIp(req({ 'x-real-ip': '203.0.113.195' }))).toBe('10.0.0.1');
    });

    it('a rotating X-Forwarded-For maps every request to the same key', () => {
      const keys = new Set(['198.51.100.1', '198.51.100.2', '198.51.100.3']
        .map(ip => getClientIp(req({ 'x-forwarded-for': ip }))));
      expect([...keys]).toEqual(['10.0.0.1']);
    });

    it('returns "unknown" when the socket has no address', () => {
      expect(getClientIp({ headers: { 'x-forwarded-for': chain }, socket: {} })).toBe('unknown');
    });
  });

  describe('trustProxy N: the Nth address counting from the socket peer', () => {
    it('1 hop returns the rightmost X-Forwarded-For entry, not the leftmost', () => {
      expect(getClientIp(req({ 'x-forwarded-for': chain }), { trustProxy: 1 })).toBe('150.172.238.178');
    });

    it('2 hops returns the second entry from the right', () => {
      expect(getClientIp(req({ 'x-forwarded-for': chain }), { trustProxy: 2 })).toBe('70.41.3.18');
    });

    it('a client-prepended entry cannot displace the address the trusted proxy appended', () => {
      const spoofed = req({ 'x-forwarded-for': '1.2.3.4, 198.51.100.7' });
      expect(getClientIp(spoofed, { trustProxy: 1 })).toBe('198.51.100.7');
    });

    it('more hops than entries clamps to the leftmost entry', () => {
      expect(getClientIp(req({ 'x-forwarded-for': '203.0.113.195' }), { trustProxy: 3 })).toBe('203.0.113.195');
    });

    it('no X-Forwarded-For falls back to the socket address', () => {
      expect(getClientIp(req({}), { trustProxy: 1 })).toBe('10.0.0.1');
    });

    it('X-Real-IP is never read, even with a trusted proxy', () => {
      expect(getClientIp(req({ 'x-real-ip': '203.0.113.195' }), { trustProxy: 1 })).toBe('10.0.0.1');
    });

    it('joins repeated header values and trims whitespace', () => {
      const r = req({ 'x-forwarded-for': ['203.0.113.195', '  70.41.3.18 , 150.172.238.178  '] });
      expect(getClientIp(r, { trustProxy: 1 })).toBe('150.172.238.178');
      expect(getClientIp(r, { trustProxy: 3 })).toBe('203.0.113.195');
    });

    it('skips empty list entries', () => {
      expect(getClientIp(req({ 'x-forwarded-for': '203.0.113.195, ,' }), { trustProxy: 1 })).toBe('203.0.113.195');
    });
  });

  describe('trustProxy validation', () => {
    it.each([true, -1, 1.5, NaN, '1', Infinity])('rejects %j', (value) => {
      expect(() => getClientIp(req({}), { trustProxy: value })).toThrow(TypeError);
    });

    it('accepts 0 and positive integers', () => {
      expect(() => getClientIp(req({}), { trustProxy: 0 })).not.toThrow();
      expect(() => getClientIp(req({}), { trustProxy: 2 })).not.toThrow();
    });
  });
});
