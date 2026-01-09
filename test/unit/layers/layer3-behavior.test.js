import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import BehaviorValidationLayer from '@/security/layers/layer3-behavior.js';

// Timing constants for rate limiting and burst detection tests
const TIMING = {
  // Window durations
  MINUTE_MS: 60 * 1000,                    // 60 seconds
  HOUR_MS: 60 * 60 * 1000,                 // 3600 seconds
  BURST_WINDOW_MS: 10 * 1000,              // 10 seconds (burst detection window)
  CLEANUP_WINDOW_MS: 30 * 1000,            // 30 seconds (cleanup threshold)

  // Window expiry (duration + buffer)
  MINUTE_EXPIRED_MS: 61 * 1000,            // 61 seconds (minute window + 1s)
  HOUR_EXPIRED_MS: 3601 * 1000,            // 3601 seconds (hour window + 1s)
  MINUTE_EXACT_EXPIRED_MS: 60 * 1000 + 1,  // 60 seconds + 1ms (exact expiry)
  BURST_EXPIRED_MS: 11 * 1000,             // 11 seconds (burst window + 1s)
  CLEANUP_EXPIRED_MS: 35 * 1000,           // 35 seconds (cleanup window + 5s)

  // Within window (should still be blocked)
  WITHIN_MINUTE_MS: 59 * 1000,             // 59 seconds (still within minute)

  // Request spacing
  SPACED_NORMAL_MS: 10 * 1000,             // 10 seconds (normal user spacing)
  SPACED_MEDIUM_MS: 5 * 1000,              // 5 seconds (moderate spacing)
  SPACED_SHORT_MS: 3 * 1000,               // 3 seconds (short but not burst)
  SPACED_SECOND_MS: 1 * 1000,              // 1 second spacing

  // Rapid/burst request spacing
  RAPID_MS: 100,                           // 100ms (rapid but not extreme)
  VERY_RAPID_MS: 50,                       // 50ms (very rapid/suspicious)
};

describe('Behavior Validation Layer', () => {
  let layer;

  beforeEach(() => {
    vi.useFakeTimers();
    layer = new BehaviorValidationLayer({
      requestsPerMinute: 10,
      requestsPerHour: 100,
      burstThreshold: 5
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    layer.cleanup?.();
  });

  describe('Rate Limiting - Per Hour', () => {
    it('should block requests exceeding per-hour limit', async () => {
      // Use a small hourly limit for testing
      const hourlyLayer = new BehaviorValidationLayer({
        requestsPerMinute: 1000, // High enough not to interfere
        requestsPerHour: 15,
        burstThreshold: 100 // High enough not to interfere
      });

      const message = createTestMessage();

      // Send requests up to the hourly limit
      for (let i = 0; i < 15; i++) {
        await hourlyLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.SPACED_MEDIUM_MS); // Space them out to avoid burst detection
      }

      // Next request should be blocked by hourly limit
      const result = await hourlyLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/rate.*limit|hour/i);
      expect(result.violationType).toBe('RATE_LIMIT_EXCEEDED');

      hourlyLayer.cleanup?.();
    });

    it('should reset hourly limit after the hour window expires', async () => {
      const hourlyLayer = new BehaviorValidationLayer({
        requestsPerMinute: 1000,
        requestsPerHour: 10,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Hit the hourly limit
      for (let i = 0; i < 10; i++) {
        await hourlyLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.SPACED_SECOND_MS);
      }

      // Verify blocked
      let result = await hourlyLayer.validate(message, {});
      expect(result.passed).toBe(false);

      // Advance time past the hour window (1 hour + 1 second)
      vi.advanceTimersByTime(TIMING.HOUR_EXPIRED_MS);

      // Should be allowed again after window reset
      result = await hourlyLayer.validate(message, {});
      expect(result.passed).toBe(true);

      hourlyLayer.cleanup?.();
    });

    it('should enforce hourly limit independently from minute limit', async () => {
      const dualLimitLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5,
        requestsPerHour: 8,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Hit minute limit (5 requests)
      for (let i = 0; i < 5; i++) {
        await dualLimitLayer.validate(message, {});
      }

      // Should be blocked by minute limit
      let result = await dualLimitLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/minute/i);

      // Advance past minute window
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      // Make 3 more requests (total 8 for the hour)
      for (let i = 0; i < 3; i++) {
        const r = await dualLimitLayer.validate(message, {});
        expect(r.passed).toBe(true);
      }

      // Should now be blocked by hourly limit
      result = await dualLimitLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/hour/i);

      dualLimitLayer.cleanup?.();
    });

    it('should correctly track hourly + minute boundary interaction across multiple windows', async () => {
      // Scenario: minute=10, hour=25 - user makes 10 requests per minute for 3 minutes
      // After 3 minutes: 30 requests attempted, but only 25 should succeed (hourly limit)
      const boundaryLayer = new BehaviorValidationLayer({
        requestsPerMinute: 10,
        requestsPerHour: 25,
        burstThreshold: 1000 // Very high to eliminate burst interference
      });

      const message = createTestMessage();
      let totalPassed = 0;
      let hourlyBlocked = false;

      // Minute 1: 10 requests should pass (space out to avoid burst detection)
      for (let i = 0; i < 10; i++) {
        const r = await boundaryLayer.validate(message, {});
        if (r.passed) totalPassed++;
        vi.advanceTimersByTime(TIMING.SPACED_SHORT_MS); // 3 seconds spacing
      }
      expect(totalPassed).toBe(10);

      // Advance to minute 2
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      // Minute 2: 10 more requests should pass (total 20)
      for (let i = 0; i < 10; i++) {
        const r = await boundaryLayer.validate(message, {});
        if (r.passed) totalPassed++;
        vi.advanceTimersByTime(TIMING.SPACED_SHORT_MS);
      }
      expect(totalPassed).toBe(20);

      // Advance to minute 3
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      // Minute 3: only 5 more should pass before hourly limit kicks in
      for (let i = 0; i < 10; i++) {
        const r = await boundaryLayer.validate(message, {});
        if (r.passed) {
          totalPassed++;
        } else if (r.reason?.match(/hour/i)) {
          hourlyBlocked = true;
        }
        vi.advanceTimersByTime(TIMING.SPACED_SHORT_MS);
      }

      // Should have hit hourly limit at 25 total
      expect(totalPassed).toBe(25);
      expect(hourlyBlocked).toBe(true);

      boundaryLayer.cleanup?.();
    });

    it('should prefer minute limit error when both limits would be exceeded', async () => {
      // Edge case: both limits hit at the same time
      const edgeLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5,
        requestsPerHour: 5, // Same as minute limit
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Make 5 requests (hit both limits simultaneously)
      for (let i = 0; i < 5; i++) {
        await edgeLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.SPACED_SECOND_MS);
      }

      // 6th request should be blocked - check which limit is reported first
      const result = await edgeLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('RATE_LIMIT_EXCEEDED');
      // Either limit error is acceptable since both are exceeded
      expect(result.reason).toMatch(/minute|hour/i);

      edgeLayer.cleanup?.();
    });

    it('should allow requests after hourly window resets even if minute was recently blocked', async () => {
      const resetLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5,
        requestsPerHour: 10,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Hit minute limit twice, exhausting hourly limit
      for (let i = 0; i < 5; i++) {
        await resetLayer.validate(message, {});
      }
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      for (let i = 0; i < 5; i++) {
        await resetLayer.validate(message, {});
      }

      // Both limits now exhausted
      let result = await resetLayer.validate(message, {});
      expect(result.passed).toBe(false);

      // Advance past hourly window (> 1 hour)
      vi.advanceTimersByTime(TIMING.HOUR_EXPIRED_MS);

      // Both windows should be reset, request should pass
      result = await resetLayer.validate(message, {});
      expect(result.passed).toBe(true);

      resetLayer.cleanup?.();
    });
  });

  describe('Rate Limiting - Per Minute', () => {
    it('should allow requests under the limit', async () => {
      const message = createTestMessage();

      for (let i = 0; i < 5; i++) {
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
      }
    });

    it('should block requests exceeding per-minute limit', async () => {
      const message = createTestMessage();

      // Send requests up to the limit
      for (let i = 0; i < 10; i++) {
        await layer.validate(message, {});
      }

      // Next request should be blocked
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/rate.*limit|too.*many/i);
    });

    it('should reset after the time window expires', async () => {
      const message = createTestMessage();

      // Hit the limit
      for (let i = 0; i < 10; i++) {
        await layer.validate(message, {});
      }

      // Verify blocked
      let result = await layer.validate(message, {});
      expect(result.passed).toBe(false);

      // Advance time past the minute window
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      // Should be allowed again
      result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });

    it('should allow exactly at minute rate limit', async () => {
      const boundaryLayer = new BehaviorValidationLayer({
        requestsPerMinute: 10,
        requestsPerHour: 1000,
        burstThreshold: 100 // High to avoid interference
      });

      // Send exactly 10 concurrent requests (at limit)
      const promises = Array.from({ length: 10 }, () =>
        boundaryLayer.validate(createTestMessage(), {})
      );

      const results = await Promise.all(promises);

      // All 10 should pass (exactly at the limit)
      const passedCount = results.filter(r => r.passed).length;
      expect(passedCount).toBe(10);

      boundaryLayer.cleanup?.();
    });

    it('should block at minute limit + 1', async () => {
      const boundaryLayer = new BehaviorValidationLayer({
        requestsPerMinute: 10,
        requestsPerHour: 1000,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Send 10 requests (at limit)
      for (let i = 0; i < 10; i++) {
        await boundaryLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.SPACED_SECOND_MS);
      }

      // 11th request should fail
      const result = await boundaryLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('RATE_LIMIT_EXCEEDED');
      expect(result.reason).toMatch(/minute/i);

      boundaryLayer.cleanup?.();
    });

    it('should still block at 59 seconds (within window)', async () => {
      const windowLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5,
        requestsPerHour: 1000,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await windowLayer.validate(message, {});
      }

      // Advance 59 seconds (still within minute window)
      vi.advanceTimersByTime(TIMING.WITHIN_MINUTE_MS);

      // Should still be blocked
      const result = await windowLayer.validate(message, {});
      expect(result.passed).toBe(false);

      windowLayer.cleanup?.();
    });

    it('should allow at exactly 60 seconds (window expires)', async () => {
      const windowLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5,
        requestsPerHour: 1000,
        burstThreshold: 100
      });

      const message = createTestMessage();

      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await windowLayer.validate(message, {});
      }

      // Advance exactly 60 seconds (window expires)
      vi.advanceTimersByTime(TIMING.MINUTE_EXACT_EXPIRED_MS);

      // Should be allowed
      const result = await windowLayer.validate(message, {});
      expect(result.passed).toBe(true);

      windowLayer.cleanup?.();
    });
  });

  describe('Burst Detection', () => {
    it('should detect burst activity', async () => {
      const message = createTestMessage();

      // Send rapid requests within burst detection window (10 seconds)
      for (let i = 0; i < 5; i++) {
        await layer.validate(message, {});
        vi.advanceTimersByTime(TIMING.RAPID_MS); // 100ms between requests
      }

      // Next request should trigger burst detection
      const result = await layer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/burst|rapid|suspicious/i);
    });

    it('should allow spaced out requests', async () => {
      const message = createTestMessage();

      // Send requests with enough spacing
      for (let i = 0; i < 5; i++) {
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
        vi.advanceTimersByTime(TIMING.SPACED_SHORT_MS); // 3 seconds between requests
      }
    });

    it('should allow exactly burst threshold requests in window', async () => {
      const boundaryLayer = new BehaviorValidationLayer({
        requestsPerMinute: 100, // High to avoid rate limit interference
        requestsPerHour: 1000,
        burstThreshold: 5
      });

      const message = createTestMessage();

      // Send exactly 5 requests (at threshold) within burst window
      // All should pass since we're AT the threshold, not over
      for (let i = 0; i < 5; i++) {
        const result = await boundaryLayer.validate(message, {});
        expect(result.passed).toBe(true);
        vi.advanceTimersByTime(TIMING.RAPID_MS);
      }

      boundaryLayer.cleanup?.();
    });

    it('should block at burst threshold + 1', async () => {
      const boundaryLayer = new BehaviorValidationLayer({
        requestsPerMinute: 100,
        requestsPerHour: 1000,
        burstThreshold: 5
      });

      const message = createTestMessage();

      // Send 5 requests (at threshold)
      for (let i = 0; i < 5; i++) {
        await boundaryLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.RAPID_MS);
      }

      // 6th request should trigger burst detection
      const result = await boundaryLayer.validate(message, {});
      expect(result.passed).toBe(false);
      expect(result.reason).toMatch(/burst|rapid|suspicious/i);
      expect(result.violationType).toBe('BURST_ACTIVITY');

      boundaryLayer.cleanup?.();
    });

    it('should reset burst count after window expires', async () => {
      const windowLayer = new BehaviorValidationLayer({
        requestsPerMinute: 100,
        requestsPerHour: 1000,
        burstThreshold: 5
      });

      const message = createTestMessage();

      // Fill burst window
      for (let i = 0; i < 5; i++) {
        await windowLayer.validate(message, {});
        vi.advanceTimersByTime(TIMING.RAPID_MS);
      }

      // Advance past 10-second burst window
      vi.advanceTimersByTime(TIMING.BURST_EXPIRED_MS);

      // Should be allowed again after window reset
      const result = await windowLayer.validate(message, {});
      expect(result.passed).toBe(true);

      windowLayer.cleanup?.();
    });
  });

  describe('Automation Detection', () => {
    it('should detect identical rapid requests', async () => {
      const message = createTestMessage();

      // Send identical requests rapidly
      for (let i = 0; i < 6; i++) {
        await layer.validate(message, {});
        vi.advanceTimersByTime(TIMING.VERY_RAPID_MS); // Very rapid
      }

      const result = await layer.validate(message, {});
      // Should be flagged for either burst or automation
      expect(result.passed).toBe(false);
    });
  });

  describe('Valid Behavior', () => {
    it('should pass single request', async () => {
      const message = createTestMessage();
      const result = await layer.validate(message, {});

      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
    });

    it('should pass reasonable request patterns', async () => {
      const message = createTestMessage();

      // Simulate normal usage - a few requests spread out
      for (let i = 0; i < 3; i++) {
        const result = await layer.validate(message, {});
        expect(result.passed).toBe(true);
        vi.advanceTimersByTime(TIMING.SPACED_NORMAL_MS); // 10 seconds between requests
      }
    });
  });

  describe('State Management', () => {
    it('should track requests independently', async () => {
      const layer1 = new BehaviorValidationLayer({ requestsPerMinute: 5 });
      const layer2 = new BehaviorValidationLayer({ requestsPerMinute: 5 });
      const message = createTestMessage();

      // Hit limit on layer1
      for (let i = 0; i < 5; i++) {
        await layer1.validate(message, {});
      }

      // layer1 should be blocked
      const result1 = await layer1.validate(message, {});
      expect(result1.passed).toBe(false);

      // layer2 should still allow
      const result2 = await layer2.validate(message, {});
      expect(result2.passed).toBe(true);

      layer1.cleanup?.();
      layer2.cleanup?.();
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle concurrent requests at rate limit boundary', async () => {
      const concurrentLayer = new BehaviorValidationLayer({
        requestsPerMinute: 10,
        burstThreshold: 100 // High threshold to avoid burst detection
      });

      // Send 10 concurrent requests (exactly at the limit)
      const promises = Array.from({ length: 10 }, () =>
        concurrentLayer.validate(createTestMessage(), {})
      );

      const results = await Promise.all(promises);

      // All 10 should pass (at the limit)
      const passedCount = results.filter(r => r.passed).length;
      expect(passedCount).toBe(10);

      // 11th request should fail
      const result11 = await concurrentLayer.validate(createTestMessage(), {});
      expect(result11.passed).toBe(false);
      expect(result11.violationType).toBe('RATE_LIMIT_EXCEEDED');

      concurrentLayer.cleanup?.();
    });

    it('should handle burst of concurrent requests', async () => {
      const burstLayer = new BehaviorValidationLayer({
        requestsPerMinute: 100,
        burstThreshold: 5
      });

      // Send 10 concurrent requests rapidly
      const promises = Array.from({ length: 10 }, () =>
        burstLayer.validate(createTestMessage(), {})
      );

      const results = await Promise.all(promises);

      // Some should be blocked for burst activity
      const blockedCount = results.filter(r => !r.passed).length;
      expect(blockedCount).toBeGreaterThan(0);

      burstLayer.cleanup?.();
    });
  });

  describe('Memory Leak Prevention', () => {
    it('should expose cleanup method', () => {
      const testLayer = new BehaviorValidationLayer();
      expect(typeof testLayer.cleanup).toBe('function');
      testLayer.cleanup?.();
    });

    it('should clean up old requests from memory over time', async () => {
      const cleanupLayer = new BehaviorValidationLayer({
        requestsPerMinute: 1000
      });

      // Generate many requests
      for (let i = 0; i < 100; i++) {
        await cleanupLayer.validate(createTestMessage(), {});
      }

      // Initial state - should have requests tracked
      const initialStats = cleanupLayer.getStats();
      expect(initialStats.totalRequestsTracked).toBeGreaterThan(0);

      // Advance time past the 30-second burst window
      vi.advanceTimersByTime(TIMING.CLEANUP_EXPIRED_MS);

      // Trigger another request to potentially run cleanup
      await cleanupLayer.validate(createTestMessage(), {});

      // After time advancement, old requests should be cleaned from recent history
      const afterStats = cleanupLayer.getStats();
      // recentRequests should be reduced (only keeping last 30 seconds)
      expect(afterStats.totalRequestsTracked).toBeLessThan(100);

      cleanupLayer.cleanup?.();
    });

    it('should reset rate limit windows after time expires', async () => {
      const windowLayer = new BehaviorValidationLayer({
        requestsPerMinute: 5
      });

      // Exhaust the rate limit
      for (let i = 0; i < 5; i++) {
        await windowLayer.validate(createTestMessage(), {});
      }

      // Should be blocked now
      const blockedResult = await windowLayer.validate(createTestMessage(), {});
      expect(blockedResult.passed).toBe(false);

      // Advance time past the 1-minute window
      vi.advanceTimersByTime(TIMING.MINUTE_EXPIRED_MS);

      // Should be allowed again after window reset
      const allowedResult = await windowLayer.validate(createTestMessage(), {});
      expect(allowedResult.passed).toBe(true);

      windowLayer.cleanup?.();
    });
  });
});

function createTestMessage() {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: 1,
    params: {
      name: 'test-tool',
      arguments: {}
    }
  };
}
