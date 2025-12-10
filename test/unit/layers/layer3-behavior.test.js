import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import BehaviorValidationLayer from '@/security/layers/layer3-behavior.js';

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
      vi.advanceTimersByTime(61000);

      // Should be allowed again
      result = await layer.validate(message, {});
      expect(result.passed).toBe(true);
    });
  });

  describe('Burst Detection', () => {
    it('should detect burst activity', async () => {
      const message = createTestMessage();

      // Send rapid requests within burst detection window (10 seconds)
      for (let i = 0; i < 5; i++) {
        await layer.validate(message, {});
        vi.advanceTimersByTime(100); // 100ms between requests
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
        vi.advanceTimersByTime(3000); // 3 seconds between requests
      }
    });
  });

  describe('Automation Detection', () => {
    it('should detect identical rapid requests', async () => {
      const message = createTestMessage();

      // Send identical requests rapidly
      for (let i = 0; i < 6; i++) {
        await layer.validate(message, {});
        vi.advanceTimersByTime(50); // Very rapid
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
        vi.advanceTimersByTime(10000); // 10 seconds between requests
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
      vi.advanceTimersByTime(35000);

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
      vi.advanceTimersByTime(61000);

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
