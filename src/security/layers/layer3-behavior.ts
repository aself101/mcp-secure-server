/**
 * Layer 3: Behavior Validation (Simple Version)
 * Self-contained behavioral analysis with basic rate limiting and pattern detection
 * No external session dependencies - manages its own lightweight state
 */

import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import { RATE_LIMITS } from '../constants.js';

/** Layer 3 specific options */
export interface BehaviorLayerOptions extends ValidationLayerOptions {
  requestsPerMinute?: number;
  requestsPerHour?: number;
  burstThreshold?: number;
}

/** Rate limits configuration */
interface RateLimitsConfig {
  requestsPerMinute: number;
  requestsPerHour: number;
  burstThreshold: number;
}

/** Rate counter state */
interface RateCounter {
  count: number;
  windowStart: number;
}

/** Request tracking entry */
interface RequestEntry {
  timestamp: number;
  method: string;
  size: number;
}

/** Message with method field */
interface MessageWithMethod {
  method?: string;
  [key: string]: unknown;
}

/** Behavior statistics */
interface BehaviorStats {
  totalRequestsTracked: number;
  activeRateWindows: number;
  uptimeMs: number;
  memoryFootprint: {
    recentRequests: number;
    requestCounters: number;
  };
}

export default class BehaviorValidationLayer extends ValidationLayer {
  private rateLimits: RateLimitsConfig;
  private requestCounters: Map<string, RateCounter>;
  private recentRequests: RequestEntry[];
  private startTime: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null;

  constructor(options: BehaviorLayerOptions = {}) {
    super(options);

    this.rateLimits = {
      requestsPerMinute: options.requestsPerMinute ?? RATE_LIMITS.REQUESTS_PER_MINUTE,
      requestsPerHour: options.requestsPerHour ?? RATE_LIMITS.REQUESTS_PER_HOUR,
      burstThreshold: options.burstThreshold ?? RATE_LIMITS.BURST_THRESHOLD,
    };

    this.requestCounters = new Map();
    this.recentRequests = [];
    this.startTime = Date.now();
    this.cleanupTimer = null;

    this.setupCleanup();
  }

  async validate(message: unknown, context?: ValidationContext): Promise<ValidationResult> {
    return await this.validateBehavior(message, context);
  }

  private async validateBehavior(message: unknown, _context?: ValidationContext): Promise<ValidationResult> {
    const now = Date.now();
    const msg = message as MessageWithMethod;

    this.recentRequests.push({
      timestamp: now,
      method: msg.method ?? 'unknown',
      size: JSON.stringify(message).length
    });

    const checks = [
      () => this.checkGlobalRateLimit(now),
      () => this.checkBurstActivity(now),
      () => this.checkBasicAutomation(message, now)
    ];

    for (const check of checks) {
      const result = check();
      if (!result.passed) {
        return result;
      }
    }

    return this.createSuccessResult();
  }

  private checkGlobalRateLimit(now: number): ValidationResult {
    const minuteKey = 'requests-per-minute';
    const minuteResult = this.checkRateWindow(
      minuteKey,
      now,
      60000,
      this.rateLimits.requestsPerMinute
    );

    if (!minuteResult.passed) {
      return minuteResult;
    }

    const hourKey = 'requests-per-hour';
    const hourResult = this.checkRateWindow(
      hourKey,
      now,
      3600000,
      this.rateLimits.requestsPerHour
    );

    return hourResult;
  }

  private checkBurstActivity(now: number): ValidationResult {
    const thirtySecondsAgo = now - 30000;
    this.recentRequests = this.recentRequests.filter(r => r.timestamp > thirtySecondsAgo);

    const tenSecondsAgo = now - 10000;
    const burstRequests = this.recentRequests.filter(r => r.timestamp > tenSecondsAgo);

    if (burstRequests.length > this.rateLimits.burstThreshold) {
      return this.createFailureResult(
        `Burst activity detected: ${burstRequests.length} requests in 10 seconds (limit: ${this.rateLimits.burstThreshold})`,
        'HIGH',
        'BURST_ACTIVITY'
      );
    }

    return this.createSuccessResult();
  }

  private checkBasicAutomation(message: unknown, _now: number): ValidationResult {
    const msg = message as MessageWithMethod;
    const messageSize = JSON.stringify(message).length;

    if (messageSize > 20000) {
      return this.createFailureResult(
        `Suspiciously large message: ${messageSize} bytes`,
        'MEDIUM',
        'OVERSIZED_MESSAGE'
      );
    }

    if (this.recentRequests.length >= 5) {
      const recent = this.recentRequests.slice(-5);
      const intervals: number[] = [];

      for (let i = 1; i < recent.length; i++) {
        const prev = recent[i - 1];
        const curr = recent[i];
        if (prev && curr) {
          intervals.push(curr.timestamp - prev.timestamp);
        }
      }

      if (intervals.length >= 3) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) =>
          sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);

        if (stdDev < 50 && avgInterval < 2000 && avgInterval > 100) {
          return this.createFailureResult(
            `Automated timing pattern detected: ${avgInterval.toFixed(0)}ms ±${stdDev.toFixed(0)}ms`,
            'MEDIUM',
            'AUTOMATED_TIMING'
          );
        }
      }
    }

    if (msg.method && this.looksLikeProbing(msg.method)) {
      return this.createFailureResult(
        `Suspicious method pattern: ${msg.method}`,
        'LOW',
        'SUSPICIOUS_METHOD'
      );
    }

    return this.createSuccessResult();
  }

  private checkRateWindow(key: string, now: number, windowMs: number, limit: number): ValidationResult {
    let counter = this.requestCounters.get(key);

    if (!counter) {
      counter = { count: 0, windowStart: now };
      this.requestCounters.set(key, counter);
    }

    if (now - counter.windowStart >= windowMs) {
      counter.count = 0;
      counter.windowStart = now;
    }

    counter.count++;

    if (counter.count > limit) {
      const windowName = windowMs === 60000 ? 'minute' : 'hour';
      return this.createFailureResult(
        `Rate limit exceeded: ${counter.count} requests per ${windowName} (limit: ${limit})`,
        'HIGH',
        'RATE_LIMIT_EXCEEDED'
      );
    }

    return this.createSuccessResult();
  }

  private looksLikeProbing(method: string): boolean {
    const probingPatterns = [
      /^(test|probe|check|scan|enum)/i,
      /^(list|get|read).*config/i,
      /^(list|get|read).*secret/i,
      /^(list|get|read).*key/i,
      /(admin|root|sudo|system)/i
    ];

    return probingPatterns.some(pattern => pattern.test(method));
  }

  private setupCleanup(): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();

      const oneHourAgo = now - 3600000;
      this.recentRequests = this.recentRequests.filter(r => r.timestamp > oneHourAgo);

      for (const [key, counter] of this.requestCounters.entries()) {
        if (now - counter.windowStart > 7200000) {
          this.requestCounters.delete(key);
        }
      }
    }, RATE_LIMITS.CLEANUP_INTERVAL_MS);

    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  cleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.recentRequests = [];
    this.requestCounters.clear();
  }

  getStats(): BehaviorStats {
    return {
      totalRequestsTracked: this.recentRequests.length,
      activeRateWindows: this.requestCounters.size,
      uptimeMs: Date.now() - this.startTime,
      memoryFootprint: {
        recentRequests: this.recentRequests.length,
        requestCounters: this.requestCounters.size
      }
    };
  }
}
