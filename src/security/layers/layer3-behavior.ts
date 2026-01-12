/**
 * Layer 3: Behavior Validation (Simple Version)
 * Self-contained behavioral analysis with basic rate limiting and pattern detection
 * No external session dependencies - manages its own lightweight state
 */

import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import { RATE_LIMITS, AUTOMATION_DETECTION } from '../constants.js';

/** Automation detection options */
export interface AutomationDetectionOptions {
  enabled?: boolean;
  sampleSize?: number;
  maxVariance?: number;
  minInterval?: number;
  maxInterval?: number;
}

/** Layer 3 specific options */
export interface BehaviorLayerOptions extends ValidationLayerOptions {
  requestsPerMinute?: number;
  requestsPerHour?: number;
  burstThreshold?: number;
  burstWindowMs?: number;
  suspiciousMessageSize?: number;
  automationDetection?: AutomationDetectionOptions;
}

/** Rate limits configuration */
interface RateLimitsConfig {
  requestsPerMinute: number;
  requestsPerHour: number;
  burstThreshold: number;
  burstWindowMs: number;
  suspiciousMessageSize: number;
}

/** Resolved automation detection config */
interface AutomationConfig {
  enabled: boolean;
  sampleSize: number;
  maxVariance: number;
  minInterval: number;
  maxInterval: number;
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
  private automationConfig: AutomationConfig;
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
      burstWindowMs: options.burstWindowMs ?? RATE_LIMITS.BURST_WINDOW_MS,
      suspiciousMessageSize: options.suspiciousMessageSize ?? RATE_LIMITS.SUSPICIOUS_MESSAGE_SIZE,
    };

    const autoOpts = options.automationDetection ?? {};
    this.automationConfig = {
      enabled: autoOpts.enabled ?? AUTOMATION_DETECTION.ENABLED,
      sampleSize: autoOpts.sampleSize ?? AUTOMATION_DETECTION.SAMPLE_SIZE,
      maxVariance: autoOpts.maxVariance ?? AUTOMATION_DETECTION.MAX_VARIANCE,
      minInterval: autoOpts.minInterval ?? AUTOMATION_DETECTION.MIN_INTERVAL,
      maxInterval: autoOpts.maxInterval ?? AUTOMATION_DETECTION.MAX_INTERVAL,
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
    const messageSize = JSON.stringify(message).length;

    this.recentRequests.push({
      timestamp: now,
      method: msg.method ?? 'unknown',
      size: messageSize
    });

    const checks = [
      () => this.checkGlobalRateLimit(now),
      () => this.checkBurstActivity(now),
      () => this.checkBasicAutomation(messageSize, msg.method, now)
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
    // Keep requests for 3x the burst window for analysis
    const retentionWindow = now - (this.rateLimits.burstWindowMs * 3);
    this.recentRequests = this.recentRequests.filter(r => r.timestamp > retentionWindow);

    const burstWindowStart = now - this.rateLimits.burstWindowMs;
    const burstRequests = this.recentRequests.filter(r => r.timestamp > burstWindowStart);

    if (burstRequests.length > this.rateLimits.burstThreshold) {
      const windowSeconds = Math.round(this.rateLimits.burstWindowMs / 1000);
      return this.createFailureResult(
        `Burst activity detected: ${burstRequests.length} requests in ${windowSeconds} seconds (limit: ${this.rateLimits.burstThreshold})`,
        'HIGH',
        'BURST_ACTIVITY'
      );
    }

    return this.createSuccessResult();
  }

  private checkBasicAutomation(messageSize: number, method: string | undefined, _now: number): ValidationResult {
    if (messageSize > this.rateLimits.suspiciousMessageSize) {
      return this.createFailureResult(
        `Suspiciously large message: ${messageSize} bytes (limit: ${this.rateLimits.suspiciousMessageSize})`,
        'MEDIUM',
        'OVERSIZED_MESSAGE'
      );
    }

    // Skip automation detection if disabled
    if (!this.automationConfig.enabled) {
      return this.createSuccessResult();
    }

    const { sampleSize, maxVariance, minInterval, maxInterval } = this.automationConfig;

    if (sampleSize > 0 && this.recentRequests.length >= sampleSize) {
      const recent = this.recentRequests.slice(-sampleSize);
      const intervals: number[] = [];

      for (let i = 1; i < recent.length; i++) {
        const prev = recent[i - 1];
        const curr = recent[i];
        if (prev && curr) {
          intervals.push(curr.timestamp - prev.timestamp);
        }
      }

      // Need at least 2 intervals to calculate meaningful variance
      if (intervals.length >= Math.max(2, sampleSize - 2)) {
        const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
        const variance = intervals.reduce((sum, interval) =>
          sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
        const stdDev = Math.sqrt(variance);

        if (stdDev < maxVariance && avgInterval < maxInterval && avgInterval > minInterval) {
          return this.createFailureResult(
            `Automated timing pattern detected: ${avgInterval.toFixed(0)}ms ±${stdDev.toFixed(0)}ms`,
            'MEDIUM',
            'AUTOMATED_TIMING'
          );
        }
      }
    }

    if (method && this.looksLikeProbing(method)) {
      return this.createFailureResult(
        `Suspicious method pattern: ${method}`,
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
