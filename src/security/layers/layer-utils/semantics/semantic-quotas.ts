/**
 * Quota management for semantic validation
 * - Pluggable QuotaProvider interface for different storage backends
 * - In-memory implementation with windowed counters and automatic cleanup
 */

/** Rate limits configuration */
export interface QuotaLimits {
  minute?: number;
  hour?: number;
}

/** Result from quota check */
export interface QuotaResult {
  passed: boolean;
  reason?: string;
}

/** Window counter entry */
interface WindowEntry {
  count: number;
  windowStart: number;
}

/** Bucket entry containing window counters */
interface BucketEntry {
  minute?: WindowEntry;
  hour?: WindowEntry;
}

/** Constructor options for InMemoryQuotaProvider */
export interface InMemoryQuotaOptions {
  clockSkewMs?: number;
  sweepIntervalMs?: number;
}

/**
 * QuotaProvider interface for managing rate limits and usage quotas
 */
export class QuotaProvider {
  /**
   * Increment usage counter and check against limits
   */
  incrementAndCheck(_key: string, _limits: QuotaLimits = {}, _nowMs = Date.now()): QuotaResult {
    throw new Error('incrementAndCheck must be implemented by QuotaProvider subclass');
  }

  /**
   * Optional cleanup method for removing stale quota data
   */
  sweep(_nowMs = Date.now()): void {
    // Default implementation does nothing
  }
}

/**
 * In-memory quota provider with automatic cleanup
 * Uses sliding window counters for minute and hour limits
 */
export class InMemoryQuotaProvider extends QuotaProvider {
  private clockSkewMs: number;
  private counters: Map<string, BucketEntry>;
  private timer: ReturnType<typeof setInterval> | null;

  constructor({ clockSkewMs = 1000, sweepIntervalMs = 30_000 }: InMemoryQuotaOptions = {}) {
    super();
    this.clockSkewMs = clockSkewMs;
    this.counters = new Map();

    // Setup automatic cleanup timer
    this.timer = setInterval(() => this.sweep(Date.now()), sweepIntervalMs);
    // Unref to allow process to exit
    if (this.timer.unref) this.timer.unref();
  }

  incrementAndCheck(key: string, { minute, hour }: QuotaLimits = {}, now = Date.now()): QuotaResult {
    if (minute) {
      const minuteResult = this.checkWindow(key, 'minute', minute, 60_000, now);
      if (!minuteResult.passed) return minuteResult;
    }

    if (hour) {
      const hourResult = this.checkWindow(key, 'hour', hour, 3_600_000, now);
      if (!hourResult.passed) return hourResult;
    }

    return { passed: true };
  }

  private checkWindow(key: string, bucket: 'minute' | 'hour', limit: number, windowMs: number, now: number): QuotaResult {
    const entry = this.ensureEntry(key, bucket, now);

    // Reset window if expired
    if (now - entry.windowStart > windowMs + this.clockSkewMs) {
      entry.count = 0;
      entry.windowStart = now;
    }

    // Check BEFORE increment to prevent race condition
    // Even in single-threaded Node.js, checking first is safer and clearer
    if (entry.count >= limit) {
      const bucketName = bucket === 'minute' ? 'minute' : 'hour';
      return {
        passed: false,
        reason: `Per-${bucketName} quota exceeded for ${key}: ${entry.count}/${limit}`
      };
    }

    // Increment counter after successful check
    entry.count += 1;

    return { passed: true };
  }

  private ensureEntry(key: string, bucket: 'minute' | 'hour', now: number): WindowEntry {
    if (!this.counters.has(key)) {
      this.counters.set(key, {});
    }

    const keyEntry = this.counters.get(key)!;
    if (!keyEntry[bucket]) {
      keyEntry[bucket] = { count: 0, windowStart: now };
    }

    return keyEntry[bucket]!;
  }

  sweep(now = Date.now()): void {
    const minuteExpiry = 120_000 + this.clockSkewMs; // 2 minutes
    const hourExpiry = 7_200_000 + this.clockSkewMs; // 2 hours

    for (const [key, entry] of this.counters) {
      const minuteEntry = entry.minute;
      const hourEntry = entry.hour;

      const minuteStale = !minuteEntry || (now - minuteEntry.windowStart > minuteExpiry);
      const hourStale = !hourEntry || (now - hourEntry.windowStart > hourExpiry);

      if (minuteStale && hourStale) {
        this.counters.delete(key);
      } else {
        // Clean up individual expired buckets
        if (minuteStale && minuteEntry) delete entry.minute;
        if (hourStale && hourEntry) delete entry.hour;
      }
    }
  }

  /**
   * Get current quota usage for debugging/monitoring
   */
  getUsage(key: string): { minute: number; hour: number } {
    const entry = this.counters.get(key);
    if (!entry) return { minute: 0, hour: 0 };

    const now = Date.now();
    return {
      minute: entry.minute && (now - entry.minute.windowStart <= 60_000 + this.clockSkewMs)
        ? entry.minute.count : 0,
      hour: entry.hour && (now - entry.hour.windowStart <= 3_600_000 + this.clockSkewMs)
        ? entry.hour.count : 0
    };
  }

  /**
   * Get total number of tracked quota keys
   */
  getActiveKeys(): number {
    return this.counters.size;
  }

  /**
   * Clear all quota data (useful for testing)
   */
  clear(): void {
    this.counters.clear();
  }

  /**
   * Cleanup resources when provider is no longer needed
   */
  destroy(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.clear();
  }
}
