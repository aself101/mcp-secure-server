// src/security/layers/layer-utils/semantics/semantic-quotas.js
// Quota management for semantic validation
// - Pluggable QuotaProvider interface for different storage backends
// - In-memory implementation with windowed counters and automatic cleanup

/**
 * QuotaProvider interface for managing rate limits and usage quotas
 * @interface
 */
export class QuotaProvider {
  /**
   * Increment usage counter and check against limits
   * @param {string} key - Quota identifier (e.g., "tool:calculator", "method:resources/read")
   * @param {Object} limits - Rate limits
   * @param {number} [limits.minute] - Requests per minute limit
   * @param {number} [limits.hour] - Requests per hour limit
   * @param {number} [nowMs] - Current timestamp
   * @returns {Object} Result with passed boolean and optional reason
   */
  incrementAndCheck(key, _limits = {}, _nowMs = Date.now()) {
    throw new Error('incrementAndCheck must be implemented by QuotaProvider subclass');
  }

  /**
   * Optional cleanup method for removing stale quota data
   * @param {number} [_nowMs] - Current timestamp
   */
  sweep(_nowMs = Date.now()) {
    // Default implementation does nothing
  }
}

/**
 * In-memory quota provider with automatic cleanup
 * Uses sliding window counters for minute and hour limits
 */
export class InMemoryQuotaProvider extends QuotaProvider {
  constructor({ clockSkewMs = 1000, sweepIntervalMs = 30_000 } = {}) {
    super();
    this.clockSkewMs = clockSkewMs;
    this.counters = new Map(); // key -> { minute?: {count, windowStart}, hour?: {...} }
    
    // Setup automatic cleanup timer
    this.timer = setInterval(() => this.sweep(Date.now()), sweepIntervalMs);
    // Unref to allow process to exit
    if (this.timer.unref) this.timer.unref();
  }

  incrementAndCheck(key, { minute, hour } = {}, now = Date.now()) {
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

  checkWindow(key, bucket, limit, windowMs, now) {
    const entry = this.ensureEntry(key, bucket, now);
    
    // Reset window if expired
    if (now - entry.windowStart > windowMs + this.clockSkewMs) {
      entry.count = 0;
      entry.windowStart = now;
    }
    
    // Increment counter (atomic within single-threaded event loop)
    entry.count += 1;
    
    if (entry.count > limit) {
      const bucketName = bucket === 'minute' ? 'minute' : 'hour';
      return {
        passed: false,
        reason: `Per-${bucketName} quota exceeded for ${key}: ${entry.count}/${limit}`
      };
    }
    
    return { passed: true };
  }

  ensureEntry(key, bucket, now) {
    if (!this.counters.has(key)) {
      this.counters.set(key, {});
    }
    
    const keyEntry = this.counters.get(key);
    if (!keyEntry[bucket]) {
      keyEntry[bucket] = { count: 0, windowStart: now };
    }
    
    return keyEntry[bucket];
  }

  sweep(now = Date.now()) {
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
   * @param {string} key - Quota key to check
   * @returns {Object} Usage statistics
   */
  getUsage(key) {
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
   * @returns {number} Number of active quota keys
   */
  getActiveKeys() {
    return this.counters.size;
  }

  /**
   * Clear all quota data (useful for testing)
   */
  clear() {
    this.counters.clear();
  }

  /**
   * Cleanup resources when provider is no longer needed
   */
  destroy() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.clear();
  }
}