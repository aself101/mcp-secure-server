/**
 * IP-based rate limiter for error responses.
 * Prevents attackers from probing the server with invalid requests
 * that bypass the validation pipeline.
 */

import { RATE_LIMITS } from '../constants.js';

/** Rate counter for tracking errors per IP */
interface ErrorCounter {
  count: number;
  windowStart: number;
}

/** Error rate limiter options */
export interface ErrorRateLimiterOptions {
  /** Maximum errors per minute per IP (default: 20) */
  errorsPerMinute?: number;
  /** Maximum errors per hour per IP (default: 100) */
  errorsPerHour?: number;
  /** Cleanup interval in ms (default: 60000) */
  cleanupIntervalMs?: number;
}

/**
 * Rate limiter for error responses.
 * Tracks error counts by client IP to prevent probing attacks
 * that bypass the validation pipeline.
 */
export class ErrorRateLimiter {
  private minuteCounters: Map<string, ErrorCounter>;
  private hourCounters: Map<string, ErrorCounter>;
  private errorsPerMinute: number;
  private errorsPerHour: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null;

  constructor(options: ErrorRateLimiterOptions = {}) {
    this.errorsPerMinute = options.errorsPerMinute ?? 20;
    this.errorsPerHour = options.errorsPerHour ?? 100;
    this.minuteCounters = new Map();
    this.hourCounters = new Map();
    this.cleanupTimer = null;
    this.setupCleanup(options.cleanupIntervalMs ?? RATE_LIMITS.CLEANUP_INTERVAL_MS);
  }

  /**
   * Check if the client IP should be rate limited for errors.
   * Call this before returning early error responses.
   *
   * @param clientIp - Client IP address
   * @returns true if the request should be rate limited (return 429)
   */
  shouldRateLimit(clientIp: string): boolean {
    const now = Date.now();

    // Check minute window
    if (this.checkWindow(this.minuteCounters, clientIp, now, 60000, this.errorsPerMinute)) {
      return true;
    }

    // Check hour window
    if (this.checkWindow(this.hourCounters, clientIp, now, 3600000, this.errorsPerHour)) {
      return true;
    }

    return false;
  }

  /**
   * Record an error for the client IP.
   * Call this after returning an error response.
   *
   * @param clientIp - Client IP address
   */
  recordError(clientIp: string): void {
    const now = Date.now();
    this.incrementCounter(this.minuteCounters, clientIp, now, 60000);
    this.incrementCounter(this.hourCounters, clientIp, now, 3600000);
  }

  private checkWindow(
    counters: Map<string, ErrorCounter>,
    clientIp: string,
    now: number,
    windowMs: number,
    limit: number
  ): boolean {
    const counter = counters.get(clientIp);
    if (!counter) return false;

    // Reset if window has passed
    if (now - counter.windowStart >= windowMs) {
      return false;
    }

    return counter.count >= limit;
  }

  private incrementCounter(
    counters: Map<string, ErrorCounter>,
    clientIp: string,
    now: number,
    windowMs: number
  ): void {
    let counter = counters.get(clientIp);

    if (!counter || now - counter.windowStart >= windowMs) {
      counter = { count: 0, windowStart: now };
      counters.set(clientIp, counter);
    }

    counter.count++;
  }

  private setupCleanup(intervalMs: number): void {
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();

      // Clean minute counters older than 2 minutes
      for (const [ip, counter] of this.minuteCounters.entries()) {
        if (now - counter.windowStart > 120000) {
          this.minuteCounters.delete(ip);
        }
      }

      // Clean hour counters older than 2 hours
      for (const [ip, counter] of this.hourCounters.entries()) {
        if (now - counter.windowStart > 7200000) {
          this.hourCounters.delete(ip);
        }
      }
    }, intervalMs);

    if (this.cleanupTimer.unref) {
      this.cleanupTimer.unref();
    }
  }

  /** Stop the cleanup timer and clear all counters */
  cleanup(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.minuteCounters.clear();
    this.hourCounters.clear();
  }

  /** Get statistics for monitoring */
  getStats(): { minuteTracked: number; hourTracked: number } {
    return {
      minuteTracked: this.minuteCounters.size,
      hourTracked: this.hourCounters.size
    };
  }
}

/**
 * Extract client IP from request, considering proxied environments.
 * @param req - HTTP request with headers
 * @returns Client IP address
 */
export function getClientIp(req: { headers: Record<string, string | string[] | undefined>; socket?: { remoteAddress?: string } }): string {
  // Check X-Forwarded-For header (used by proxies/load balancers)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const forwardedStr = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    // Take the first IP in the chain (original client)
    const clientIp = forwardedStr?.split(',')[0]?.trim();
    if (clientIp) return clientIp;
  }

  // Check X-Real-IP header (nginx)
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    const realIpStr = Array.isArray(realIp) ? realIp[0] : realIp;
    if (realIpStr) return realIpStr;
  }

  // Fall back to socket remote address
  return req.socket?.remoteAddress ?? 'unknown';
}
