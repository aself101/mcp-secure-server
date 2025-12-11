/**
 * Session memory management for method chaining validation
 * - LRU cache with TTL for bounded memory usage
 * - Tracks last method called per session for chaining rules
 */

/** Session entry stored in the map */
interface SessionEntry {
  method: string;
  timestamp: number;
}

/** Constructor options for SessionMemory */
export interface SessionMemoryOptions {
  maxEntries?: number;
  ttlMs?: number;
}

/** Session statistics for monitoring */
export interface SessionStats {
  total: number;
  active: number;
  expired: number;
  maxEntries: number;
  ttlMs: number;
  utilizationPercent: number;
}

/** Context for creating session keys */
export interface SessionContext {
  sessionId?: string;
  clientId?: string;
}

/**
 * Simple LRU/TTL store for session chaining memory
 * Maintains the last method called per session to enforce chaining rules
 */
export class SessionMemory {
  private maxEntries: number;
  private ttlMs: number;
  private map: Map<string, SessionEntry>;

  constructor({ maxEntries = 5000, ttlMs = 30 * 60_000 }: SessionMemoryOptions = {}) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
    this.map = new Map();
  }

  /**
   * Get the last method for a session
   */
  get(key: string, now = Date.now()): string | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;

    // Check if entry has expired
    if (now - entry.timestamp > this.ttlMs) {
      this.map.delete(key);
      return undefined;
    }

    // Move to end for LRU (refresh position)
    this.map.delete(key);
    this.map.set(key, entry);

    return entry.method;
  }

  /**
   * Set the last method for a session
   */
  set(key: string, method: string, now = Date.now()): void {
    // Remove existing entry to update position
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxEntries) {
      // Evict oldest entry (first in Map iteration order)
      const oldestKey = this.map.keys().next().value;
      if (oldestKey !== undefined) {
        this.map.delete(oldestKey);
      }
    }

    this.map.set(key, { method, timestamp: now });
  }

  /**
   * Check if a session exists and is not expired
   */
  has(key: string, now = Date.now()): boolean {
    const entry = this.map.get(key);
    if (!entry) return false;

    if (now - entry.timestamp > this.ttlMs) {
      this.map.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Delete a specific session
   */
  delete(key: string): boolean {
    return this.map.delete(key);
  }

  /**
   * Clear all sessions
   */
  clear(): void {
    this.map.clear();
  }

  /**
   * Get current number of stored sessions
   */
  size(): number {
    return this.map.size;
  }

  /**
   * Remove expired sessions
   */
  cleanup(now = Date.now()): number {
    let removed = 0;

    for (const [key, entry] of this.map) {
      if (now - entry.timestamp > this.ttlMs) {
        this.map.delete(key);
        removed++;
      }
    }

    return removed;
  }

  /**
   * Get all active session keys (for debugging/monitoring)
   */
  getActiveSessions(now = Date.now()): string[] {
    const active: string[] = [];

    for (const [key, entry] of this.map) {
      if (now - entry.timestamp <= this.ttlMs) {
        active.push(key);
      }
    }

    return active;
  }

  /**
   * Get session statistics for monitoring
   */
  getStats(now = Date.now()): SessionStats {
    let active = 0;
    let expired = 0;

    for (const [, entry] of this.map) {
      if (now - entry.timestamp <= this.ttlMs) {
        active++;
      } else {
        expired++;
      }
    }

    return {
      total: this.map.size,
      active,
      expired,
      maxEntries: this.maxEntries,
      ttlMs: this.ttlMs,
      utilizationPercent: Math.round((this.map.size / this.maxEntries) * 100)
    };
  }

  /**
   * Create a new session key from context information
   */
  static createSessionKey(context: SessionContext | null | undefined): string {
    return context?.sessionId || context?.clientId || 'global';
  }
}
