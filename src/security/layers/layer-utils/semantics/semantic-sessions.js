// src/security/layers/layer-utils/semantics/semantic-sessions.js
// Session memory management for method chaining validation
// - LRU cache with TTL for bounded memory usage
// - Tracks last method called per session for chaining rules

/**
 * Simple LRU/TTL store for session chaining memory
 * Maintains the last method called per session to enforce chaining rules
 */
export class SessionMemory {
  constructor({ maxEntries = 5000, ttlMs = 30 * 60_000 } = {}) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
    this.map = new Map(); // key -> {method, timestamp}
  }

  /**
   * Get the last method for a session
   * @param {string} key - Session identifier
   * @param {number} [now] - Current timestamp
   * @returns {string|undefined} Last method or undefined if not found/expired
   */
  get(key, now = Date.now()) {
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
   * @param {string} key - Session identifier
   * @param {string} method - Method name to store
   * @param {number} [now] - Current timestamp
   */
  set(key, method, now = Date.now()) {
    // Remove existing entry to update position
    if (this.map.has(key)) {
      this.map.delete(key);
    } else if (this.map.size >= this.maxEntries) {
      // Evict oldest entry (first in Map iteration order)
      const oldestKey = this.map.keys().next().value;
      this.map.delete(oldestKey);
    }

    this.map.set(key, { method, timestamp: now });
  }

  /**
   * Check if a session exists and is not expired
   * @param {string} key - Session identifier
   * @param {number} [now] - Current timestamp
   * @returns {boolean} True if session exists and is valid
   */
  has(key, now = Date.now()) {
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
   * @param {string} key - Session identifier
   * @returns {boolean} True if session existed and was deleted
   */
  delete(key) {
    return this.map.delete(key);
  }

  /**
   * Clear all sessions
   */
  clear() {
    this.map.clear();
  }

  /**
   * Get current number of stored sessions
   * @returns {number} Number of active sessions
   */
  size() {
    return this.map.size;
  }

  /**
   * Remove expired sessions
   * @param {number} [now] - Current timestamp
   * @returns {number} Number of sessions removed
   */
  cleanup(now = Date.now()) {
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
   * @param {number} [now] - Current timestamp
   * @returns {string[]} Array of active session keys
   */
  getActiveSessions(now = Date.now()) {
    const active = [];
    
    for (const [key, entry] of this.map) {
      if (now - entry.timestamp <= this.ttlMs) {
        active.push(key);
      }
    }
    
    return active;
  }

  /**
   * Get session statistics for monitoring
   * @param {number} [now] - Current timestamp
   * @returns {Object} Statistics about session memory usage
   */
  getStats(now = Date.now()) {
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
   * @param {Object} context - Request context
   * @returns {string} Session key for tracking
   */
  static createSessionKey(context) {
    return context?.sessionId || context?.clientId || 'global';
  }
}