// src/security/layers/layer3-behavior.js

import { ValidationLayer } from './validation-layer-base.js';
import { RATE_LIMITS } from '../constants.js';

/**
 * Layer 3: Behavior Validation (Simple Version)
 * Self-contained behavioral analysis with basic rate limiting and pattern detection
 * No external session dependencies - manages its own lightweight state
 */
export default class BehaviorValidationLayer extends ValidationLayer {
    constructor(options = {}) {
        super(options);
        
        // Simple rate limiting configuration
        this.rateLimits = {
            requestsPerMinute: options.requestsPerMinute || RATE_LIMITS.REQUESTS_PER_MINUTE,
            requestsPerHour: options.requestsPerHour || RATE_LIMITS.REQUESTS_PER_HOUR,
            burstThreshold: options.burstThreshold || RATE_LIMITS.BURST_THRESHOLD,
        };
        
        // Self-managed lightweight state
        this.requestCounters = new Map(); // rate limit windows
        this.recentRequests = []; // sliding window for burst detection
        this.startTime = Date.now();
        
        // Cleanup interval to prevent memory leaks
        this.setupCleanup();
    }

    /**
     * Main validation entry point for Layer 3
     * Currently implements just validateBehavior - more methods coming in future iterations
     */
    async validate(message, context) {
        return await this.validateBehavior(message, context);
    }

    /**
     * Simple behavioral validation with self-contained state management
     * Handles: global rate limiting, burst detection, basic automation indicators
     */
    async validateBehavior(message, context) {
        const now = Date.now();
        
        // Track this request for burst analysis
        this.recentRequests.push({
            timestamp: now,
            method: message.method,
            size: JSON.stringify(message).length
        });
        
        // Validation checks (fail-fast)
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
        
        // All checks passed
        return this.createSuccessResult();
    }

    /**
     * Global rate limiting - simple per-minute and per-hour windows
     */
    checkGlobalRateLimit(now) {
        // Per-minute rate limiting
        const minuteKey = 'requests-per-minute';
        const minuteResult = this.checkRateWindow(
            minuteKey, 
            now, 
            60000, // 1 minute window
            this.rateLimits.requestsPerMinute
        );
        
        if (!minuteResult.passed) {
            return minuteResult;
        }
        
        // Per-hour rate limiting
        const hourKey = 'requests-per-hour';
        const hourResult = this.checkRateWindow(
            hourKey,
            now,
            3600000, // 1 hour window  
            this.rateLimits.requestsPerHour
        );
        
        return hourResult;
    }

    /**
     * Burst activity detection - too many requests in short time
     */
    checkBurstActivity(now) {
        // Clean up old requests (keep only last 30 seconds for burst detection)
        const thirtySecondsAgo = now - 30000;
        this.recentRequests = this.recentRequests.filter(r => r.timestamp > thirtySecondsAgo);
        
        // Check for burst in last 10 seconds
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

    /**
     * Basic automation detection - simple patterns that indicate non-human behavior
     */
    checkBasicAutomation(message, now) {
        // Check for suspiciously large messages (possible automated data dumps)
        const messageSize = JSON.stringify(message).length;
        if (messageSize > 20000) { // 20KB threshold
            return this.createFailureResult(
                `Suspiciously large message: ${messageSize} bytes`,
                'MEDIUM',
                'OVERSIZED_MESSAGE'
            );
        }
        
        // Check recent request timing patterns (if we have enough history)
        if (this.recentRequests.length >= 5) {
            const recent = this.recentRequests.slice(-5); // Last 5 requests
            const intervals = [];
            
            for (let i = 1; i < recent.length; i++) {
                intervals.push(recent[i].timestamp - recent[i-1].timestamp);
            }
            
            // Check for suspiciously regular timing (possible bot behavior)
            if (intervals.length >= 3) {
                const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
                const variance = intervals.reduce((sum, interval) => 
                    sum + Math.pow(interval - avgInterval, 2), 0) / intervals.length;
                const stdDev = Math.sqrt(variance);
                
                // Very regular timing under 2 seconds is suspicious
                if (stdDev < 50 && avgInterval < 2000 && avgInterval > 100) {
                    return this.createFailureResult(
                        `Automated timing pattern detected: ${avgInterval.toFixed(0)}ms ±${stdDev.toFixed(0)}ms`,
                        'MEDIUM',
                        'AUTOMATED_TIMING'
                    );
                }
            }
        }
        
        // Check for method name patterns that might indicate probing
        if (message.method && this.looksLikeProbing(message.method)) {
            return this.createFailureResult(
                `Suspicious method pattern: ${message.method}`,
                'LOW',
                'SUSPICIOUS_METHOD'
            );
        }
        
        return this.createSuccessResult();
    }

    /**
     * Helper: Check rate limit for a specific window
     */
    checkRateWindow(key, now, windowMs, limit) {
        if (!this.requestCounters.has(key)) {
            this.requestCounters.set(key, { count: 0, windowStart: now });
        }
        
        const counter = this.requestCounters.get(key);
        
        // Reset window if expired
        if (now - counter.windowStart >= windowMs) {
            counter.count = 0;
            counter.windowStart = now;
        }
        
        // Increment counter
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

    /**
     * Helper: Detect method names that might indicate system probing
     */
    looksLikeProbing(method) {
        const probingPatterns = [
            /^(test|probe|check|scan|enum)/i,
            /^(list|get|read).*config/i,
            /^(list|get|read).*secret/i,
            /^(list|get|read).*key/i,
            /(admin|root|sudo|system)/i
        ];
        
        return probingPatterns.some(pattern => pattern.test(method));
    }

    /**
     * Periodic cleanup to prevent memory leaks
     */
    setupCleanup() {
        this.cleanupTimer = setInterval(() => {
            const now = Date.now();

            // Clean old request history (keep only last hour)
            const oneHourAgo = now - 3600000;
            this.recentRequests = this.recentRequests.filter(r => r.timestamp > oneHourAgo);

            // Clean expired rate limit windows
            for (const [key, counter] of this.requestCounters.entries()) {
                // If window is more than 2 hours old, remove it
                if (now - counter.windowStart > 7200000) {
                    this.requestCounters.delete(key);
                }
            }
        }, RATE_LIMITS.CLEANUP_INTERVAL_MS); // Cleanup every 1 minute

        // Allow Node.js to exit if this is the only remaining timer
        if (this.cleanupTimer.unref) {
            this.cleanupTimer.unref();
        }
    }

    /**
     * Cleanup resources when layer is destroyed
     */
    cleanup() {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = null;
        }
        this.recentRequests = [];
        this.requestCounters.clear();
    }

    /**
     * Get current behavior stats for debugging/monitoring
     */
    getStats() {
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