/**
 * Anomaly Detector
 *
 * Detects unusual request patterns that may indicate abuse.
 * Learns baseline behavior and flags deviations.
 */

// Simple validation result type compatible with Layer 5
interface SimpleValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

export interface AnomalyDetectorConfig {
  learningPeriodMs: number;      // Time to establish baseline
  maxRequestsPerWindow: number;  // Normal request count threshold
  windowMs: number;              // Sliding window size
  toolFrequencyThreshold: number; // Max times same tool in window
  sensitiveTools: string[];      // Tools to monitor more closely
}

interface RequestRecord {
  timestamp: number;
  tool: string;
}

interface SessionBehavior {
  requests: RequestRecord[];
  learningComplete: boolean;
  startTime: number;
  baselineRpm?: number;
  toolBaseline: Map<string, number>;
}

interface MessageWithParams {
  params?: {
    name?: string;
  };
}

interface AnomalyContext {
  sessionId?: string;
}

const sessionBehaviors = new Map<string, SessionBehavior>();

export function createAnomalyDetector(config: AnomalyDetectorConfig) {
  return function anomalyDetector(
    message: unknown,
    context: unknown
  ): SimpleValidationResult {
    const ctx = context as AnomalyContext;
    const msg = message as MessageWithParams;

    const sessionId = ctx.sessionId || 'anonymous';
    const toolName = msg.params?.name || 'unknown';
    const now = Date.now();

    // Get or create session behavior
    let behavior = sessionBehaviors.get(sessionId);
    if (!behavior) {
      behavior = {
        requests: [],
        learningComplete: false,
        startTime: now,
        toolBaseline: new Map()
      };
      sessionBehaviors.set(sessionId, behavior);
    }

    // Record this request
    behavior.requests.push({ timestamp: now, tool: toolName });

    // Remove old requests outside window
    const windowStart = now - config.windowMs;
    behavior.requests = behavior.requests.filter(r => r.timestamp > windowStart);

    // Check if still in learning period
    if (!behavior.learningComplete) {
      if (now - behavior.startTime > config.learningPeriodMs) {
        // Calculate baseline
        behavior.learningComplete = true;
        behavior.baselineRpm = behavior.requests.length;

        // Calculate per-tool baseline
        for (const req of behavior.requests) {
          const count = behavior.toolBaseline.get(req.tool) || 0;
          behavior.toolBaseline.set(req.tool, count + 1);
        }
      }
      return { passed: true };
    }

    // Anomaly detection after learning period

    // Check overall request rate
    if (behavior.requests.length > config.maxRequestsPerWindow) {
      return {
        passed: false,
        severity: 'MEDIUM',
        reason: `Anomaly detected: Unusual request rate (${behavior.requests.length} requests in window)`,
        violationType: 'ANOMALY_DETECTED'
      };
    }

    // Check tool-specific frequency
    const toolCount = behavior.requests.filter(r => r.tool === toolName).length;
    if (toolCount > config.toolFrequencyThreshold) {
      // Extra scrutiny for sensitive tools
      const isSensitive = config.sensitiveTools.includes(toolName);
      const threshold = isSensitive
        ? Math.floor(config.toolFrequencyThreshold / 2)
        : config.toolFrequencyThreshold;

      if (toolCount > threshold) {
        return {
          passed: false,
          severity: isSensitive ? 'HIGH' : 'MEDIUM',
          reason: `Anomaly detected: Tool '${toolName}' called ${toolCount} times in window (threshold: ${threshold})`,
          violationType: 'TOOL_FREQUENCY_ANOMALY'
        };
      }
    }

    // Check for sudden spike compared to baseline
    if (behavior.baselineRpm) {
      const currentRate = behavior.requests.length;
      const spike = currentRate / behavior.baselineRpm;

      if (spike > 3) { // 3x baseline is suspicious
        return {
          passed: false,
          severity: 'MEDIUM',
          reason: `Anomaly detected: Request rate ${spike.toFixed(1)}x above baseline`,
          violationType: 'RATE_SPIKE_ANOMALY'
        };
      }
    }

    return { passed: true };
  };
}

export function resetSessionBehavior(sessionId: string) {
  sessionBehaviors.delete(sessionId);
}

export function getSessionBehavior(sessionId: string) {
  return sessionBehaviors.get(sessionId);
}
