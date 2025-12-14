/**
 * Cumulative Egress Tracker
 *
 * Tracks total data sent per session and enforces limits.
 * Useful for preventing data exfiltration.
 */

// Simple validation result type compatible with Layer 5
interface SimpleValidationResult {
  passed: boolean;
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  reason?: string;
  violationType?: string;
}

export interface EgressTrackerConfig {
  maxBytesPerSession: number;
  maxBytesPerRequest: number;
  alertThreshold: number; // Alert when this % of limit reached
  onAlert?: (sessionId: string, bytesUsed: number, limit: number) => void;
}

interface EgressContext {
  sessionId?: string;
}

// In-memory storage for session egress data
const sessionEgress = new Map<string, {
  totalBytes: number;
  requestCount: number;
  alertSent: boolean;
  firstRequest: number;
}>();

export function getSessionEgress(sessionId: string) {
  return sessionEgress.get(sessionId);
}

export function resetSessionEgress(sessionId: string) {
  sessionEgress.delete(sessionId);
}

export function createEgressTrackerValidator(config: EgressTrackerConfig) {
  return function egressTracker(
    response: unknown,
    _request: unknown,
    context: unknown
  ): SimpleValidationResult {
    const ctx = context as EgressContext;
    const sessionId = ctx.sessionId || 'anonymous';

    // Calculate response size
    const responseStr = JSON.stringify(response);
    const responseBytes = Buffer.byteLength(responseStr, 'utf8');

    // Check per-request limit
    if (responseBytes > config.maxBytesPerRequest) {
      return {
        passed: false,
        severity: 'HIGH',
        reason: `Response size (${formatBytes(responseBytes)}) exceeds per-request limit (${formatBytes(config.maxBytesPerRequest)})`,
        violationType: 'EGRESS_LIMIT_EXCEEDED'
      };
    }

    // Get or create session tracking
    let session = sessionEgress.get(sessionId);
    if (!session) {
      session = {
        totalBytes: 0,
        requestCount: 0,
        alertSent: false,
        firstRequest: Date.now()
      };
      sessionEgress.set(sessionId, session);
    }

    // Check cumulative limit
    const newTotal = session.totalBytes + responseBytes;
    if (newTotal > config.maxBytesPerSession) {
      return {
        passed: false,
        severity: 'CRITICAL',
        reason: `Session egress limit exceeded (${formatBytes(newTotal)} / ${formatBytes(config.maxBytesPerSession)})`,
        violationType: 'SESSION_EGRESS_LIMIT'
      };
    }

    // Update tracking
    session.totalBytes = newTotal;
    session.requestCount++;

    // Check alert threshold
    const percentUsed = (newTotal / config.maxBytesPerSession) * 100;
    if (percentUsed >= config.alertThreshold && !session.alertSent) {
      session.alertSent = true;
      if (config.onAlert) {
        config.onAlert(sessionId, newTotal, config.maxBytesPerSession);
      }
      console.warn(
        `[Egress Alert] Session ${sessionId} has used ${percentUsed.toFixed(1)}% of egress limit`
      );
    }

    return { passed: true };
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

export function getEgressStats(sessionId: string) {
  const session = sessionEgress.get(sessionId);
  if (!session) return null;

  return {
    totalBytes: session.totalBytes,
    requestCount: session.requestCount,
    sessionDuration: Date.now() - session.firstRequest,
    formatted: formatBytes(session.totalBytes)
  };
}
