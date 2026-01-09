/**
 * Type definitions for security logger
 * @module security-logger-types
 */

/** Logger options */
export interface SecurityLoggerOptions {
  logLevel?: string;
  [key: string]: unknown;
}

/** Security decision for logging */
export interface SecurityDecision {
  passed?: boolean;
  allowed?: boolean;
  severity?: string;
  violationType?: string | null;
  reason?: string;
  confidence?: number;
  layerName?: string;
  validationTime?: number;
  /** Name of the specific pattern that matched */
  patternName?: string;
  /** Category of the matched pattern */
  patternCategory?: string;
  /** Layer number (1-5) that detected the issue */
  layerNumber?: number;
}

/** Message for logging */
export interface LoggableMessage {
  method?: string;
  params?: Record<string, unknown>;
  [key: string]: unknown;
}

/** Log context */
export interface LogContext {
  canonical?: string;
  [key: string]: unknown;
}

/** Layer statistics */
export interface LayerStats {
  passed: number;
  blocked: number;
}

/** Security statistics */
export interface SecurityStats {
  totalRequests: number;
  totalBlocked: number;
  totalAllowed: number;
  blockRate: string;
  passRate: string;
  layerStats: Record<string, LayerStats>;
  logLevel: string;
  logFiles: {
    decisions: string;
    blocks: string;
    performance: string;
    debug: string;
  };
}

/** Security report */
export interface SecurityReport {
  summary: SecurityStats;
  timestamp: string;
  testDuration: number;
  logFiles: SecurityStats['logFiles'];
  recommendations: string[];
}

/** Log file verification result */
export interface LogFileResult {
  exists: boolean;
  size?: number;
  error?: string;
}
