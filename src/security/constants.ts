/**
 * Centralized configuration constants for the MCP Security Framework.
 */

/** Message and parameter size limits */
export const LIMITS = {
  /** Maximum message size in bytes (50KB) */
  MESSAGE_SIZE_MAX: 50_000,
  /** Minimum valid message size in bytes */
  MESSAGE_SIZE_MIN: 10,
  /** Maximum number of parameters (recursive key count) */
  PARAM_COUNT_MAX: 100,
  /** Maximum string parameter length */
  STRING_LENGTH_MAX: 5_000,
  /** Maximum method name length */
  METHOD_NAME_MAX: 100,
  /** Maximum allowed control characters */
  CONTROL_CHARS_MAX: 10,
} as const;

/** Rate limiting configuration */
export const RATE_LIMITS = {
  /** Maximum requests per minute */
  REQUESTS_PER_MINUTE: 30,
  /** Maximum requests per hour */
  REQUESTS_PER_HOUR: 500,
  /** Maximum requests in burst window */
  BURST_THRESHOLD: 10,
  /** Burst detection window in ms (10 seconds) */
  BURST_WINDOW_MS: 10_000,
  /** Message size threshold for suspicious activity in bytes */
  SUSPICIOUS_MESSAGE_SIZE: 20_000,
  /** Cleanup interval in ms (1 minute) */
  CLEANUP_INTERVAL_MS: 60_000,
} as const;

/** Automation detection configuration */
export const AUTOMATION_DETECTION = {
  /** Enable automation detection by default */
  ENABLED: true,
  /** Number of recent requests to analyze */
  SAMPLE_SIZE: 5,
  /** Maximum timing variance in ms to flag as automated */
  MAX_VARIANCE: 50,
  /** Minimum interval in ms for automation detection */
  MIN_INTERVAL: 100,
  /** Maximum interval in ms for automation detection */
  MAX_INTERVAL: 2_000,
} as const;

/** Logging configuration */
export const LOGGING = {
  /** Maximum log file size in bytes (10MB) */
  MAX_FILE_SIZE: 10_485_760,
  /** Maximum number of log files to retain */
  MAX_FILES: 5,
} as const;

/** Type for LIMITS constant */
export type Limits = typeof LIMITS;

/** Type for RATE_LIMITS constant */
export type RateLimits = typeof RATE_LIMITS;

/** Type for LOGGING constant */
export type LoggingConfig = typeof LOGGING;

/** Type for AUTOMATION_DETECTION constant */
export type AutomationDetectionConfig = typeof AUTOMATION_DETECTION;
