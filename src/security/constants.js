// src/security/constants.js
// Centralized configuration constants for the MCP Security Framework

export const LIMITS = {
  MESSAGE_SIZE_MAX: 50_000,      // 50KB max message size
  MESSAGE_SIZE_MIN: 10,          // Minimum valid message size (bytes)
  PARAM_COUNT_MAX: 20,           // Maximum number of parameters
  STRING_LENGTH_MAX: 5_000,      // Maximum string parameter length
  REQUEST_SIZE_MAX: 10_000,      // Maximum request size for middleware
  METHOD_NAME_MAX: 100,          // Maximum method name length
  CONTROL_CHARS_MAX: 10,         // Maximum allowed control characters
};

export const RATE_LIMITS = {
  REQUESTS_PER_MINUTE: 30,
  REQUESTS_PER_HOUR: 500,
  BURST_THRESHOLD: 10,           // Max requests in 10-second window
  BURST_WINDOW_MS: 10_000,       // 10 seconds
  CLEANUP_INTERVAL_MS: 60_000,   // 1 minute cleanup interval
};

export const LOGGING = {
  MAX_FILE_SIZE: 10_485_760,     // 10MB per log file
  MAX_FILES: 5,                  // Maximum log file rotation
};
