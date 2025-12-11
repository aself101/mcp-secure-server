/**
 * Core validation types for the MCP Security Framework.
 */

/** Severity levels for validation results */
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NONE';

/** Violation types detected by the security layers */
export type ViolationType =
  // Generic
  | 'UNKNOWN'
  | 'VALIDATION_ERROR'
  | 'INTERNAL_ERROR'
  | 'POLICY_VIOLATION'
  // Structure (Layer 1)
  | 'INVALID_MESSAGE'
  | 'INVALID_PROTOCOL'
  | 'INVALID_METHOD'
  | 'INVALID_SCHEMA'
  | 'SIZE_LIMIT_EXCEEDED'
  | 'STRING_LIMIT_EXCEEDED'
  | 'PARAM_LIMIT_EXCEEDED'
  | 'MISSING_REQUIRED_PARAM'
  | 'MALFORMED_MESSAGE'
  // Content (Layer 2)
  | 'DANGEROUS_ENCODING'
  | 'SUSPICIOUS_ENCODING'
  | 'ENCODING_EVASION'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'SQL_INJECTION'
  | 'NOSQL_INJECTION'
  | 'GRAPHQL_INJECTION'
  | 'XSS_ATTEMPT'
  | 'SCRIPT_INJECTION'
  | 'CSS_INJECTION'
  | 'CRLF_INJECTION'
  | 'SSRF_ATTEMPT'
  | 'BUFFER_OVERFLOW_ATTEMPT'
  | 'DESERIALIZATION_INJECTION'
  | 'PROTOTYPE_POLLUTION'
  | 'XML_ENTITY_ATTACK'
  | 'LOLBINS_EXECUTION'
  | 'DANGEROUS_DATA_URI'
  | 'BASE64_INJECTION'
  | 'NESTED_DATA_URI'
  | 'SUSPICIOUS_TEST_DATA'
  | 'EXCESSIVE_NESTING'
  | 'PARAM_SERIALIZATION_ERROR'
  | 'OVERSIZED_PARAMS'
  | 'EXCESSIVE_PARAM_COUNT'
  | 'REQUEST_FLOODING'
  // Behavior (Layer 3)
  | 'RATE_LIMIT_EXCEEDED'
  | 'BURST_ACTIVITY'
  | 'OVERSIZED_MESSAGE'
  | 'AUTOMATED_TIMING'
  | 'SUSPICIOUS_METHOD'
  // Semantics (Layer 4)
  | 'QUOTA_EXCEEDED'
  | 'TOOL_NOT_ALLOWED'
  | 'INVALID_TOOL_ARGUMENTS'
  | 'ARGS_EGRESS_LIMIT'
  | 'ARG_SERIALIZATION_ERROR'
  | 'RESOURCE_POLICY_VIOLATION'
  | 'RESOURCE_EGRESS_LIMIT'
  | 'SIDE_EFFECT_NOT_ALLOWED'
  | 'CHAIN_VIOLATION'
  | 'INVALID_MCP_METHOD'
  | 'TOOL_EGRESS_LIMIT'
  // Contextual (Layer 5)
  | 'DANGEROUS_URL_SCHEME'
  | 'DOMAIN_RESTRICTION_VIOLATION'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'VALIDATOR_ERROR'
  | 'BLOCKED_DOMAIN'
  | 'DOMAIN_NOT_ALLOWED';

/** Result of a validation operation */
export interface ValidationResult {
  /** Whether the validation passed */
  passed: boolean;
  /** Alias for passed (backward compatibility) */
  allowed: boolean;
  /** Alias for passed (backward compatibility) */
  valid?: boolean;
  /** Severity level of any detected issue */
  severity: Severity;
  /** Human-readable reason for failure (sanitized) */
  reason: string | null;
  /** Type of violation detected */
  violationType: ViolationType | string | null;
  /** Confidence score (0.0 to 1.0) */
  confidence: number;
  /** Timestamp of validation */
  timestamp: number;
  /** Name of the layer that produced this result */
  layerName: string | null;
  /** Detection layer identifier */
  detectionLayer?: string;
  /** Source validator that detected the issue */
  validatorSource?: string;
  /** Time taken for validation in ms */
  validationTime?: number;
}

/** Policy context for controlling side effects */
export interface PolicyContext {
  /** Whether network operations are allowed */
  allowNetwork?: boolean;
  /** Whether write operations are allowed */
  allowWrites?: boolean;
}

/** Context passed through the validation pipeline */
export interface ValidationContext {
  /** Logger instance */
  logger?: unknown;
  /** Request timestamp */
  timestamp?: number;
  /** Whether validation is at transport level */
  transportLevel?: boolean;
  /** Unique request identifier */
  requestId?: string | number | null;
  /** Session identifier */
  sessionId?: string;
  /** Client identifier */
  clientId?: string;
  /** Policy context for side effects */
  policy?: PolicyContext;
  /** Canonicalized message content */
  canonical?: string;
  /** Original message before normalization */
  originalMessage?: unknown;
  /** Enable verbose logging */
  verbose?: boolean;
  /** Base directory for path validation */
  baseDir?: string;
}

/** Validator function signature for request validation */
export type ValidatorFunction = (
  message: Record<string, unknown>,
  context: ValidationContext
) => ValidationResult | Promise<ValidationResult>;

/** Validator function signature for response validation */
export type ResponseValidatorFunction = (
  response: Record<string, unknown>,
  request: Record<string, unknown>,
  context: ValidationContext
) => ValidationResult | Promise<ValidationResult>;

/** Global rule function that can return null to skip */
export type GlobalRuleFunction = (
  message: Record<string, unknown>,
  context: ValidationContext
) => ValidationResult | null | Promise<ValidationResult | null>;

/** Options for validator registration */
export interface ValidatorOptions {
  /** Whether the validator is enabled */
  enabled?: boolean;
  /** Priority for execution order (lower = earlier) */
  priority?: number;
  /** Skip remaining validators on success */
  skipOnSuccess?: boolean;
  /** Fail validation if this validator throws */
  failOnError?: boolean;
}

// ==================== Type Guards ====================

/** All valid severity levels */
const SEVERITY_VALUES: readonly Severity[] = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

/** All valid violation types */
const VIOLATION_TYPE_VALUES: readonly ViolationType[] = [
  'UNKNOWN', 'VALIDATION_ERROR', 'INTERNAL_ERROR', 'POLICY_VIOLATION',
  'INVALID_MESSAGE', 'INVALID_PROTOCOL', 'INVALID_METHOD', 'INVALID_SCHEMA',
  'SIZE_LIMIT_EXCEEDED', 'STRING_LIMIT_EXCEEDED', 'PARAM_LIMIT_EXCEEDED',
  'MISSING_REQUIRED_PARAM', 'MALFORMED_MESSAGE', 'DANGEROUS_ENCODING',
  'SUSPICIOUS_ENCODING', 'ENCODING_EVASION', 'PATH_TRAVERSAL', 'COMMAND_INJECTION',
  'SQL_INJECTION', 'NOSQL_INJECTION', 'GRAPHQL_INJECTION', 'XSS_ATTEMPT',
  'SCRIPT_INJECTION', 'CSS_INJECTION', 'CRLF_INJECTION', 'SSRF_ATTEMPT',
  'BUFFER_OVERFLOW_ATTEMPT', 'DESERIALIZATION_INJECTION', 'PROTOTYPE_POLLUTION',
  'XML_ENTITY_ATTACK', 'LOLBINS_EXECUTION', 'DANGEROUS_DATA_URI', 'BASE64_INJECTION', 'NESTED_DATA_URI',
  'SUSPICIOUS_TEST_DATA', 'EXCESSIVE_NESTING', 'PARAM_SERIALIZATION_ERROR',
  'OVERSIZED_PARAMS', 'EXCESSIVE_PARAM_COUNT', 'REQUEST_FLOODING',
  'RATE_LIMIT_EXCEEDED', 'BURST_ACTIVITY', 'OVERSIZED_MESSAGE', 'AUTOMATED_TIMING',
  'SUSPICIOUS_METHOD', 'QUOTA_EXCEEDED', 'TOOL_NOT_ALLOWED', 'INVALID_TOOL_ARGUMENTS',
  'ARGS_EGRESS_LIMIT', 'ARG_SERIALIZATION_ERROR', 'RESOURCE_POLICY_VIOLATION',
  'RESOURCE_EGRESS_LIMIT', 'SIDE_EFFECT_NOT_ALLOWED', 'CHAIN_VIOLATION',
  'INVALID_MCP_METHOD', 'TOOL_EGRESS_LIMIT', 'DANGEROUS_URL_SCHEME',
  'DOMAIN_RESTRICTION_VIOLATION', 'SENSITIVE_DATA_EXPOSURE', 'VALIDATOR_ERROR',
  'BLOCKED_DOMAIN', 'DOMAIN_NOT_ALLOWED'
] as const;

/**
 * Type guard to check if a value is a valid Severity level.
 * @param value - The value to check
 * @returns True if value is a valid Severity
 */
export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && SEVERITY_VALUES.includes(value as Severity);
}

/**
 * Type guard to check if a value is a valid ViolationType.
 * @param value - The value to check
 * @returns True if value is a valid ViolationType
 */
export function isViolationType(value: unknown): value is ViolationType {
  return typeof value === 'string' && VIOLATION_TYPE_VALUES.includes(value as ViolationType);
}

/**
 * Type guard to check if a value is an Error instance.
 * @param value - The value to check
 * @returns True if value is an Error
 */
export function isError(value: unknown): value is Error {
  return value instanceof Error;
}

/**
 * Safely extract error message from unknown error type.
 * @param error - The error value (may be unknown type)
 * @returns The error message string
 */
export function getErrorMessage(error: unknown): string {
  if (isError(error)) {
    return error.message;
  }
  return String(error);
}
