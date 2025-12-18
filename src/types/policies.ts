/**
 * Tool and resource policy types for the MCP Security Framework.
 */

/** Side effect types for tools */
export type SideEffectType = 'none' | 'read' | 'write' | 'network';

/** Argument type definitions */
export type ArgType = 'string' | 'number' | 'boolean' | 'array' | 'object';

/** Argument definition for tool contracts */
export interface ArgDefinition {
  /** Expected type */
  type: ArgType;
  /** Whether the argument is optional */
  optional?: boolean;
}

/** Tool specification for contract enforcement */
export interface ToolSpec {
  /** Tool name */
  name: string;
  /** Side effect classification */
  sideEffects: SideEffectType;
  /** Maximum arguments size in bytes */
  maxArgsSize?: number;
  /** Maximum egress bytes for network tools */
  maxEgressBytes?: number;
  /** Quota per minute */
  quotaPerMinute?: number;
  /** Quota per hour */
  quotaPerHour?: number;
  /** Expected argument shape */
  argsShape?: Record<string, ArgDefinition>;
}

/** Resource access policy */
export interface ResourcePolicy {
  /** Allowed URI schemes (e.g., ['file', 'https']) */
  allowedSchemes: string[];
  /** Allowed hosts for network resources */
  allowedHosts?: string[];
  /** Allowed root directories for file access */
  rootDirs?: string[];
  /** Denied path patterns */
  denyGlobs?: (string | RegExp)[];
  /** Maximum path length */
  maxPathLength?: number;
  /** Maximum URI length */
  maxUriLength?: number;
  /** Maximum bytes to read from resources */
  maxReadBytes?: number;
}

/** Method parameter shape definition */
export interface MethodDefinition {
  /** Required parameter names */
  required?: string[];
}

/** Method specification for parameter validation */
export interface MethodSpec {
  /** Shape definitions by method name */
  shape: Record<string, MethodDefinition>;
}

/** Method chaining rule */
export interface ChainingRule {
  /** Method to transition from ('*' for any) */
  from: string;
  /** Method to transition to ('*' for any) */
  to: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  fromTool?: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  toTool?: string;
  /** Side effect of the 'from' tool */
  fromSideEffect?: SideEffectType;
  /** Side effect of the 'to' tool */
  toSideEffect?: SideEffectType;
  /** Action to take when rule matches. Default: 'allow' */
  action?: 'allow' | 'deny';
  /** Rule identifier for logging */
  id?: string;
}

/** Quota limits for tools */
export interface QuotaLimits {
  /** Maximum calls per minute */
  minute?: number;
  /** Maximum calls per hour */
  hour?: number;
}

/** Result of a quota check */
export interface QuotaCheckResult {
  /** Whether the quota check passed */
  passed: boolean;
  /** Reason for failure */
  reason?: string;
}

/** Quota provider interface for custom quota implementations */
export interface QuotaProvider {
  /**
   * Increment counter and check if quota is exceeded
   * @param key - Quota key (e.g., tool name)
   * @param limits - Quota limits to check against
   * @param now - Current timestamp in ms
   * @returns Result of quota check
   */
  incrementAndCheck(
    key: string,
    limits: QuotaLimits,
    now: number
  ): QuotaCheckResult;

  /**
   * Sweep expired quota entries
   * @param now - Current timestamp in ms
   */
  sweep?(now: number): void;
}

/** Rate window for tracking request counts */
export interface RateWindow {
  /** Request count in window */
  count: number;
  /** Window start timestamp */
  windowStart: number;
}

/** Request entry for behavior tracking */
export interface RequestEntry {
  /** Request timestamp */
  timestamp: number;
  /** Method name */
  method: string;
  /** Request size in bytes */
  size: number;
}

/** Error sanitizer configuration */
export interface ErrorSanitizerConfig {
  /** Enable detailed errors (for development) */
  enableDetailedErrors?: boolean;
  /** Maximum log entry length */
  maxLogLength?: number;
}

/** Security logger options */
export interface SecurityLoggerOptions {
  /** Enable logging */
  enabled?: boolean;
  /** Log level */
  level?: 'debug' | 'info' | 'warn' | 'error';
  /** Enable verbose logging */
  verbose?: boolean;
  /** Enable performance metrics */
  logPerformanceMetrics?: boolean;
  /** Log directory path */
  logDir?: string;
}
