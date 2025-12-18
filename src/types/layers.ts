/**
 * Layer configuration types for the MCP Security Framework.
 */

import type { ToolSpec, ResourcePolicy, MethodSpec, ChainingRule, QuotaLimits, QuotaProvider } from './policies.js';

/** Base options for all validation layers */
export interface LayerOptions {
  /** Whether the layer is enabled (default: true) */
  enabled?: boolean;
}

/** Layer 1 (Structure) configuration */
export interface StructureLayerOptions extends LayerOptions {
  /** Maximum message size in bytes (default: 50000) */
  maxMessageSize?: number;
  /** Maximum parameter count (default: 100) */
  maxParamCount?: number;
  /** Maximum string length (default: 10000) */
  maxStringLength?: number;
}

/** Layer 2 (Content) configuration */
export interface ContentLayerOptions extends LayerOptions {
  /** Maximum cache size for processed content (default: 1000) */
  cacheMaxSize?: number;
  /** Enable debug mode for content validation */
  debugMode?: boolean;
  /** Maximum input size in bytes for content validation (default: 2MB) */
  maxInputSize?: number;
}

/** Layer 3 (Behavior) configuration */
export interface BehaviorLayerOptions extends LayerOptions {
  /** Rate limit per minute (default: 30) */
  requestsPerMinute?: number;
  /** Rate limit per hour (default: 500) */
  requestsPerHour?: number;
  /** Max requests in burst window (default: 10) */
  burstThreshold?: number;
}

/** Layer 4 (Semantics) configuration */
export interface SemanticsLayerOptions extends LayerOptions {
  /** Tool registry for contract enforcement */
  toolRegistry?: ToolSpec[];
  /** Resource access policy */
  resourcePolicy?: ResourcePolicy;
  /** Method shape specifications */
  methodSpec?: MethodSpec;
  /** Method chaining rules */
  chainingRules?: ChainingRule[];
  /** Enforce method chaining rules (default: false) */
  enforceChaining?: boolean;
  /** Default action when no chaining rule matches (default: 'deny') */
  chainingDefaultAction?: 'allow' | 'deny';
  /** Quota limits per tool */
  quotas?: Record<string, QuotaLimits>;
  /** Custom quota provider */
  quotaProvider?: QuotaProvider;
  /** Maximum concurrent sessions (default: 5000) */
  maxSessions?: number;
  /** Session TTL in ms (default: 1800000 / 30 min) */
  sessionTtlMs?: number;
  /** Clock skew tolerance in ms (default: 1000) */
  clockSkewMs?: number;
}

/** OAuth URL validation options */
export interface OAuthValidationOptions {
  /** Enable OAuth URL validation */
  enabled?: boolean;
  /** Allowed OAuth domains */
  allowedDomains?: string[];
  /** Block dangerous URL schemes (file:, javascript:, etc.) */
  blockDangerousSchemes?: boolean;
}

/** Domain restriction options */
export interface DomainRestrictionsOptions {
  /** Enable domain restrictions */
  enabled?: boolean;
  /** Allowed domains (whitelist) */
  allowedDomains?: string[];
  /** Blocked domains (blacklist) */
  blockedDomains?: string[];
}

/** Rate limiting options for Layer 5 */
export interface RateLimitingOptions {
  /** Enable rate limiting */
  enabled?: boolean;
  /** Maximum requests in window (default: 10) */
  limit?: number;
  /** Time window in ms (default: 60000) */
  windowMs?: number;
}

/** Response validation options */
export interface ResponseValidationOptions {
  /** Enable response validation */
  enabled?: boolean;
  /** Block responses containing sensitive data patterns */
  blockSensitiveData?: boolean;
}

/** Layer 5 (Contextual) configuration */
export interface ContextualLayerOptions extends LayerOptions {
  /** OAuth URL validation config */
  oauthValidation?: OAuthValidationOptions;
  /** Domain restriction config */
  domainRestrictions?: DomainRestrictionsOptions;
  /** Per-tool rate limiting config */
  rateLimiting?: RateLimitingOptions;
  /** Response validation config */
  responseValidation?: ResponseValidationOptions;
}

/** Complete security options for SecureMcpServer */
export interface SecurityOptions {
  /** McpServer options passed to underlying SDK */
  server?: Record<string, unknown>;
  /** Maximum message size in bytes (default: 50000) */
  maxMessageSize?: number;
  /** Rate limit per minute (default: 30) */
  maxRequestsPerMinute?: number;
  /** Rate limit per hour (default: 500) */
  maxRequestsPerHour?: number;
  /** Max requests in 10-second window (default: 10) */
  burstThreshold?: number;
  /** Enable security logging - opt-in (default: false) */
  enableLogging?: boolean;
  /** Enable verbose decision logs (default: false) */
  verboseLogging?: boolean;
  /** Enable timing statistics (default: false) */
  logPerformanceMetrics?: boolean;
  /** Log level when logging enabled (default: 'info') */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Custom tool registry for Layer 4 */
  toolRegistry?: ToolSpec[];
  /** Custom resource policy for Layer 4 */
  resourcePolicy?: ResourcePolicy;
  /** Method shape specifications for Layer 4 */
  methodSpec?: MethodSpec;
  /** Method chaining rules for Layer 4 */
  chainingRules?: ChainingRule[];
  /** Quota limits per tool */
  quotas?: Record<string, QuotaLimits>;
  /** Custom quota provider */
  quotaProvider?: QuotaProvider;
  /** Maximum concurrent sessions (default: 5000) */
  maxSessions?: number;
  /** Session TTL in ms (default: 1800000 / 30 min) */
  sessionTtlMs?: number;
  /** Clock skew tolerance in ms (default: 1000) */
  clockSkewMs?: number;
  /** Layer 5 contextual validation config */
  contextual?: ContextualLayerOptions;
  /** Default policy for side effects */
  defaultPolicy?: {
    allowNetwork?: boolean;
    allowWrites?: boolean;
  };
}

/** Server info for SecureMcpServer constructor */
export interface ServerInfo {
  /** Server name */
  name: string;
  /** Server version */
  version: string;
}

/** Security statistics from SecureMcpServer */
export interface SecurityStats {
  /** Server statistics */
  server: {
    /** Uptime in ms */
    uptime: number;
    /** Total number of validation layers */
    totalLayers: number;
    /** Number of enabled layers */
    enabledLayers: number;
    /** Whether logging is enabled */
    loggingEnabled: boolean;
  };
  /** Behavior layer statistics */
  behaviorLayer?: BehaviorStats;
  /** Logger statistics */
  logger?: unknown;
}

/** Behavior layer statistics */
export interface BehaviorStats {
  /** Total requests tracked */
  totalRequestsTracked: number;
  /** Active rate windows */
  activeRateWindows: number;
  /** Uptime in ms */
  uptimeMs: number;
  /** Memory footprint info */
  memoryFootprint: {
    /** Recent requests count */
    recentRequests: number;
    /** Request counters count */
    requestCounters: number;
  };
}
