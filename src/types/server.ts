/**
 * Server-specific types for SecureMcpServer.
 */

import type { ContextualLayerOptions } from './layers.js';
import type { ToolSpec, ResourcePolicy, MethodSpec, ChainingRule, QuotaLimits } from './policies.js';
import type { QuotaProvider } from '../security/layers/layer-utils/semantics/semantic-quotas.js';
import type { PolicyContext } from './validation.js';
import type { ToolPoliciesConfig } from '../security/config/tool-policies-config.js';
import type { SecurityPreset } from '../security/presets.js';
import type { ServerCapabilities } from '@modelcontextprotocol/sdk/types.js';

/** MCP message structure for internal processing */
export interface McpMessage {
  jsonrpc?: string;
  method?: string;
  id?: string | number | null;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

/** Request history entry for tracking */
export interface RequestHistoryEntry {
  timestamp: number;
  method: string | undefined;
  hasParams: boolean;
  messageSize: number;
}

/** Contextual layer configuration with optional enable flag */
export type ContextualConfig = Partial<ContextualLayerOptions> & {
  enabled?: boolean;
};

/** Content validation level for Layer 2 */
export type ContentValidationLevel = 'minimal' | 'standard' | 'full';

/** SecureMcpServer configuration options */
export interface SecureMcpServerOptions {
  /**
   * Security preset - simplified configuration.
   * - 'basic': Relaxed limits for development/testing
   * - 'standard': Balanced security for production (default)
   * - 'paranoid': Maximum security for high-risk environments
   * - 'custom': Full control, preset ignored
   *
   * Individual options below override preset values.
   *
   * @example
   * ```typescript
   * // Use paranoid preset but allow more requests per minute
   * new SecureMcpServer(info, {
   *   securityLevel: 'paranoid',
   *   maxRequestsPerMinute: 30  // Override preset's 15
   * });
   * ```
   */
  securityLevel?: SecurityPreset;
  /** McpServer options passed to underlying SDK */
  server?: Record<string, unknown>;
  /** Maximum message size in bytes */
  maxMessageSize?: number;
  /** Maximum parameter count (recursive key count) */
  maxParamCount?: number;
  /** Rate limit per minute */
  maxRequestsPerMinute?: number;
  /** Rate limit per hour */
  maxRequestsPerHour?: number;
  /** Max requests in 10-second window */
  burstThreshold?: number;
  /** Content validation level for Layer 2 pattern detection */
  contentValidation?: ContentValidationLevel;
  /** Enable security logging (opt-in) */
  enableLogging?: boolean;
  /** Enable verbose decision logs */
  verboseLogging?: boolean;
  /** Enable timing stats */
  logPerformanceMetrics?: boolean;
  /** Log level when logging enabled */
  logLevel?: string;
  /** Custom tool registry for Layer 4 */
  toolRegistry?: ToolSpec[];
  /** Custom resource policy for Layer 4 */
  resourcePolicy?: ResourcePolicy;
  /** Method spec for Layer 4 */
  methodSpec?: MethodSpec;
  /** Chaining rules for Layer 4 */
  chainingRules?: ChainingRule[];
  /** Enforce method chaining (disabled by default) */
  enforceChaining?: boolean;
  /** Quotas for Layer 4 */
  quotas?: Record<string, QuotaLimits>;
  /** Quota provider for Layer 4 */
  quotaProvider?: QuotaProvider;
  /** Clock skew tolerance in ms */
  clockSkewMs?: number;
  /** Max sessions for Layer 4 */
  maxSessions?: number;
  /** Session TTL in ms */
  sessionTtlMs?: number;
  /** Default policy for side effects */
  defaultPolicy?: PolicyContext;
  /** Layer 5 contextual validation config */
  contextual?: ContextualConfig;
  /** Path to tool policies configuration file (JSON) */
  toolPoliciesPath?: string;
  /** Inline tool policies configuration (takes precedence over file) */
  toolPoliciesConfig?: ToolPoliciesConfig;
  /**
   * Explicit server capabilities declaration.
   * When provided, these are passed directly to the underlying McpServer.
   * Useful for declaring logging support or other MCP capabilities.
   *
   * @example
   * ```typescript
   * const server = new SecureMcpServer(
   *   { name: 'my-server', version: '1.0.0' },
   *   {
   *     capabilities: {
   *       logging: {}  // Enable logging capability
   *     }
   *   }
   * );
   * ```
   */
  capabilities?: ServerCapabilities;
}

/** Internal resolved options with defaults applied */
export interface ResolvedOptions extends Required<Pick<SecureMcpServerOptions,
  'maxMessageSize' | 'maxRequestsPerMinute' | 'maxRequestsPerHour' | 'burstThreshold' |
  'enableLogging' | 'verboseLogging' | 'logPerformanceMetrics' | 'logLevel' | 'defaultPolicy'
>> {
  [key: string]: unknown;
}
