/**
 * SecureMcpServer - Unified secure MCP server with built-in validation.
 * Consolidates MCPSecurityMiddleware, EnhancedMCPSecurityMiddleware, and SecureMcpServer.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ValidationPipeline, ValidationLayerInterface, PipelineContext } from "./utils/validation-pipeline.js";
import { LIMITS, RATE_LIMITS } from './constants.js';
import StructureValidationLayer from "./layers/layer1-structure.js";
import ContentValidationLayer from "./layers/layer2-content.js";
import BehaviorValidationLayer from "./layers/layer3-behavior.js";
import SemanticsValidationLayer from "./layers/layer4-semantics.js";
import ContextualValidationLayer from "./layers/layer5-contextual.js";
import { InMemoryQuotaProvider, QuotaProvider } from "./layers/layer-utils/semantics/semantic-quotas.js";
import { defaultToolRegistry, defaultResourcePolicy } from "./utils/tool-registry.js";
import { ErrorSanitizer } from "./utils/error-sanitizer.js";
import { SecureTransport, McpTransport } from "./transport/index.js";
import { SecurityLogger } from "./utils/security-logger.js";
import { normalizeRequest } from "./utils/request-normalizer.js";
import type { ValidationResult, PolicyContext } from '../types/index.js';
import type { ToolSpec, ResourcePolicy, MethodSpec, ChainingRule } from "./layers/layer-utils/semantics/semantic-policies.js";
import type { ContextualLayerOptions } from "./layers/layer5-contextual.js";
import type { QuotaLimits } from "./layers/layer-utils/semantics/semantic-quotas.js";

/** Server info passed to MCP SDK */
export interface ServerInfo {
  name: string;
  version: string;
}

/** MCP message structure */
interface McpMessage {
  jsonrpc?: string;
  method?: string;
  id?: string | number | null;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
  [key: string]: unknown;
}

/** Request history entry */
interface RequestHistoryEntry {
  timestamp: number;
  method: string | undefined;
  hasParams: boolean;
  messageSize: number;
}

/** Security stats structure */
interface SecurityStats {
  server: {
    uptime: number;
    totalLayers: number;
    enabledLayers: number;
    loggingEnabled: boolean;
  };
  behaviorLayer: unknown;
  logger?: unknown;
}

/** Contextual layer configuration options */
interface ContextualConfig extends Partial<ContextualLayerOptions> {
  enabled?: boolean;
}

/** SecureMcpServer configuration options */
export interface SecureMcpServerOptions {
  /** McpServer options passed to underlying SDK */
  server?: Record<string, unknown>;
  /** Maximum message size in bytes */
  maxMessageSize?: number;
  /** Rate limit per minute */
  maxRequestsPerMinute?: number;
  /** Rate limit per hour */
  maxRequestsPerHour?: number;
  /** Max requests in 10-second window */
  burstThreshold?: number;
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
}

/** Internal resolved options */
interface ResolvedOptions extends Required<Pick<SecureMcpServerOptions,
  'maxMessageSize' | 'maxRequestsPerMinute' | 'maxRequestsPerHour' | 'burstThreshold' |
  'enableLogging' | 'verboseLogging' | 'logPerformanceMetrics' | 'logLevel' | 'defaultPolicy'
>> {
  [key: string]: unknown;
}

/**
 * Unified secure MCP server with built-in transport-level security validation.
 * All incoming messages are validated before reaching handlers.
 *
 * Logging is opt-in (quiet by default for production).
 */
class SecureMcpServer {
  /** Server info - exposed for testing */
  _serverInfo: ServerInfo;
  private _options: ResolvedOptions;
  private _mcpServer: McpServer;
  private _validationPipeline: ValidationPipeline;
  private _errorSanitizer: ErrorSanitizer;
  private _securityLogger: SecurityLogger | null;
  private _wrappedTransport: SecureTransport | null;
  private _startTime: number;
  private _requestHistory: RequestHistoryEntry[];
  private _requestIdByJsonrpcId: Map<string | number | null | undefined, number>;

  constructor(serverInfo: ServerInfo, options: SecureMcpServerOptions = {}) {
    this._serverInfo = serverInfo;
    this._options = {
      // Limits
      maxMessageSize: options.maxMessageSize ?? LIMITS.MESSAGE_SIZE_MAX,
      maxRequestsPerMinute: options.maxRequestsPerMinute ?? RATE_LIMITS.REQUESTS_PER_MINUTE,
      maxRequestsPerHour: options.maxRequestsPerHour ?? RATE_LIMITS.REQUESTS_PER_HOUR,
      burstThreshold: options.burstThreshold ?? RATE_LIMITS.BURST_THRESHOLD,
      // Logging (OPT-IN - quiet by default)
      enableLogging: options.enableLogging ?? false,
      verboseLogging: options.verboseLogging ?? false,
      logPerformanceMetrics: options.logPerformanceMetrics ?? false,
      logLevel: options.logLevel ?? 'info',
      // Default policy for side effects (restrictive by default)
      defaultPolicy: options.defaultPolicy ?? {
        allowNetwork: false,
        allowWrites: false
      },
      ...options
    };

    // Core MCP server
    this._mcpServer = new McpServer(serverInfo, options.server ?? {});

    // Security components
    this._validationPipeline = this._createValidationPipeline(options);
    this._errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());

    // Optional logging (only created if enabled)
    this._securityLogger = this._options.enableLogging
      ? new SecurityLogger({ logLevel: this._options.logLevel })
      : null;

    // State tracking
    this._wrappedTransport = null;
    this._startTime = Date.now();
    this._requestHistory = [];
    this._requestIdByJsonrpcId = new Map();
  }

  /**
   * Create the 5-layer validation pipeline
   */
  private _createValidationPipeline(options: SecureMcpServerOptions): ValidationPipeline {
    const layers: ValidationLayerInterface[] = [
      new StructureValidationLayer({
        maxMessageSize: options.maxMessageSize ?? LIMITS.MESSAGE_SIZE_MAX,
        maxParamCount: LIMITS.PARAM_COUNT_MAX,
        maxStringLength: LIMITS.STRING_LENGTH_MAX
      }),
      new ContentValidationLayer(),
      new BehaviorValidationLayer({
        requestsPerMinute: options.maxRequestsPerMinute ?? RATE_LIMITS.REQUESTS_PER_MINUTE,
        requestsPerHour: options.maxRequestsPerHour ?? RATE_LIMITS.REQUESTS_PER_HOUR,
        burstThreshold: options.burstThreshold ?? RATE_LIMITS.BURST_THRESHOLD
      }),
      new SemanticsValidationLayer({
        toolRegistry: options.toolRegistry ?? defaultToolRegistry(),
        resourcePolicy: options.resourcePolicy ?? defaultResourcePolicy(),
        methodSpec: options.methodSpec,
        chainingRules: options.chainingRules,
        quotas: options.quotas,
        quotaProvider: options.quotaProvider ?? new InMemoryQuotaProvider({
          clockSkewMs: options.clockSkewMs ?? 1000
        }),
        maxSessions: options.maxSessions ?? 5000,
        sessionTtlMs: options.sessionTtlMs ?? 30 * 60_000
      })
    ];

    // Layer 5: Contextual Validation (enabled by default)
    const contextualConfig = options.contextual ?? {};
    if (contextualConfig.enabled !== false) {
      layers.push(new ContextualValidationLayer(contextualConfig));
    }

    return new ValidationPipeline(layers);
  }

  // ==================== McpServer Delegation ====================

  async connect(transport: McpTransport): Promise<void> {
    this._wrappedTransport = this._wrapTransport(transport);
    return this._mcpServer.connect(this._wrappedTransport as unknown as Parameters<McpServer['connect']>[0]);
  }

  async close(): Promise<void> {
    return this._mcpServer.close();
  }

  isConnected(): boolean {
    return this._mcpServer.isConnected();
  }

  tool(name: string, ...rest: unknown[]): unknown {
    return (this._mcpServer.tool as (...args: unknown[]) => unknown)(name, ...rest);
  }

  registerTool(name: string, config: unknown, callback: unknown): unknown {
    return (this._mcpServer.registerTool as (...args: unknown[]) => unknown)(name, config, callback);
  }

  resource(name: string, uriOrTemplate: unknown, ...rest: unknown[]): unknown {
    return (this._mcpServer.resource as (...args: unknown[]) => unknown)(name, uriOrTemplate, ...rest);
  }

  registerResource(name: string, uriOrTemplate: unknown, config: unknown, callback: unknown): unknown {
    return (this._mcpServer.registerResource as (...args: unknown[]) => unknown)(name, uriOrTemplate, config, callback);
  }

  prompt(name: string, ...rest: unknown[]): unknown {
    return (this._mcpServer.prompt as (...args: unknown[]) => unknown)(name, ...rest);
  }

  registerPrompt(name: string, config: unknown, callback: unknown): unknown {
    return (this._mcpServer.registerPrompt as (...args: unknown[]) => unknown)(name, config, callback);
  }

  async sendLoggingMessage(params: unknown, sessionId?: string): Promise<unknown> {
    return (this._mcpServer.sendLoggingMessage as (...args: unknown[]) => Promise<unknown>)(params, sessionId);
  }

  sendResourceListChanged(): void {
    return this._mcpServer.sendResourceListChanged();
  }

  sendToolListChanged(): void {
    return this._mcpServer.sendToolListChanged();
  }

  sendPromptListChanged(): void {
    return this._mcpServer.sendPromptListChanged();
  }

  get server(): unknown {
    return this._mcpServer.server;
  }

  get mcpServer(): McpServer {
    return this._mcpServer;
  }

  get validationPipeline(): ValidationPipeline {
    return this._validationPipeline;
  }

  // ==================== Transport Wrapping ====================

  /**
   * Wraps a transport with security validation at the message level.
   */
  private _wrapTransport(transport: McpTransport): SecureTransport {
    const validator = async (message: McpMessage, context: { timestamp: number; transportLevel: boolean }): Promise<ValidationResult> => {
      const startTime = this._options.logPerformanceMetrics ? performance.now() : 0;
      const normalizedMessage = normalizeRequest(message as Record<string, unknown>);

      // Optional logging
      if (this._securityLogger) {
        let internalId = this._requestIdByJsonrpcId.get(normalizedMessage.id);
        if (!internalId) {
          internalId = this._securityLogger.nextRequestId();
          this._requestIdByJsonrpcId.set(normalizedMessage.id, internalId);
        }

        this._securityLogger.logRequest(normalizedMessage as unknown as Record<string, unknown>, {
          timestamp: context.timestamp ?? Date.now(),
          source: 'transport-level',
          requestSize: JSON.stringify(message).length,
          pipelineLayers: this._validationPipeline.getLayers(),
          requestId: internalId
        });
      }

      // Run validation pipeline
      const pipelineContext: PipelineContext = {
        timestamp: context.timestamp ?? Date.now(),
        transportLevel: true,
        originalMessage: message,
        logger: this._securityLogger as unknown as PipelineContext['logger'],
        verbose: this._options.verboseLogging,
        requestId: normalizedMessage.id,
        policy: this._options.defaultPolicy
      };

      const result = await this._validationPipeline.validate(
        normalizedMessage as unknown as Record<string, unknown>,
        pipelineContext
      );

      // Performance tracking
      if (this._options.logPerformanceMetrics && this._securityLogger) {
        const endTime = performance.now();
        (result as ValidationResult & { validationTime?: number }).validationTime = endTime - startTime;
        this._securityLogger.logPerformance(startTime, endTime, normalizedMessage as unknown as Record<string, unknown>);
      }

      // Log decision
      if (this._securityLogger) {
        this._securityLogger.logSecurityDecision(result, normalizedMessage as unknown as Record<string, unknown>, 'Transport');
      }

      this._trackRequest(normalizedMessage as unknown as McpMessage);
      return result as ValidationResult;
    };

    return new SecureTransport(transport, validator, {
      errorSanitizer: this._errorSanitizer
    });
  }

  private _trackRequest(message: McpMessage): void {
    this._requestHistory.push({
      timestamp: Date.now(),
      method: message.method,
      hasParams: !!message.params,
      messageSize: JSON.stringify(message).length
    });

    // Keep only recent history to prevent memory leaks
    if (this._requestHistory.length > 1000) {
      this._requestHistory = this._requestHistory.slice(-500);
    }
  }

  // ==================== Stats & Reporting ====================

  /**
   * Get security stats from all layers
   */
  getSecurityStats(): SecurityStats {
    const behaviorLayer = this._validationPipeline.layers.find(
      layer => layer.constructor.name === 'BehaviorValidationLayer'
    ) as BehaviorValidationLayer | undefined;

    return {
      server: {
        uptime: Date.now() - this._startTime,
        totalLayers: this._validationPipeline.layers.length,
        enabledLayers: this._validationPipeline.layers.filter(l => l.isEnabled()).length,
        loggingEnabled: this._options.enableLogging
      },
      behaviorLayer: behaviorLayer ? behaviorLayer.getStats() : null,
      ...(this._securityLogger ? { logger: this._securityLogger.getStats() } : {})
    };
  }

  /**
   * Get verbose security report (requires logging enabled)
   */
  getVerboseSecurityReport(): unknown {
    if (!this._securityLogger) {
      return { error: 'Logging not enabled. Set enableLogging: true in options.' };
    }
    return this._securityLogger.getStats();
  }

  /**
   * Generate security report (requires logging enabled)
   */
  async generateSecurityReport(): Promise<unknown> {
    if (!this._securityLogger) {
      return { error: 'Logging not enabled. Set enableLogging: true in options.' };
    }
    return await this._securityLogger.generateReport();
  }

  /**
   * Graceful shutdown with optional final report
   */
  async shutdown(): Promise<unknown> {
    let finalReport: unknown = null;

    if (this._securityLogger) {
      finalReport = await this._securityLogger.generateReport();
      await this._securityLogger.flush();
    }

    // Cleanup behavior layer timers
    const behaviorLayer = this._validationPipeline.layers.find(
      layer => layer.constructor.name === 'BehaviorValidationLayer'
    ) as BehaviorValidationLayer | undefined;
    if (behaviorLayer?.cleanup) {
      behaviorLayer.cleanup();
    }

    await this.close();
    return finalReport;
  }
}

export { SecureMcpServer };
