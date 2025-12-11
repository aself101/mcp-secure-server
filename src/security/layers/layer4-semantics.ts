/**
 * Layer 4: Semantics Validation
 * Coordinates policy enforcement across tool contracts, resource access, and method chaining
 */

import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import { canonicalizeString } from './layer-utils/content/canonicalize.js';
import { InMemoryQuotaProvider, QuotaProvider, QuotaLimits } from './layer-utils/semantics/semantic-quotas.js';
import {
  getDefaultPolicies,
  normalizePolicies,
  validateToolCall as validateToolContract,
  validateResourceAccess,
  ToolSpec,
  ResourcePolicy,
  MethodSpec,
  ChainingRule,
  PolicyValidationResult,
  ToolCallParams
} from './layer-utils/semantics/semantic-policies.js';

/** Layer 4 specific options */
export interface SemanticsLayerOptions extends ValidationLayerOptions {
  toolRegistry?: ToolSpec[];
  resourcePolicy?: Partial<ResourcePolicy>;
  methodSpec?: Partial<MethodSpec>;
  chainingRules?: ChainingRule[];
  quotas?: Record<string, QuotaLimits>;
  quotaProvider?: QuotaProvider;
  clockSkewMs?: number;
  maxSessions?: number;
  sessionTtlMs?: number;
}

/** MCP message structure */
interface McpMessage {
  method?: string;
  params?: {
    name?: string;
    uri?: string;
    arguments?: unknown;
    args?: unknown;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/** Validation context with policy */
interface SemanticsContext extends ValidationContext {
  sessionId?: string;
  clientId?: string;
  baseDir?: string;
  policy?: {
    allowWrites?: boolean;
    allowNetwork?: boolean;
    [key: string]: unknown;
  };
}

/** Size result */
interface SizeResult extends ValidationResult {
  bytes?: number;
}

export default class SemanticsValidationLayer extends ValidationLayer {
  private tools: Map<string, ToolSpec>;
  private res: ResourcePolicy;
  private methods: MethodSpec;
  private quotas: Record<string, QuotaLimits>;
  private quotaProvider: QuotaProvider;

  constructor(options: SemanticsLayerOptions = {}) {
    super(options);

    const defaults = getDefaultPolicies();

    this.tools = new Map();
    (options.toolRegistry ?? defaults.tools).forEach(t => this.tools.set(t.name, t));

    const normalized = normalizePolicies({
      resourcePolicy: { ...defaults.resourcePolicy, ...options.resourcePolicy },
      methodSpec: { ...defaults.methodSpec, ...options.methodSpec },
      chainingRules: options.chainingRules ?? defaults.chainingRules
    });

    this.res = normalized.resourcePolicy;
    this.methods = normalized.methodSpec;

    this.quotas = options.quotas ?? {};
    this.quotaProvider = options.quotaProvider ?? new InMemoryQuotaProvider({
      clockSkewMs: options.clockSkewMs ?? 1000
    });

    this.logDebug('SemanticsValidationLayer initialized');
  }

  async validate(message: unknown, context: SemanticsContext = {}): Promise<ValidationResult> {
    const msg = message as McpMessage;

    const methodResult = this.checkMethodSemantics(msg);
    if (!methodResult.passed) return methodResult;

    if (msg.method === 'tools/call') {
      const toolResult = this.checkToolCall(msg, context);
      if (!toolResult.passed) return toolResult;
    }

    if (msg.method === 'resources/read') {
      const resourceResult = this.checkResourceRead(msg, context);
      if (!resourceResult.passed) return resourceResult;
    }

    const sideEffectResult = this.checkSideEffectsAndEgress(msg, context);
    if (!sideEffectResult.passed) return sideEffectResult;

    return this.createSuccessResult();
  }

  private checkMethodSemantics(message: McpMessage): ValidationResult {
    if (!message || typeof message !== 'object') {
      return this.createFailureResult('Empty or invalid message', 'HIGH', 'INVALID_MESSAGE');
    }
    if (!message.method || typeof message.method !== 'string') {
      return this.createFailureResult('Missing method', 'HIGH', 'INVALID_MCP_METHOD');
    }

    const spec = this.methods.shape[message.method];
    if (!spec) {
      return this.createFailureResult(
        `Unknown or disallowed method: ${message.method}`,
        'MEDIUM',
        'INVALID_MCP_METHOD'
      );
    }

    if (spec.required && spec.required.length) {
      const params = message.params;
      if (!params || typeof params !== 'object') {
        return this.createFailureResult(
          `Method ${message.method} requires params object`,
          'MEDIUM',
          'MISSING_REQUIRED_PARAM'
        );
      }
      for (const key of spec.required) {
        if (!(key in params)) {
          return this.createFailureResult(
            `Method ${message.method} missing required param: "${key}"`,
            'MEDIUM',
            'MISSING_REQUIRED_PARAM'
          );
        }
      }
    }

    return this.createSuccessResult();
  }

  private checkToolCall(message: McpMessage, _context: SemanticsContext): ValidationResult {
    const params = message.params;
    const name = params?.name;
    if (!name || typeof name !== 'string') {
      return this.createFailureResult(
        'tools/call requires "name"',
        'MEDIUM',
        'MISSING_REQUIRED_PARAM'
      );
    }

    const tool = this.tools.get(name);
    if (!tool) {
      return this.createFailureResult(
        `Tool "${name}" is not allowed`,
        'HIGH',
        'TOOL_NOT_ALLOWED'
      );
    }

    const toolParams: ToolCallParams = {
      name: params?.name,
      arguments: params?.arguments as Record<string, unknown> | undefined,
      args: params?.args as Record<string, unknown> | undefined
    };
    const contractResult = validateToolContract(tool, toolParams, message.method ?? '');
    if (!contractResult.passed) return this.wrapPolicyResult(contractResult);

    const quotaKey = `tool:${name}`;
    const methodKey = `${message.method}:${name}`;
    const quotaLimits: QuotaLimits = {
      minute: tool.quotaPerMinute ?? this.quotas[methodKey]?.minute,
      hour: tool.quotaPerHour ?? this.quotas[methodKey]?.hour
    };

    const quotaResult = this.quotaProvider.incrementAndCheck(quotaKey, quotaLimits, Date.now());
    if (!quotaResult.passed) {
      return this.createFailureResult(
        quotaResult.reason ?? `Quota exceeded for ${quotaKey}`,
        'HIGH',
        'QUOTA_EXCEEDED'
      );
    }

    return this.createSuccessResult();
  }

  private checkResourceRead(message: McpMessage, context: SemanticsContext): ValidationResult {
    let uri = message.params?.uri;
    if (!uri || typeof uri !== 'string') {
      return this.createFailureResult(
        'resources/read requires "uri" string',
        'MEDIUM',
        'MISSING_REQUIRED_PARAM'
      );
    }

    uri = canonicalizeString(uri);

    const accessResult = validateResourceAccess(uri, this.res, { baseDir: context.baseDir });
    if (!accessResult.passed) return this.wrapPolicyResult(accessResult);

    const quotaResult = this.quotaProvider.incrementAndCheck('method:resources/read', {
      minute: this.quotas['resources/read']?.minute,
      hour: this.quotas['resources/read']?.hour
    }, Date.now());

    if (!quotaResult.passed) {
      return this.createFailureResult(
        quotaResult.reason ?? 'Quota exceeded',
        'HIGH',
        'QUOTA_EXCEEDED'
      );
    }

    return this.createSuccessResult();
  }

  private checkSideEffectsAndEgress(message: McpMessage, context: SemanticsContext): ValidationResult {
    if (message.method !== 'tools/call') return this.createSuccessResult();

    const name = message.params?.name;
    const tool = name ? this.tools.get(name) : undefined;
    if (!tool) return this.createSuccessResult();

    if (tool.sideEffects && tool.sideEffects !== 'none') {
      const policy = context.policy ?? {};
      const allowed =
        (tool.sideEffects === 'read') ||
        (tool.sideEffects === 'write' && policy.allowWrites) ||
        (tool.sideEffects === 'network' && policy.allowNetwork);

      if (!allowed) {
        return this.createFailureResult(
          `Tool "${name}" requires ${tool.sideEffects} permission`,
          'HIGH',
          'SIDE_EFFECT_NOT_ALLOWED'
        );
      }
    }

    if (tool.maxEgressBytes != null) {
      const args = message.params?.arguments ?? message.params?.args ?? {};
      const sizeResult = this.safeSizeOrFail(args);
      if (!sizeResult.passed) return sizeResult;

      const estimatedEgress = (sizeResult.bytes ?? 0) * 16;
      if (estimatedEgress > tool.maxEgressBytes) {
        return this.createFailureResult(
          `Estimated egress exceeds policy: ${estimatedEgress} > ${tool.maxEgressBytes}`,
          'MEDIUM',
          'TOOL_EGRESS_LIMIT'
        );
      }
    }

    return this.createSuccessResult();
  }

  private safeSizeOrFail(obj: unknown): SizeResult {
    try {
      const serialized = JSON.stringify(obj);
      const result = this.createSuccessResult() as SizeResult;
      result.bytes = serialized.length;
      return result;
    } catch (e) {
      return this.createFailureResult(
        `Argument serialization error: ${(e as Error)?.message ?? 'unknown'}`,
        'MEDIUM',
        'ARG_SERIALIZATION_ERROR'
      );
    }
  }

  private wrapPolicyResult(result: PolicyValidationResult): ValidationResult {
    if (result.passed) {
      return this.createSuccessResult();
    }
    return this.createFailureResult(
      result.reason ?? 'Policy validation failed',
      result.severity ?? 'MEDIUM',
      result.violationType ?? 'POLICY_VIOLATION'
    );
  }
}
