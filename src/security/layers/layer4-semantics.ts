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
  simpleGlobMatch,
  ToolSpec,
  ResourcePolicy,
  MethodSpec,
  ChainingRule,
  PolicyValidationResult,
  ToolCallParams,
  SideEffects
} from './layer-utils/semantics/semantic-policies.js';

/** Layer 4 specific options */
export interface SemanticsLayerOptions extends ValidationLayerOptions {
  toolRegistry?: ToolSpec[];
  resourcePolicy?: Partial<ResourcePolicy>;
  methodSpec?: Partial<MethodSpec>;
  chainingRules?: ChainingRule[];
  enforceChaining?: boolean;
  /** Default action when no chaining rule matches. Default: 'deny' (for backward compatibility) */
  chainingDefaultAction?: 'allow' | 'deny';
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

/** Session entry for method chaining */
interface SessionEntry {
  method: string;
  timestamp: number;
  /** Tool name for tools/call methods */
  toolName?: string;
  /** Side effect of the tool (from registry) */
  toolSideEffect?: SideEffects;
}

export default class SemanticsValidationLayer extends ValidationLayer {
  private tools: Map<string, ToolSpec>;
  private res: ResourcePolicy;
  private methods: MethodSpec;
  private chaining: ChainingRule[];
  private enforceChaining: boolean;
  private chainingDefaultAction: 'allow' | 'deny';
  private quotas: Record<string, QuotaLimits>;
  private quotaProvider: QuotaProvider;
  private sessions: Map<string, SessionEntry>;
  private maxSessions: number;
  private sessionTtlMs: number;

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
    this.chaining = normalized.chainingRules;
    this.enforceChaining = options.enforceChaining ?? false; // Disabled by default
    // Default to 'deny' for backward compatibility (old behavior denied if no rule matched)
    this.chainingDefaultAction = options.chainingDefaultAction ?? 'deny';

    this.quotas = options.quotas ?? {};
    this.quotaProvider = options.quotaProvider ?? new InMemoryQuotaProvider({
      clockSkewMs: options.clockSkewMs ?? 1000
    });

    this.sessions = new Map();
    this.maxSessions = options.maxSessions ?? 10000;
    this.sessionTtlMs = options.sessionTtlMs ?? 30 * 60 * 1000; // 30 minutes default

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

    if (this.enforceChaining) {
      const chainResult = this.checkMethodChaining(msg, context);
      if (!chainResult.passed) return chainResult;
    }

    return this.createSuccessResult();
  }

  private getSessionKey(context: SemanticsContext): string {
    return context.sessionId ?? context.clientId ?? 'default';
  }

  private checkMethodChaining(message: McpMessage, context: SemanticsContext): ValidationResult {
    const sessionKey = this.getSessionKey(context);
    const now = Date.now();

    // Clean up expired sessions periodically
    if (this.sessions.size > this.maxSessions) {
      this.cleanExpiredSessions(now);
    }

    // Get previous session entry (if valid)
    const entry = this.sessions.get(sessionKey);
    const validEntry = entry && (now - entry.timestamp < this.sessionTtlMs) ? entry : null;

    // Build transition context
    const previousMethod = validEntry?.method ?? '*';
    const currentMethod = message.method ?? '';

    // Extract tool info for tools/call
    const currentToolName = currentMethod === 'tools/call' ? (message.params?.name as string | undefined) : undefined;
    const currentTool = currentToolName ? this.tools.get(currentToolName) : undefined;
    const currentSideEffect = currentTool?.sideEffects;

    const previousToolName = validEntry?.toolName;
    const previousSideEffect = validEntry?.toolSideEffect;

    // First-match-wins evaluation
    let matchedRule: ChainingRule | undefined;
    for (const rule of this.chaining) {
      // Check method match
      const methodMatch = (rule.from === previousMethod || rule.from === '*') &&
                          (rule.to === currentMethod || rule.to === '*');
      if (!methodMatch) continue;

      // Check tool match (only for tools/call)
      const fromToolMatch = simpleGlobMatch(rule.fromTool, previousToolName);
      const toToolMatch = simpleGlobMatch(rule.toTool, currentToolName);
      if (!fromToolMatch || !toToolMatch) continue;

      // Check side effect match
      const fromSideEffectMatch = rule.fromSideEffect === undefined || rule.fromSideEffect === previousSideEffect;
      const toSideEffectMatch = rule.toSideEffect === undefined || rule.toSideEffect === currentSideEffect;
      if (!fromSideEffectMatch || !toSideEffectMatch) continue;

      // All constraints matched
      matchedRule = rule;
      break;
    }

    // Determine action
    const action = matchedRule?.action ?? (matchedRule ? 'allow' : this.chainingDefaultAction);

    if (action === 'deny') {
      const ruleId = matchedRule?.id ? ` "${matchedRule.id}"` : '';
      const details = matchedRule?.fromSideEffect || matchedRule?.toSideEffect
        ? ` (${previousSideEffect ?? 'none'} → ${currentSideEffect ?? 'none'})`
        : '';
      return this.createFailureResult(
        `Transition denied by rule${ruleId}: ${previousMethod} → ${currentMethod}${details}`,
        'HIGH',
        'CHAIN_VIOLATION'
      );
    }

    // Update session with extended entry
    this.sessions.set(sessionKey, {
      method: currentMethod,
      timestamp: now,
      toolName: currentToolName,
      toolSideEffect: currentSideEffect
    });

    return this.createSuccessResult();
  }

  private cleanExpiredSessions(now: number): void {
    for (const [key, entry] of this.sessions) {
      if (now - entry.timestamp > this.sessionTtlMs) {
        this.sessions.delete(key);
      }
    }
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
    const contractResult = validateToolContract(tool, toolParams);
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
