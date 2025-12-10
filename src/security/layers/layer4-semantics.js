// src/security/layers/layer4-semantics.js
// SemanticsValidationLayer: Main orchestration for semantic validation
// - Coordinates policy enforcement across tool contracts, resource access, and method chaining
// - Delegates to specialized modules for quotas, sessions, and policy definitions

import { ValidationLayer } from './validation-layer-base.js';
import { canonicalizeString } from './layer-utils/content/canonicalize.js';
import { InMemoryQuotaProvider } from './layer-utils/semantics/semantic-quotas.js';
import { SessionMemory } from './layer-utils/semantics/semantic-sessions.js';
import {
  getDefaultPolicies,
  normalizePolicies,
  validateToolCall as validateToolContract,
  validateResourceAccess
} from './layer-utils/semantics/semantic-policies.js';

/**
 * @typedef {import('./layer-utils/semantics/semantic-policies.js').ToolSpec} ToolSpec
 * @typedef {import('./layer-utils/semantics/semantic-policies.js').ResourcePolicy} ResourcePolicy
 * @typedef {import('./layer-utils/semantics/semantic-policies.js').MethodSpec} MethodSpec
 * @typedef {import('./layer-utils/semantics/semantic-policies.js').ChainingRule} ChainingRule
 */

export default class SemanticsValidationLayer extends ValidationLayer {
  constructor(options = {}) {
    super(options);

    const defaults = getDefaultPolicies();
    
    // Tool & Resource policy
    this.tools = new Map();
    (options.toolRegistry || defaults.tools).forEach(t => this.tools.set(t.name, t));

    // Normalize and store policies
    const normalized = normalizePolicies({
      resourcePolicy: options.resourcePolicy || defaults.resourcePolicy,
      methodSpec: options.methodSpec || defaults.methodSpec,
      chainingRules: options.chainingRules || defaults.chainingRules
    });

    this.res = normalized.resourcePolicy;
    this.methods = normalized.methodSpec;
    this.chaining = normalized.chainingRules;

    // Quotas and session management
    this.quotas = options.quotas || {};
    this.quotaProvider = options.quotaProvider || new InMemoryQuotaProvider({ 
      clockSkewMs: options.clockSkewMs ?? 1000 
    });

    this.sessions = new SessionMemory({ 
      maxEntries: options.maxSessions ?? 5000, 
      ttlMs: options.sessionTtlMs ?? 30*60_000 
    });

    this.logDebug('SemanticsValidationLayer initialized');
  }

  async validate(message, context = {}) {
    const methodResult = this.checkMethodSemantics(message);
    if (!methodResult.passed) return methodResult;

    if (message.method === 'tools/call') {
      const toolResult = this.checkToolCall(message, context);
      if (!toolResult.passed) return toolResult;
    }

    if (message.method === 'resources/read') {
      const resourceResult = this.checkResourceRead(message, context);
      if (!resourceResult.passed) return resourceResult;
    }

    const sideEffectResult = this.checkSideEffectsAndEgress(message, context);
    if (!sideEffectResult.passed) return sideEffectResult;
    /*
    const chainResult = this.checkMethodChaining(message, context);
    if (!chainResult.passed) return chainResult;
    */
    return this.createSuccessResult();
  }

  checkMethodSemantics(message) {
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

  checkToolCall(message, _context) {
    const { params } = message || {};
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

    const contractResult = validateToolContract(tool, params, message.method);
    if (!contractResult.passed) return contractResult;

    const quotaKey = `tool:${name}`;
    const quotaLimits = {
      minute: tool.quotaPerMinute ?? this.quotas[`${message.method}:${name}`]?.minute,
      hour: tool.quotaPerHour ?? this.quotas[`${message.method}:${name}`]?.hour
    };
    
    const quotaResult = this.quotaProvider.incrementAndCheck(quotaKey, quotaLimits, Date.now());
    if (!quotaResult.passed) {
      return this.createFailureResult(
        quotaResult.reason || `Quota exceeded for ${quotaKey}`, 
        'HIGH', 
        'QUOTA_EXCEEDED'
      );
    }

    return this.createSuccessResult();
  }

  checkResourceRead(message, context) {
    let uri = message?.params?.uri;
    if (!uri || typeof uri !== 'string') {
      return this.createFailureResult(
        'resources/read requires "uri" string',
        'MEDIUM',
        'MISSING_REQUIRED_PARAM'
      );
    }

    uri = canonicalizeString(uri);

    const accessResult = validateResourceAccess(uri, this.res, context);
    if (!accessResult.passed) return accessResult;

    const quotaResult = this.quotaProvider.incrementAndCheck('method:resources/read', {
      minute: this.quotas['resources/read']?.minute,
      hour: this.quotas['resources/read']?.hour
    }, Date.now());
    
    if (!quotaResult.passed) {
      return this.createFailureResult(
        quotaResult.reason || 'Quota exceeded',
        'HIGH',
        'QUOTA_EXCEEDED'
      );
    }

    return this.createSuccessResult();
  }

  checkSideEffectsAndEgress(message, context) {
    if (message.method !== 'tools/call') return this.createSuccessResult();

    const name = message?.params?.name;
    const tool = name && this.tools.get(name);
    if (!tool) return this.createSuccessResult();

    if (tool.sideEffects && tool.sideEffects !== 'none') {
      const policy = (context && context.policy) || {};
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
      const args = message?.params?.arguments ?? message?.params?.args ?? {};
      const sizeResult = this.safeSizeOrFail(args);
      if (!sizeResult.passed) return sizeResult;
      
      const estimatedEgress = sizeResult.bytes * 16;
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

  checkMethodChaining(message, context) {
    const sessionKey = this.getSessionKey(context);
    const now = Date.now();
    const previousMethod = this.sessions.get(sessionKey, now) || '*';
    const currentMethod = message.method;

    const allowed = this.chaining.some(rule => 
      (rule.from === previousMethod || rule.from === '*') && rule.to === currentMethod
    );

    if (allowed) {
      this.sessions.set(sessionKey, currentMethod, now);
    }

    if (!allowed) {
      return this.createFailureResult(
        `Method chaining not allowed: ${previousMethod} → ${currentMethod}`,
        'MEDIUM',
        'CHAIN_VIOLATION'
      );
    }

    return this.createSuccessResult();
  }

  safeSizeOrFail(obj) {
    try {
      const serialized = JSON.stringify(obj);
      return { passed: true, bytes: serialized.length };
    } catch (e) {
      return this.createFailureResult(
        `Argument serialization error: ${e?.message || 'unknown'}`,
        'MEDIUM',
        'ARG_SERIALIZATION_ERROR'
      );
    }
  }

  getSessionKey(context) {
    return context?.sessionId || context?.clientId || 'global';
  }
}