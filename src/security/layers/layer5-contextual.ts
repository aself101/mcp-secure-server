/**
 * Layer 5 - User-configurable contextual validation layer.
 * Handles complex scenarios without bloating core framework.
 */

import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import {
  ContextualConfigBuilder,
  ContextualConfig,
  OAuthValidationConfig,
  DomainRestrictionsConfig,
  RateLimitingConfig,
  ResponseValidationConfig
} from './contextual-config-builder.js';

/** Layer 5 specific options extending base config */
export interface ContextualLayerOptions extends ValidationLayerOptions, ContextualConfig {}

/** Validator function type */
type ValidatorFunction = (message: unknown, context: ContextualContext) => ValidationResult | Promise<ValidationResult>;

/** Response validator function type */
type ResponseValidatorFunction = (response: unknown, request: unknown, context: ContextualContext) => ValidationResult | Promise<ValidationResult>;

/** Validator options */
interface ValidatorOptions {
  enabled: boolean;
  priority: number;
  skipOnSuccess: boolean;
  failOnError?: boolean;
}

/** Response validator options */
interface ResponseValidatorOptions {
  enabled: boolean;
  [key: string]: unknown;
}

/** Global rule options */
interface GlobalRuleOptions {
  enabled: boolean;
  priority: number;
  [key: string]: unknown;
}

/** Stored validator entry */
interface ValidatorEntry {
  validate: ValidatorFunction;
  options: ValidatorOptions;
}

/** Stored response validator entry */
interface ResponseValidatorEntry {
  validate: ResponseValidatorFunction;
  options: ResponseValidatorOptions;
}

/** Stored global rule entry */
interface GlobalRuleEntry {
  validate: ValidatorFunction;
  options: GlobalRuleOptions;
}

/** Context store entry */
interface ContextStoreEntry {
  value: unknown;
  expires: number;
}

/** Context with session info */
interface ContextualContext extends ValidationContext {
  sessionId?: string;
  [key: string]: unknown;
}

/** Message with method */
interface MessageWithMethod {
  method?: string;
  [key: string]: unknown;
}

/** Enhanced result with Layer 5 metadata */
interface EnhancedResult extends ValidationResult {
  detectionLayer?: string;
  validatorSource?: string;
}

/**
 * Layer 5 - Contextual Validation Layer for user-configurable security rules.
 *
 * Provides extensible validation with custom validators, response filtering,
 * domain restrictions, OAuth validation, and session-aware rate limiting.
 * This layer handles complex scenarios without bloating the core framework.
 *
 * @example Adding a custom validator
 * ```typescript
 * import { ContextualValidationLayer } from 'mcp-secure-server';
 *
 * const layer5 = new ContextualValidationLayer();
 *
 * layer5.addValidator('custom-check', (message, context) => {
 *   if (message.method === 'dangerous-tool') {
 *     return { passed: false, reason: 'Tool not allowed' };
 *   }
 *   return { passed: true };
 * });
 * ```
 *
 * @example Adding a response validator
 * ```typescript
 * layer5.addResponseValidator('pii-filter', (response, request, context) => {
 *   const text = JSON.stringify(response);
 *   if (/\d{3}-\d{2}-\d{4}/.test(text)) {
 *     return { passed: false, reason: 'SSN detected in response' };
 *   }
 *   return { passed: true };
 * });
 * ```
 */
export default class ContextualValidationLayer extends ValidationLayer {
  private validators: Map<string, ValidatorEntry>;
  private responseValidators: Map<string, ResponseValidatorEntry>;
  private globalRules: GlobalRuleEntry[];
  private contextStore: Map<string, ContextStoreEntry>;

  constructor(options: ContextualLayerOptions = {}) {
    super(options);

    this.validators = new Map();
    this.responseValidators = new Map();
    this.globalRules = [];
    this.contextStore = new Map();

    this.setupBuiltinValidators(options);

    this.logDebug('Contextual Validation Layer initialized');
  }

  addValidator(name: string, validator: ValidatorFunction, options: Partial<ValidatorOptions> = {}): void {
    if (typeof validator !== 'function') {
      throw new Error(`Validator ${name} must be a function`);
    }

    this.validators.set(name, {
      validate: validator,
      options: {
        enabled: true,
        priority: 100,
        skipOnSuccess: false,
        ...options
      }
    });
  }

  addResponseValidator(name: string, validator: ResponseValidatorFunction, options: Partial<ResponseValidatorOptions> = {}): void {
    this.responseValidators.set(name, {
      validate: validator,
      options: { enabled: true, ...options }
    });
  }

  addGlobalRule(rule: ValidatorFunction, options: Partial<GlobalRuleOptions> = {}): void {
    this.globalRules.push({
      validate: rule,
      options: { enabled: true, priority: 0, ...options }
    });
  }

  async validate(message: unknown, context: ContextualContext = {}): Promise<ValidationResult> {
    for (const { validate, options } of this.globalRules) {
      if (!options.enabled) continue;

      try {
        const result = await validate(message, context);
        if (result && !result.passed) {
          return this.enhanceResult(result, 'global_rule');
        }
      } catch (error) {
        this.logDebug(`Global rule error: ${(error as Error).message}`);
      }
    }

    const sortedValidators = Array.from(this.validators.entries())
      .filter(([_, { options }]) => options.enabled)
      .sort(([_, a], [__, b]) => (a.options.priority || 100) - (b.options.priority || 100));

    for (const [name, { validate, options }] of sortedValidators) {
      try {
        const result = await validate(message, context);
        if (result && !result.passed) {
          return this.enhanceResult(result, `validator:${name}`);
        }

        if (options.skipOnSuccess && result?.passed) {
          break;
        }
      } catch (error) {
        this.logDebug(`Validator ${name} error: ${(error as Error).message}`);

        if (options.failOnError) {
          return this.createFailureResult(
            `Validator ${name} failed: ${(error as Error).message}`,
            'MEDIUM',
            'VALIDATOR_ERROR'
          );
        }
      }
    }

    return this.createSuccessResult();
  }

  async validateResponse(response: unknown, request: unknown, context: ContextualContext = {}): Promise<ValidationResult> {
    if (this.responseValidators.size === 0) {
      return this.createSuccessResult();
    }

    for (const [name, { validate, options }] of this.responseValidators) {
      if (!options.enabled) continue;

      try {
        const result = await validate(response, request, context);
        if (result && !result.passed) {
          return this.enhanceResult(result, `response_validator:${name}`);
        }
      } catch (error) {
        this.logDebug(`Response validator ${name} error: ${(error as Error).message}`);
      }
    }

    return this.createSuccessResult();
  }

  setContext(key: string, value: unknown, ttl = 300000): void {
    // Prevent prototype pollution via context key
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new Error('Invalid context key: prototype pollution attempt');
    }
    this.contextStore.set(key, {
      value,
      expires: Date.now() + ttl
    });
  }

  getContext(key: string): unknown {
    const entry = this.contextStore.get(key);
    if (!entry) return null;

    if (Date.now() > entry.expires) {
      this.contextStore.delete(key);
      return null;
    }

    return entry.value;
  }

  private setupBuiltinValidators(options: ContextualLayerOptions): void {
    if (options.oauthValidation?.enabled) {
      this.addValidator('oauth_urls',
        (message, _context) => this.validateOAuthUrls(message, options.oauthValidation!),
        { priority: 50 }
      );
    }

    if (options.rateLimiting?.enabled) {
      this.addValidator('rate_limiting',
        (message, context) => this.validateRateLimit(message, context, options.rateLimiting!),
        { priority: 10 }
      );
    }

    if (options.domainRestrictions?.enabled) {
      this.addValidator('domain_restrictions',
        (message, _context) => this.validateDomainRestrictions(message, options.domainRestrictions!),
        { priority: 30 }
      );
    }

    if (options.responseValidation?.enabled) {
      this.addResponseValidator('malicious_content',
        (response, _request, _context) => this.validateResponseContent(response, options.responseValidation!)
      );
    }
  }

  private validateOAuthUrls(message: unknown, config: OAuthValidationConfig): ValidationResult {
    const urls = this.extractUrls(JSON.stringify(message));
    const { allowedDomains = [], blockDangerousSchemes = true } = config;

    for (const url of urls) {
      if (blockDangerousSchemes) {
        if (/^(javascript|vbscript|data):/i.test(url)) {
          return this.createFailureResult(
            `Dangerous URL scheme detected: ${url}`,
            'HIGH',
            'DANGEROUS_URL_SCHEME'
          );
        }
      }

      if (allowedDomains.length > 0) {
        try {
          const isAllowed = allowedDomains.some(domain =>
            url.includes(domain) || new URL(url).hostname.endsWith(domain)
          );

          if (!isAllowed) {
            return this.createFailureResult(
              `URL not in allowed domains: ${url}`,
              'MEDIUM',
              'DOMAIN_RESTRICTION_VIOLATION'
            );
          }
        } catch (_e) {
          // Invalid URL - skip
        }
      }
    }

    return this.createSuccessResult();
  }

  private validateRateLimit(message: unknown, context: ContextualContext, config: RateLimitingConfig): ValidationResult {
    const msg = message as MessageWithMethod;
    const key = `${context.sessionId ?? 'anonymous'}:${msg.method ?? 'unknown'}`;
    const history = (this.getContext(key) as number[]) ?? [];
    const now = Date.now();
    const windowMs = config.windowMs || 60000;

    const recentRequests = history.filter(time => now - time < windowMs);

    if (recentRequests.length >= (config.limit || 10)) {
      return this.createFailureResult(
        `Rate limit exceeded for ${msg.method ?? 'unknown'}`,
        'HIGH',
        'RATE_LIMIT_EXCEEDED'
      );
    }

    recentRequests.push(now);
    this.setContext(key, recentRequests, windowMs);

    return this.createSuccessResult();
  }

  private validateDomainRestrictions(message: unknown, config: DomainRestrictionsConfig): ValidationResult {
    const content = JSON.stringify(message);
    const urls = this.extractUrls(content);
    const { allowedDomains = [], blockedDomains = [] } = config;

    for (const url of urls) {
      try {
        const hostname = new URL(url).hostname;

        if (blockedDomains.length > 0) {
          const isBlocked = blockedDomains.some(domain =>
            hostname === domain || hostname.endsWith(`.${domain}`)
          );
          if (isBlocked) {
            return this.createFailureResult(
              `Domain blocked by policy: ${hostname}`,
              'HIGH',
              'BLOCKED_DOMAIN'
            );
          }
        }

        if (allowedDomains.length > 0) {
          const isAllowed = allowedDomains.some(domain =>
            hostname === domain || hostname.endsWith(`.${domain}`)
          );
          if (!isAllowed) {
            return this.createFailureResult(
              `Domain not in allowlist: ${hostname}`,
              'MEDIUM',
              'DOMAIN_NOT_ALLOWED'
            );
          }
        }
      } catch (_e) {
        // Invalid URL - skip domain check
      }
    }

    return this.createSuccessResult();
  }

  private validateResponseContent(response: unknown, config: ResponseValidationConfig): ValidationResult {
    const content = JSON.stringify(response);

    if (config.blockSensitiveData) {
      const patterns = [
        /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // emails
        /\b\d{3}-\d{2}-\d{4}\b/g, // SSNs
        /\b(?:\d{4}[\s-]?){3}\d{4}\b/g // credit cards
      ];

      for (const pattern of patterns) {
        if (pattern.test(content)) {
          return this.createFailureResult(
            'Sensitive data detected in response',
            'HIGH',
            'SENSITIVE_DATA_EXPOSURE'
          );
        }
      }
    }

    return this.createSuccessResult();
  }

  private extractUrls(text: string): string[] {
    const urlPattern = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/gi;
    return text.match(urlPattern) ?? [];
  }

  private enhanceResult(result: ValidationResult, source: string): EnhancedResult {
    return {
      ...result,
      detectionLayer: 'Layer5-Contextual',
      validatorSource: source,
      timestamp: Date.now()
    };
  }
}

export { ContextualConfigBuilder };

/**
 * Creates a pre-configured Layer 5 contextual validation layer with sensible defaults.
 *
 * This is a convenience factory function that creates a ContextualValidationLayer
 * with rate limiting enabled by default (20 requests per minute).
 *
 * @param customConfig - Optional configuration to override defaults
 * @returns A configured ContextualValidationLayer instance
 *
 * @example Basic usage with defaults
 * ```typescript
 * import { createContextualLayer } from 'mcp-secure-server';
 *
 * const layer5 = createContextualLayer();
 * ```
 *
 * @example Custom configuration
 * ```typescript
 * import { createContextualLayer } from 'mcp-secure-server';
 *
 * const layer5 = createContextualLayer({
 *   rateLimiting: { enabled: true, limit: 50, windowMs: 60000 },
 *   domainRestrictions: { enabled: true, blockedDomains: ['evil.com'] }
 * });
 * ```
 */
export function createContextualLayer(customConfig: Partial<ContextualLayerOptions> = {}): ContextualValidationLayer {
  const builder = new ContextualConfigBuilder();

  const defaultConfig = builder
    .enableRateLimiting(20, 60000)
    .build();

  return new ContextualValidationLayer({
    ...defaultConfig,
    ...customConfig
  });
}
