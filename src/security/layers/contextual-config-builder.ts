/**
 * Configuration builder for Layer 5 contextual validation.
 * Provides fluent API for common configuration scenarios.
 */

/** OAuth validation configuration */
export interface OAuthValidationConfig {
  enabled: boolean;
  allowedDomains: string[];
  blockDangerousSchemes: boolean;
}

/** Domain restrictions configuration */
export interface DomainRestrictionsConfig {
  enabled: boolean;
  blockedDomains: string[];
  allowedDomains: string[];
}

/** Rate limiting configuration */
export interface RateLimitingConfig {
  enabled: boolean;
  limit: number;
  windowMs: number;
}

/** Response validation configuration */
export interface ResponseValidationConfig {
  enabled: boolean;
  blockSensitiveData: boolean;
  [key: string]: unknown;
}

/** Domain restriction options */
export interface DomainRestrictionOptions {
  blockedDomains?: string[];
  allowedDomains?: string[];
}

/** Response validation options */
export interface ResponseValidationOptions {
  blockSensitiveData?: boolean;
  [key: string]: unknown;
}

/** Full contextual configuration */
export interface ContextualConfig {
  oauthValidation?: OAuthValidationConfig;
  domainRestrictions?: DomainRestrictionsConfig;
  rateLimiting?: RateLimitingConfig;
  responseValidation?: ResponseValidationConfig;
}

export class ContextualConfigBuilder {
  private config: ContextualConfig;

  constructor() {
    this.config = {};
  }

  enableOAuthValidation(allowedDomains: string[] = []): this {
    this.config.oauthValidation = {
      enabled: true,
      allowedDomains,
      blockDangerousSchemes: true
    };
    return this;
  }

  enableDomainRestrictions(options: DomainRestrictionOptions = {}): this {
    this.config.domainRestrictions = {
      enabled: true,
      blockedDomains: options.blockedDomains ?? [],
      allowedDomains: options.allowedDomains ?? []
    };
    return this;
  }

  enableRateLimiting(limit = 10, windowMs = 60000): this {
    this.config.rateLimiting = {
      enabled: true,
      limit,
      windowMs
    };
    return this;
  }

  enableResponseValidation(options: ResponseValidationOptions = {}): this {
    this.config.responseValidation = {
      enabled: true,
      blockSensitiveData: true,
      ...options
    };
    return this;
  }

  build(): ContextualConfig {
    return this.config;
  }
}
