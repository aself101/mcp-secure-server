/**
 * Built-in validators for Layer 5 contextual validation.
 * Provides reusable validation functions for OAuth, rate limiting,
 * domain restrictions, and response content filtering.
 */

import { ValidationResult } from './validation-layer-base.js';
import {
  OAuthValidationConfig,
  DomainRestrictionsConfig,
  RateLimitingConfig,
  ResponseValidationConfig
} from './contextual-config-builder.js';
import type { Severity, ViolationType } from '../../types/index.js';

/** Context with session info for rate limiting */
export interface RateLimitContext {
  sessionId?: string;
  [key: string]: unknown;
}

/** Message with method for rate limiting */
export interface MessageWithMethod {
  method?: string;
  [key: string]: unknown;
}

/** Context store interface for rate limiting */
export interface ContextStore {
  get(key: string): unknown;
  set(key: string, value: unknown, ttl?: number): void;
}

/** Result factory interface */
export interface ResultFactory {
  createSuccessResult(): ValidationResult;
  createFailureResult(reason: string, severity: Severity, violationType: ViolationType): ValidationResult;
}

/**
 * Extract URLs from text content.
 * Matches http and https URLs.
 */
export function extractUrls(text: string): string[] {
  const urlPattern = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/gi;
  return text.match(urlPattern) ?? [];
}

/**
 * Validate OAuth URLs for dangerous schemes and allowed domains.
 *
 * @param message - Message to validate
 * @param config - OAuth validation configuration
 * @param factory - Result factory for creating validation results
 * @returns Validation result
 */
export function validateOAuthUrls(
  message: unknown,
  config: OAuthValidationConfig,
  factory: ResultFactory
): ValidationResult {
  const urls = extractUrls(JSON.stringify(message));
  const { allowedDomains = [], blockDangerousSchemes = true } = config;

  for (const url of urls) {
    if (blockDangerousSchemes) {
      if (/^(javascript|vbscript|data):/i.test(url)) {
        return factory.createFailureResult(
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
          return factory.createFailureResult(
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

  return factory.createSuccessResult();
}

/**
 * Validate rate limits based on session and method.
 *
 * @param message - Message to validate
 * @param context - Context with session info
 * @param config - Rate limiting configuration
 * @param contextStore - Context store for tracking request history
 * @param factory - Result factory for creating validation results
 * @returns Validation result
 */
export function validateRateLimit(
  message: unknown,
  context: RateLimitContext,
  config: RateLimitingConfig,
  contextStore: ContextStore,
  factory: ResultFactory
): ValidationResult {
  const msg = message as MessageWithMethod;
  const key = `${context.sessionId ?? 'anonymous'}:${msg.method ?? 'unknown'}`;
  const history = (contextStore.get(key) as number[]) ?? [];
  const now = Date.now();
  const windowMs = config.windowMs || 60000;

  const recentRequests = history.filter(time => now - time < windowMs);

  if (recentRequests.length >= (config.limit || 10)) {
    return factory.createFailureResult(
      `Rate limit exceeded for ${msg.method ?? 'unknown'}`,
      'HIGH',
      'RATE_LIMIT_EXCEEDED'
    );
  }

  recentRequests.push(now);
  contextStore.set(key, recentRequests, windowMs);

  return factory.createSuccessResult();
}

/**
 * Validate domain restrictions for URLs in message content.
 *
 * @param message - Message to validate
 * @param config - Domain restrictions configuration
 * @param factory - Result factory for creating validation results
 * @returns Validation result
 */
export function validateDomainRestrictions(
  message: unknown,
  config: DomainRestrictionsConfig,
  factory: ResultFactory
): ValidationResult {
  const content = JSON.stringify(message);
  const urls = extractUrls(content);
  const { allowedDomains = [], blockedDomains = [] } = config;

  for (const url of urls) {
    try {
      const hostname = new URL(url).hostname;

      if (blockedDomains.length > 0) {
        const isBlocked = blockedDomains.some(domain =>
          hostname === domain || hostname.endsWith(`.${domain}`)
        );
        if (isBlocked) {
          return factory.createFailureResult(
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
          return factory.createFailureResult(
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

  return factory.createSuccessResult();
}

/**
 * Validate response content for sensitive data exposure.
 *
 * @param response - Response to validate
 * @param config - Response validation configuration
 * @param factory - Result factory for creating validation results
 * @returns Validation result
 */
export function validateResponseContent(
  response: unknown,
  config: ResponseValidationConfig,
  factory: ResultFactory
): ValidationResult {
  const content = JSON.stringify(response);

  if (config.blockSensitiveData) {
    // Strip UUIDs before sensitive data checks — digit-heavy UUIDs false-positive as credit cards
    const stripped = content.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '');
    const patterns = [
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, // emails
      /\b\d{3}-\d{2}-\d{4}\b/g, // SSNs
      /\b(?:\d{4}[\s-]?){3}\d{4}\b/g // credit cards
    ];

    for (const pattern of patterns) {
      if (pattern.test(stripped)) {
        return factory.createFailureResult(
          'Sensitive data detected in response',
          'HIGH',
          'SENSITIVE_DATA_EXPOSURE'
        );
      }
    }
  }

  return factory.createSuccessResult();
}
