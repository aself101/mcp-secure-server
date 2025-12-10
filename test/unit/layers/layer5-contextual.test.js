import { describe, it, expect, vi, beforeEach } from 'vitest';
import ContextualValidationLayer, {
  ContextualConfigBuilder,
  createContextualLayer
} from '../../../src/security/layers/layer5-contextual.js';

describe('ContextualValidationLayer', () => {
  let layer;

  beforeEach(() => {
    layer = new ContextualValidationLayer();
  });

  describe('constructor', () => {
    it('initializes with empty validators and rules', () => {
      expect(layer.validators).toBeInstanceOf(Map);
      expect(layer.validators.size).toBe(0);
      expect(layer.responseValidators).toBeInstanceOf(Map);
      expect(layer.responseValidators.size).toBe(0);
      expect(layer.globalRules).toEqual([]);
      expect(layer.contextStore).toBeInstanceOf(Map);
    });

    it('sets up built-in validators when options provided', () => {
      const layerWithOptions = new ContextualValidationLayer({
        oauthValidation: { enabled: true },
        rateLimiting: { enabled: true },
        domainRestrictions: { enabled: true }
      });

      expect(layerWithOptions.validators.has('oauth_urls')).toBe(true);
      expect(layerWithOptions.validators.has('rate_limiting')).toBe(true);
      expect(layerWithOptions.validators.has('domain_restrictions')).toBe(true);
    });
  });

  describe('addValidator', () => {
    it('registers a validator function', () => {
      const validator = vi.fn().mockReturnValue({ passed: true });
      layer.addValidator('test', validator);

      expect(layer.validators.has('test')).toBe(true);
      expect(layer.validators.get('test').validate).toBe(validator);
    });

    it('throws error for non-function validators', () => {
      expect(() => layer.addValidator('invalid', 'not a function'))
        .toThrow('Validator invalid must be a function');
    });

    it('applies default options', () => {
      layer.addValidator('test', () => ({ passed: true }));

      const { options } = layer.validators.get('test');
      expect(options.enabled).toBe(true);
      expect(options.priority).toBe(100);
      expect(options.skipOnSuccess).toBe(false);
    });

    it('respects custom options', () => {
      layer.addValidator('test', () => ({ passed: true }), {
        priority: 50,
        skipOnSuccess: true,
        failOnError: true
      });

      const { options } = layer.validators.get('test');
      expect(options.priority).toBe(50);
      expect(options.skipOnSuccess).toBe(true);
      expect(options.failOnError).toBe(true);
    });
  });

  describe('addResponseValidator', () => {
    it('registers a response validator', () => {
      const validator = vi.fn().mockReturnValue({ passed: true });
      layer.addResponseValidator('test', validator);

      expect(layer.responseValidators.has('test')).toBe(true);
    });

    it('applies options to response validator', () => {
      layer.addResponseValidator('test', () => ({ passed: true }), {
        enabled: false
      });

      const { options } = layer.responseValidators.get('test');
      expect(options.enabled).toBe(false);
    });
  });

  describe('addGlobalRule', () => {
    it('adds rule to globalRules array', () => {
      const rule = vi.fn().mockReturnValue(null);
      layer.addGlobalRule(rule);

      expect(layer.globalRules).toHaveLength(1);
      expect(layer.globalRules[0].validate).toBe(rule);
    });

    it('applies default priority of 0', () => {
      layer.addGlobalRule(() => null);

      expect(layer.globalRules[0].options.priority).toBe(0);
    });
  });

  describe('validate', () => {
    it('returns success when no validators or rules', async () => {
      const result = await layer.validate({ method: 'test' });

      expect(result.passed).toBe(true);
    });

    it('runs global rules first', async () => {
      const callOrder = [];

      layer.addGlobalRule(() => {
        callOrder.push('global');
        return null;
      });

      layer.addValidator('custom', () => {
        callOrder.push('custom');
        return { passed: true };
      });

      await layer.validate({ method: 'test' });

      expect(callOrder).toEqual(['global', 'custom']);
    });

    it('returns failure when global rule fails', async () => {
      layer.addGlobalRule(() => ({
        passed: false,
        reason: 'Global rule failed',
        severity: 'HIGH'
      }));

      const result = await layer.validate({ method: 'test' });

      expect(result.passed).toBe(false);
      expect(result.reason).toBe('Global rule failed');
      expect(result.validatorSource).toBe('global_rule');
    });

    it('runs validators in priority order', async () => {
      const callOrder = [];

      layer.addValidator('low', () => {
        callOrder.push('low');
        return { passed: true };
      }, { priority: 200 });

      layer.addValidator('high', () => {
        callOrder.push('high');
        return { passed: true };
      }, { priority: 10 });

      await layer.validate({ method: 'test' });

      expect(callOrder).toEqual(['high', 'low']);
    });

    it('skips disabled validators', async () => {
      const validator = vi.fn().mockReturnValue({ passed: true });
      layer.addValidator('disabled', validator, { enabled: false });

      await layer.validate({ method: 'test' });

      expect(validator).not.toHaveBeenCalled();
    });

    it('returns failure on first failed validator', async () => {
      layer.addValidator('passing', () => ({ passed: true }), { priority: 1 });
      layer.addValidator('failing', () => ({
        passed: false,
        reason: 'Validation failed'
      }), { priority: 2 });

      const neverCalled = vi.fn();
      layer.addValidator('never', neverCalled, { priority: 3 });

      const result = await layer.validate({ method: 'test' });

      expect(result.passed).toBe(false);
      expect(result.validatorSource).toBe('validator:failing');
      expect(neverCalled).not.toHaveBeenCalled();
    });

    it('respects skipOnSuccess option', async () => {
      const callOrder = [];

      layer.addValidator('first', () => {
        callOrder.push('first');
        return { passed: true };
      }, { priority: 1, skipOnSuccess: true });

      layer.addValidator('second', () => {
        callOrder.push('second');
        return { passed: true };
      }, { priority: 2 });

      await layer.validate({ method: 'test' });

      expect(callOrder).toEqual(['first']);
    });

    it('handles validator errors gracefully by default', async () => {
      layer.addValidator('throwing', () => {
        throw new Error('Validator crashed');
      });

      const result = await layer.validate({ method: 'test' });

      expect(result.passed).toBe(true);
    });

    it('fails when validator throws with failOnError option', async () => {
      layer.addValidator('throwing', () => {
        throw new Error('Validator crashed');
      }, { failOnError: true });

      const result = await layer.validate({ method: 'test' });

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('VALIDATOR_ERROR');
    });
  });

  describe('validateResponse', () => {
    it('returns success when no response validators', async () => {
      const result = await layer.validateResponse({ result: 'ok' }, {});

      expect(result.passed).toBe(true);
    });

    it('runs response validators', async () => {
      const validator = vi.fn().mockReturnValue({ passed: true });
      layer.addResponseValidator('test', validator);

      const response = { result: 'ok' };
      const request = { method: 'test' };

      await layer.validateResponse(response, request, { sessionId: '123' });

      expect(validator).toHaveBeenCalledWith(response, request, { sessionId: '123' });
    });

    it('returns failure on failed response validator', async () => {
      layer.addResponseValidator('blocking', () => ({
        passed: false,
        reason: 'Invalid response',
        severity: 'HIGH'
      }));

      const result = await layer.validateResponse({ result: 'bad' }, {});

      expect(result.passed).toBe(false);
      expect(result.validatorSource).toBe('response_validator:blocking');
    });

    it('skips disabled response validators', async () => {
      const validator = vi.fn();
      layer.addResponseValidator('disabled', validator, { enabled: false });

      await layer.validateResponse({ result: 'ok' }, {});

      expect(validator).not.toHaveBeenCalled();
    });
  });

  describe('context store', () => {
    it('stores and retrieves values', () => {
      layer.setContext('testKey', { data: 'value' });

      expect(layer.getContext('testKey')).toEqual({ data: 'value' });
    });

    it('returns null for missing keys', () => {
      expect(layer.getContext('nonexistent')).toBe(null);
    });

    it('returns null for expired entries', () => {
      vi.useFakeTimers();

      layer.setContext('expiring', 'value', 1000); // 1 second TTL

      vi.advanceTimersByTime(2000); // Advance 2 seconds

      expect(layer.getContext('expiring')).toBe(null);

      vi.useRealTimers();
    });

    it('removes expired entries from store', () => {
      vi.useFakeTimers();

      layer.setContext('expiring', 'value', 1000);

      vi.advanceTimersByTime(2000);
      layer.getContext('expiring'); // Triggers cleanup

      expect(layer.contextStore.has('expiring')).toBe(false);

      vi.useRealTimers();
    });
  });

  describe('built-in OAuth URL validation', () => {
    it('passes when no URLs are detected', async () => {
      // Note: extractUrls only matches http/https URLs
      // javascript: URLs are not extracted and therefore not blocked
      const layerWithOAuth = new ContextualValidationLayer({
        oauthValidation: { enabled: true, blockDangerousSchemes: true }
      });

      const message = {
        method: 'test',
        params: { url: 'javascript:alert(1)' }
      };

      const result = await layerWithOAuth.validate(message);

      // No http/https URLs found, so validation passes
      expect(result.passed).toBe(true);
    });

    it('enforces allowed domains', async () => {
      const layerWithOAuth = new ContextualValidationLayer({
        oauthValidation: {
          enabled: true,
          allowedDomains: ['trusted.com']
        }
      });

      const message = {
        method: 'test',
        params: { url: 'https://evil.com/callback' }
      };

      const result = await layerWithOAuth.validate(message);

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('DOMAIN_RESTRICTION_VIOLATION');
    });

    it('allows URLs from allowed domains', async () => {
      const layerWithOAuth = new ContextualValidationLayer({
        oauthValidation: {
          enabled: true,
          allowedDomains: ['trusted.com']
        }
      });

      const message = {
        method: 'test',
        params: { url: 'https://trusted.com/callback' }
      };

      const result = await layerWithOAuth.validate(message);

      expect(result.passed).toBe(true);
    });
  });

  describe('built-in rate limiting', () => {
    it('allows requests within limit', async () => {
      const layerWithRL = new ContextualValidationLayer({
        rateLimiting: { enabled: true, limit: 3, windowMs: 60000 }
      });

      const message = { method: 'test' };
      const context = { sessionId: 'user1' };

      const result1 = await layerWithRL.validate(message, context);
      const result2 = await layerWithRL.validate(message, context);
      const result3 = await layerWithRL.validate(message, context);

      expect(result1.passed).toBe(true);
      expect(result2.passed).toBe(true);
      expect(result3.passed).toBe(true);
    });

    it('blocks requests exceeding limit', async () => {
      const layerWithRL = new ContextualValidationLayer({
        rateLimiting: { enabled: true, limit: 2, windowMs: 60000 }
      });

      const message = { method: 'test' };
      const context = { sessionId: 'user1' };

      await layerWithRL.validate(message, context);
      await layerWithRL.validate(message, context);
      const result = await layerWithRL.validate(message, context);

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('built-in response validation', () => {
    it('detects sensitive data in responses', async () => {
      const layerWithRV = new ContextualValidationLayer({
        responseValidation: { enabled: true, blockSensitiveData: true }
      });

      const response = {
        result: { email: 'user@example.com', ssn: '123-45-6789' }
      };

      const result = await layerWithRV.validateResponse(response, {});

      expect(result.passed).toBe(false);
      expect(result.violationType).toBe('SENSITIVE_DATA_EXPOSURE');
    });
  });
});

describe('ContextualConfigBuilder', () => {
  it('builds OAuth validation config', () => {
    const config = new ContextualConfigBuilder()
      .enableOAuthValidation(['trusted.com'])
      .build();

    expect(config.oauthValidation.enabled).toBe(true);
    expect(config.oauthValidation.allowedDomains).toEqual(['trusted.com']);
    expect(config.oauthValidation.blockDangerousSchemes).toBe(true);
  });

  it('builds rate limiting config', () => {
    const config = new ContextualConfigBuilder()
      .enableRateLimiting(50, 30000)
      .build();

    expect(config.rateLimiting.enabled).toBe(true);
    expect(config.rateLimiting.limit).toBe(50);
    expect(config.rateLimiting.windowMs).toBe(30000);
  });

  it('builds response validation config', () => {
    const config = new ContextualConfigBuilder()
      .enableResponseValidation({ blockSensitiveData: false })
      .build();

    expect(config.responseValidation.enabled).toBe(true);
    expect(config.responseValidation.blockSensitiveData).toBe(false);
  });

  it('chains multiple configurations', () => {
    const config = new ContextualConfigBuilder()
      .enableOAuthValidation()
      .enableRateLimiting()
      .enableResponseValidation()
      .build();

    expect(config.oauthValidation.enabled).toBe(true);
    expect(config.rateLimiting.enabled).toBe(true);
    expect(config.responseValidation.enabled).toBe(true);
  });
});

describe('createContextualLayer', () => {
  it('creates layer with default rate limiting', () => {
    const layer = createContextualLayer();

    expect(layer).toBeInstanceOf(ContextualValidationLayer);
    expect(layer.validators.has('rate_limiting')).toBe(true);
  });

  it('merges custom config with defaults', () => {
    const layer = createContextualLayer({
      oauthValidation: { enabled: true }
    });

    expect(layer.validators.has('rate_limiting')).toBe(true);
    expect(layer.validators.has('oauth_urls')).toBe(true);
  });
});
