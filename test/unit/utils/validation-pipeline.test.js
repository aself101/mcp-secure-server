// tests/unit/utils/validation-pipeline.test.js
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ValidationPipeline } from '../../../src/security/utils/validation-pipeline.js';

// Mock layers for testing
class MockLayer {
  constructor(name, result = { passed: true }) {
    this.name = name;
    this.result = result;
    this.enabled = true;
    this.validateCalled = false;
  }

  getName() {
    return this.name;
  }

  isEnabled() {
    return this.enabled;
  }

  async validate(message, context) {
    this.validateCalled = true;
    this.lastMessage = message;
    this.lastContext = context;
    
    if (this.result instanceof Error) {
      throw this.result;
    }
    
    return {
      ...this.result,
      layerName: this.name
    };
  }
}

describe('ValidationPipeline', () => {
  let pipeline;
  let consoleSpy;

  beforeEach(() => {
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Constructor', () => {
    it('creates pipeline with empty layers', () => {
      pipeline = new ValidationPipeline();
      expect(pipeline.layers).toEqual([]);
      expect(typeof pipeline.errorSanitizer).toBe('object');
      expect(typeof pipeline.errorSanitizer.redact).toBe('function');
    });

    it('creates pipeline with provided layers', () => {
      const layer1 = new MockLayer('TestLayer1');
      const layer2 = new MockLayer('TestLayer2');
      
      pipeline = new ValidationPipeline([layer1, layer2]);
      expect(pipeline.layers).toHaveLength(2);
      expect(pipeline.layers[0]).toBe(layer1);
      expect(pipeline.layers[1]).toBe(layer2);
    });
  });

  describe('addLayer', () => {
    beforeEach(() => {
      pipeline = new ValidationPipeline();
    });

    it('adds layer to pipeline', () => {
      const layer = new MockLayer('TestLayer');
      pipeline.addLayer(layer);
      
      expect(pipeline.layers).toHaveLength(1);
      expect(pipeline.layers[0]).toBe(layer);
    });

    it('adds multiple layers in order', () => {
      const layer1 = new MockLayer('Layer1');
      const layer2 = new MockLayer('Layer2');
      
      pipeline.addLayer(layer1);
      pipeline.addLayer(layer2);
      
      expect(pipeline.layers).toHaveLength(2);
      expect(pipeline.layers[0]).toBe(layer1);
      expect(pipeline.layers[1]).toBe(layer2);
    });
  });

  describe('getLayers', () => {
    it('returns empty array for no layers', () => {
      pipeline = new ValidationPipeline();
      expect(pipeline.getLayers()).toEqual([]);
    });

    it('returns layer names', () => {
      const layer1 = new MockLayer('Structure');
      const layer2 = new MockLayer('Content');
      
      pipeline = new ValidationPipeline([layer1, layer2]);
      expect(pipeline.getLayers()).toEqual(['Structure', 'Content']);
    });
  });

  describe('validate - Success Cases', () => {
    it('passes with no layers', async () => {
      pipeline = new ValidationPipeline();
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(result.layerName).toBe('Pipeline');
      expect(result.reason).toBe('All validation layers passed');
    });

    it('passes when all layers pass', async () => {
      const layer1 = new MockLayer('Layer1', { passed: true });
      const layer2 = new MockLayer('Layer2', { passed: true });
      
      pipeline = new ValidationPipeline([layer1, layer2]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(layer1.validateCalled).toBe(true);
      expect(layer2.validateCalled).toBe(true);
    });

    it('passes message and context to layers', async () => {
      const layer = new MockLayer('TestLayer', { passed: true });
      pipeline = new ValidationPipeline([layer]);
      
      const message = { method: 'test', params: { arg: 'value' } };
      const context = { logger: { log: vi.fn() } };
      
      await pipeline.validate(message, context);
      
      expect(layer.lastMessage).toBe(message);
      expect(layer.lastContext).toBe(context);
    });
  });

  describe('validate - Failure Cases', () => {
    it('fails fast on first layer failure', async () => {
      const layer1 = new MockLayer('Layer1', { 
        passed: false, 
        severity: 'HIGH', 
        reason: 'Invalid structure',
        violationType: 'VALIDATION_ERROR'
      });
      const layer2 = new MockLayer('Layer2', { passed: true });
      
      pipeline = new ValidationPipeline([layer1, layer2]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(false);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Invalid structure');
      expect(result.severity).toBe('HIGH');
      expect(result.violationType).toBe('VALIDATION_ERROR');
      
      // First layer called, second layer not called
      expect(layer1.validateCalled).toBe(true);
      expect(layer2.validateCalled).toBe(false);
    });

    it('handles layer with only allowed property', async () => {
      const layer = new MockLayer('TestLayer', { 
        allowed: false, 
        reason: 'Not allowed' 
      });
      
      pipeline = new ValidationPipeline([layer]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(false);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Not allowed');
    });
  });

  describe('validate - Error Handling', () => {
    it('handles layer throwing exception', async () => {
      const error = new Error('Layer crashed');
      const layer = new MockLayer('CrashLayer', error);
      
      pipeline = new ValidationPipeline([layer]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(false);
      expect(result.allowed).toBe(false);
      expect(result.severity).toBe('CRITICAL');
      expect(result.violationType).toBe('VALIDATION_ERROR');
      expect(result.reason).toContain('Layer validation error');
      expect(result.layerName).toBe('CrashLayer');
    });

    it('sanitizes error messages', async () => {
      const error = new Error('AWS key AKIAIOSFODNN7EXAMPLE found in request');
      const layer = new MockLayer('SecureLayer', error);
      
      pipeline = new ValidationPipeline([layer]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.reason).toContain('****AWS_KEY****');
      expect(result.reason).not.toContain('AKIAIOSFODNN7EXAMPLE');
    });
  });

  describe('validate - Disabled Layers', () => {
    it('skips disabled layers', async () => {
      const layer1 = new MockLayer('Layer1', { passed: true });
      const layer2 = new MockLayer('Layer2', { passed: true });
      const layer3 = new MockLayer('Layer3', { passed: true });
      
      layer2.enabled = false; // Disable middle layer
      
      pipeline = new ValidationPipeline([layer1, layer2, layer3]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(true);
      expect(layer1.validateCalled).toBe(true);
      expect(layer2.validateCalled).toBe(false); // Skipped
      expect(layer3.validateCalled).toBe(true);
    });
  });

  describe('validate - Result Normalization', () => {
    it('normalizes results with missing fields', async () => {
      const layer = new MockLayer('MinimalLayer', { 
        passed: true 
        // Missing other fields
      });
      
      pipeline = new ValidationPipeline([layer]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
      expect(typeof result.severity).toBe('string');
      expect(typeof result.reason).toBe('string');
      expect(result.violationType).toBe(null);
      expect(typeof result.confidence).toBe('number');
      expect(typeof result.timestamp).toBe('number');
    });

    it('handles mixed passed/allowed result formats', async () => {
      const layer1 = new MockLayer('OldFormat', { allowed: true });
      const layer2 = new MockLayer('NewFormat', { passed: true });
      
      pipeline = new ValidationPipeline([layer1, layer2]);
      const message = { method: 'test' };
      
      const result = await pipeline.validate(message);
      
      expect(result.passed).toBe(true);
      expect(result.allowed).toBe(true);
    });
  });

  describe('validate - Logging Integration', () => {
    it('calls logger when provided in context', async () => {
      const logger = {
        logSecurityDecision: vi.fn()
      };
      
      const layer = new MockLayer('TestLayer', { passed: true });
      pipeline = new ValidationPipeline([layer]);
      
      const message = { method: 'test' };
      const context = { logger };
      
      await pipeline.validate(message, context);
      
      // Should be called for layer result and final success
      expect(logger.logSecurityDecision).toHaveBeenCalledTimes(2);
    });

    it('handles missing logger gracefully', async () => {
      const layer = new MockLayer('TestLayer', { passed: true });
      pipeline = new ValidationPipeline([layer]);
      
      const message = { method: 'test' };
      const context = {}; // No logger
      
      // Should not throw
      const result = await pipeline.validate(message, context);
      expect(result.passed).toBe(true);
    });
  });

  describe('Performance', () => {
    it('completes validation quickly', async () => {
      const layers = Array.from({ length: 10 }, (_, i) => 
        new MockLayer(`Layer${i}`, { passed: true })
      );
      
      pipeline = new ValidationPipeline(layers);
      const message = { method: 'test' };
      
      const start = performance.now();
      const result = await pipeline.validate(message);
      const duration = performance.now() - start;
      
      expect(result.passed).toBe(true);
      expect(duration).toBeLessThan(50); // Should complete in <50ms
    });

    it('handles large messages efficiently', async () => {
      const layer = new MockLayer('TestLayer', { passed: true });
      pipeline = new ValidationPipeline([layer]);
      
      const largeMessage = {
        method: 'test',
        params: {
          data: 'x'.repeat(10000) // 10KB of data
        }
      };
      
      const start = performance.now();
      const result = await pipeline.validate(largeMessage);
      const duration = performance.now() - start;
      
      expect(result.passed).toBe(true);
      expect(duration).toBeLessThan(100); // Should handle large messages quickly
    });
  });
});