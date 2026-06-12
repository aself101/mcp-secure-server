import { describe, it, expect } from 'vitest';
import { createValidationPipeline } from '@/security/utils/pipeline-factory.js';

describe('Pipeline Factory', () => {
  describe('maxStringLength threading', () => {
    const longStringMessage = (length) => ({
      jsonrpc: '2.0',
      method: 'custom/test',
      id: 1,
      params: { data: 'x'.repeat(length) }
    });

    it('should reject strings over the default limit when no override is given', async () => {
      const pipeline = createValidationPipeline({});
      const result = await pipeline.validate(longStringMessage(6000), {});

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });

    it('should thread options.maxStringLength into Layer 1', async () => {
      const pipeline = createValidationPipeline({ maxStringLength: 100_000 });
      const result = await pipeline.validate(longStringMessage(6000), {});

      expect(result.reason ?? '').not.toContain('String parameter too long');
    });

    it('should still reject strings over the raised limit', async () => {
      const pipeline = createValidationPipeline({ maxStringLength: 10_000 });
      const result = await pipeline.validate(longStringMessage(10_001), {});

      expect(result.passed).toBe(false);
      expect(result.reason).toContain('String parameter too long');
    });
  });
});
