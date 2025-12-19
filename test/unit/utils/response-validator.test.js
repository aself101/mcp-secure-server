import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createResponseWrapper } from '../../../src/security/utils/response-validator.js';

describe('createResponseWrapper', () => {
  let mockLogger;

  beforeEach(() => {
    mockLogger = {
      logInfo: vi.fn()
    };
  });

  describe('when Layer 5 is not available', () => {
    it('returns original response when layer5 is undefined', async () => {
      const wrapper = createResponseWrapper(undefined, mockLogger, 'test-tool');
      const handler = vi.fn().mockResolvedValue({ content: [{ type: 'text', text: 'hello' }] });
      const wrapped = wrapper(handler);

      const result = await wrapped({ input: 'test' });

      expect(result).toEqual({ content: [{ type: 'text', text: 'hello' }] });
      expect(handler).toHaveBeenCalledWith({ input: 'test' });
      expect(mockLogger.logInfo).not.toHaveBeenCalled();
    });

    it('returns original response when layer5 has no validateResponse method', async () => {
      const invalidLayer5 = { someOtherMethod: vi.fn() };
      const wrapper = createResponseWrapper(invalidLayer5, mockLogger, 'test-tool');
      const handler = vi.fn().mockResolvedValue({ data: 'success' });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({ data: 'success' });
    });

    it('returns original response when validateResponse is not a function', async () => {
      const invalidLayer5 = { validateResponse: 'not a function' };
      const wrapper = createResponseWrapper(invalidLayer5, mockLogger, 'test-tool');
      const handler = vi.fn().mockResolvedValue({ value: 42 });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({ value: 42 });
    });
  });

  describe('when Layer 5 passes validation', () => {
    it('returns original response when validation passes', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({ passed: true })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'safe-tool');
      const handler = vi.fn().mockResolvedValue({ content: [{ type: 'text', text: 'safe content' }] });
      const wrapped = wrapper(handler);

      const result = await wrapped({ query: 'test' });

      expect(result).toEqual({ content: [{ type: 'text', text: 'safe content' }] });
      expect(mockLayer5.validateResponse).toHaveBeenCalledWith(
        { content: [{ type: 'text', text: 'safe content' }] },
        { tool: 'safe-tool', arguments: { query: 'test' } },
        {}
      );
      expect(mockLogger.logInfo).not.toHaveBeenCalled();
    });
  });

  describe('when Layer 5 fails validation', () => {
    it('returns blocked response with custom reason', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({
          passed: false,
          reason: 'PII detected in response',
          severity: 'CRITICAL',
          violationType: 'PII_LEAK'
        })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'pii-tool');
      const handler = vi.fn().mockResolvedValue({ content: [{ type: 'text', text: 'SSN: 123-45-6789' }] });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({
        content: [{ type: 'text', text: 'Response blocked: PII detected in response' }],
        isError: true
      });
      expect(mockLogger.logInfo).toHaveBeenCalledWith(
        '[RESPONSE_BLOCKED] Tool: pii-tool, Reason: PII detected in response, Severity: CRITICAL, Type: PII_LEAK'
      );
    });

    it('returns blocked response with default reason when not provided', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({ passed: false })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'blocked-tool');
      const handler = vi.fn().mockResolvedValue({ data: 'blocked' });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({
        content: [{ type: 'text', text: 'Response blocked: Response validation failed' }],
        isError: true
      });
      expect(mockLogger.logInfo).toHaveBeenCalledWith(
        '[RESPONSE_BLOCKED] Tool: blocked-tool, Reason: Response validation failed, Severity: HIGH, Type: RESPONSE_BLOCKED'
      );
    });

    it('does not log when logger is null', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({
          passed: false,
          reason: 'Blocked'
        })
      };
      const wrapper = createResponseWrapper(mockLayer5, null, 'no-logger-tool');
      const handler = vi.fn().mockResolvedValue({ data: 'test' });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({
        content: [{ type: 'text', text: 'Response blocked: Blocked' }],
        isError: true
      });
    });
  });

  describe('when Layer 5 throws an error', () => {
    it('returns original response and logs error (graceful degradation)', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockRejectedValue(new Error('Validator crashed'))
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'crash-tool');
      const handler = vi.fn().mockResolvedValue({ content: [{ type: 'text', text: 'original' }] });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({ content: [{ type: 'text', text: 'original' }] });
      expect(mockLogger.logInfo).toHaveBeenCalledWith(
        '[VALIDATOR_ERROR] Response validator error for tool crash-tool: Validator crashed'
      );
    });

    it('handles non-Error exceptions gracefully', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockRejectedValue('string error')
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'string-error-tool');
      const handler = vi.fn().mockResolvedValue({ data: 'ok' });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({ data: 'ok' });
      expect(mockLogger.logInfo).toHaveBeenCalledWith(
        '[VALIDATOR_ERROR] Response validator error for tool string-error-tool: Unknown error'
      );
    });

    it('does not log error when logger is null', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockRejectedValue(new Error('Crash'))
      };
      const wrapper = createResponseWrapper(mockLayer5, null, 'null-logger-tool');
      const handler = vi.fn().mockResolvedValue({ data: 'test' });
      const wrapped = wrapper(handler);

      const result = await wrapped({});

      expect(result).toEqual({ data: 'test' });
    });
  });

  describe('wrapper function composition', () => {
    it('preserves handler arguments correctly', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({ passed: true })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'args-tool');
      const handler = vi.fn().mockResolvedValue({ result: 'done' });
      const wrapped = wrapper(handler);

      const complexArgs = { nested: { value: 123 }, array: [1, 2, 3] };
      await wrapped(complexArgs);

      expect(handler).toHaveBeenCalledWith(complexArgs);
      expect(mockLayer5.validateResponse).toHaveBeenCalledWith(
        { result: 'done' },
        { tool: 'args-tool', arguments: complexArgs },
        {}
      );
    });

    it('passes tool name correctly to context', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({ passed: true })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'my-custom-tool');
      const handler = vi.fn().mockResolvedValue({});
      const wrapped = wrapper(handler);

      await wrapped({});

      expect(mockLayer5.validateResponse).toHaveBeenCalledWith(
        {},
        expect.objectContaining({ tool: 'my-custom-tool' }),
        {}
      );
    });

    it('can wrap multiple handlers independently', async () => {
      const mockLayer5 = {
        validateResponse: vi.fn().mockResolvedValue({ passed: true })
      };
      const wrapper = createResponseWrapper(mockLayer5, mockLogger, 'multi-tool');

      const handler1 = vi.fn().mockResolvedValue({ id: 1 });
      const handler2 = vi.fn().mockResolvedValue({ id: 2 });

      const wrapped1 = wrapper(handler1);
      const wrapped2 = wrapper(handler2);

      const result1 = await wrapped1({ type: 'first' });
      const result2 = await wrapped2({ type: 'second' });

      expect(result1).toEqual({ id: 1 });
      expect(result2).toEqual({ id: 2 });
      expect(mockLayer5.validateResponse).toHaveBeenCalledTimes(2);
    });
  });
});
