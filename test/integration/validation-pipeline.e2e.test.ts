import { describe, it, expect, beforeEach } from 'vitest';
import { SecureMcpServer } from '@/security/mcp-secure-server.js';
import type { PipelineContext, PipelineResult } from '@/security/utils/validation-pipeline.js';

function createPipelineContext(overrides: Partial<PipelineContext> = {}): PipelineContext {
  return {
    timestamp: Date.now(),
    transportLevel: true,
    ...overrides
  };
}

function createToolCallMessage(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    method: 'tools/call',
    id: Date.now(),
    params: {
      name: 'debug-echo',
      arguments: {
        text: 'hello world'
      }
    },
    ...overrides
  };
}

describe('Secure validation pipeline – end to end', () => {
  let server: SecureMcpServer;

  beforeEach(() => {
    server = new SecureMcpServer(
      { name: 'integration-pipeline', version: '1.0.0' },
      {
        maxRequestsPerMinute: 25,
        maxRequestsPerHour: 50,
        burstThreshold: 8
      }
    );
  });

  async function runPipeline(message: Record<string, unknown>, context?: Partial<PipelineContext>): Promise<PipelineResult> {
    return server.validationPipeline.validate(message, createPipelineContext(context));
  }

  it('allows a benign tools/call request across all layers', async () => {
    const message = createToolCallMessage();

    const result = await runPipeline(message);

    expect(result.passed).toBe(true);
    expect(result.allowed).toBe(true);
    expect(result.layerName).toBe('Pipeline');
  });

  it('blocks malformed JSON-RPC messages before content inspection', async () => {
    const malformed = {
      method: 'tools/call',
      id: 'abc',
      params: { name: 'debug-echo' }
      // Missing jsonrpc property triggers Layer 1
    };

    const result = await runPipeline(malformed as Record<string, unknown>);

    expect(result.passed).toBe(false);
    expect(result.layerName).toMatch(/structure/i);
  });

  it('blocks content-layer attacks even when structure is valid', async () => {
    const traversal = createToolCallMessage({
      params: {
        name: 'debug-file-reader',
        arguments: {
          path: '../../../etc/passwd'
        }
      }
    });

    const result = await runPipeline(traversal);

    expect(result.passed).toBe(false);
    expect(result.layerName).toMatch(/content/i);
    expect(result.reason).toMatch(/path|traversal/i);
  });

  it('enforces semantic tool contracts for missing arguments', async () => {
    const missingArgument = createToolCallMessage({
      params: {
        name: 'debug-file-reader',
        arguments: {}
      }
    });

    const result = await runPipeline(missingArgument);

    expect(result.passed).toBe(false);
    expect(result.layerName).toMatch(/semantics/i);
    expect(result.violationType).toBe('MISSING_REQUIRED_PARAM');
  });
});

describe('Behavior layer rate limiting – stress scenarios', () => {
  let server: SecureMcpServer;

  beforeEach(() => {
    server = new SecureMcpServer(
      { name: 'rate-test', version: '1.0.0' },
      {
        maxRequestsPerMinute: 5,
        maxRequestsPerHour: 10,
        burstThreshold: 4,
        enableLogging: false
      }
    );
  });

  async function runConcurrentBatch(batchSize: number): Promise<PipelineResult[]> {
    const requests = Array.from({ length: batchSize }, (_, idx) => {
      const message = createToolCallMessage({ id: idx + 1 });
      return server.validationPipeline.validate(message, createPipelineContext());
    });
    return Promise.all(requests);
  }

  it('blocks excess concurrent requests via the behavior layer', async () => {
    const results = await runConcurrentBatch(15);

    const blocked = results.filter(result => !result.passed);
    expect(blocked.length).toBeGreaterThan(0);
    expect(blocked.some(result => /behavior/i.test(result.layerName))).toBe(true);
    expect(blocked.some(result => result.violationType === 'RATE_LIMIT_EXCEEDED' || result.violationType === 'BURST_ACTIVITY')).toBe(true);
  });
});
