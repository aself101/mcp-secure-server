import { describe, it, expect, vi } from 'vitest';
import { createTransportValidator, REQUEST_ID_MAP_MAX } from '@/security/transport/transport-validator.js';

function makeDeps() {
  let next = 0;
  const securityLogger = {
    nextRequestId: vi.fn(() => ++next),
    logRequest: vi.fn(),
    logPerformance: vi.fn(),
    logSecurityDecision: vi.fn()
  };
  const validationPipeline = {
    validate: vi.fn().mockResolvedValue({ passed: true, allowed: true, severity: 'NONE', reason: 'ok', violationType: null, confidence: 1, layerName: 'p', timestamp: 0 }),
    getLayers: vi.fn(() => [])
  };
  const requestIdByJsonrpcId = new Map<string | number | null | undefined, number>();
  return { securityLogger, validationPipeline, requestIdByJsonrpcId, trackRequest: vi.fn() };
}

const options = { logPerformanceMetrics: false, verboseLogging: false, defaultPolicy: { allowNetwork: false, allowWrites: false } };
const msg = (id: number | string) => ({ jsonrpc: '2.0', id, method: 'ping' });

describe('createTransportValidator: JSON-RPC id -> internal id map (ship run #1, issue d186a70c)', () => {
  it('is bounded: never holds more than REQUEST_ID_MAP_MAX entries with logging on', async () => {
    const deps = makeDeps();
    const validate = createTransportValidator(options, deps as never);
    const n = REQUEST_ID_MAP_MAX + 500;
    for (let i = 0; i < n; i++) await validate(msg(i) as never, { timestamp: 0, transportLevel: true });
    expect(deps.requestIdByJsonrpcId.size).toBe(REQUEST_ID_MAP_MAX);
    // FIFO: the oldest ids are gone, the newest are present.
    expect(deps.requestIdByJsonrpcId.has(0)).toBe(false);
    expect(deps.requestIdByJsonrpcId.has(499)).toBe(false);
    expect(deps.requestIdByJsonrpcId.has(500)).toBe(true);
    expect(deps.requestIdByJsonrpcId.has(n - 1)).toBe(true);
  });

  it('a retried JSON-RPC id inside the window reuses its internal id', async () => {
    const deps = makeDeps();
    const validate = createTransportValidator(options, deps as never);
    await validate(msg('abc') as never, { timestamp: 0, transportLevel: true });
    await validate(msg('abc') as never, { timestamp: 0, transportLevel: true });
    expect(deps.securityLogger.nextRequestId).toHaveBeenCalledTimes(1);
    expect(deps.securityLogger.logRequest.mock.calls.map((c) => c[1].requestId)).toEqual([1, 1]);
  });

  it('does not touch the map when logging is off', async () => {
    const deps = makeDeps();
    const validate = createTransportValidator(options, { ...deps, securityLogger: null } as never);
    for (let i = 0; i < 50; i++) await validate(msg(i) as never, { timestamp: 0, transportLevel: true });
    expect(deps.requestIdByJsonrpcId.size).toBe(0);
  });
});
