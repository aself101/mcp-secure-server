import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecureMcpServer } from '../../../src/security/mcp-secure-server.js';
import { SecureTransport } from '../../../src/security/transport/secure-transport.js';

function createMockTransport() {
    return {
        onmessage: null,
        onerror: null,
        onclose: null,
        start: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        send: vi.fn().mockResolvedValue(undefined),
        sessionId: 'test-session'
    };
}

// Every test here drives SecureMcpServer through its PUBLIC surface —
// connect(transport) — and asserts on what the wrapped transport observably
// does (what gets sent back to the client, what the validator was handed).
// Until 0.0.21 10 of 12 tests called the private _wrapTransport directly and
// two asserted private-field identity (ship run #1, issue 9abc226a), so a
// broken connect() would not have failed any of them.

async function deliver(mockTransport, message) {
    await mockTransport.onmessage(message, {});
    // The SDK Protocol replies asynchronously; let the microtask queue drain.
    await new Promise((r) => setImmediate(r));
}

describe('SecureMcpServer transport wrapping (via connect())', () => {
    let server;
    let mockTransport;

    beforeEach(() => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            { enableLogging: false }
        );
        mockTransport = createMockTransport();
    });

    it('connect() wraps the transport: starts it and installs an inbound handler on it', async () => {
        expect(mockTransport.onmessage).toBeNull();
        await server.connect(mockTransport);
        expect(mockTransport.start).toHaveBeenCalledTimes(1);
        expect(typeof mockTransport.onmessage).toBe('function');
        expect(server.isConnected()).toBe(true);
    });

    it('a benign request passes validation and the SDK answers it through the wrapped transport', async () => {
        await server.connect(mockTransport);
        await deliver(mockTransport, { jsonrpc: '2.0', method: 'ping', id: 1 });

        expect(mockTransport.send).toHaveBeenCalled();
        const reply = mockTransport.send.mock.calls[0][0];
        expect(reply).toMatchObject({ jsonrpc: '2.0', id: 1, result: {} });
    });

    it('blocks malicious requests at transport level with a sanitized error, never reaching the SDK', async () => {
        await server.connect(mockTransport);
        const maliciousRequest = {
            jsonrpc: '2.0',
            method: 'tools/call',
            id: 42,
            params: { name: 'file-reader', arguments: { path: '../../../etc/passwd' } }
        };

        await deliver(mockTransport, maliciousRequest);

        expect(mockTransport.send).toHaveBeenCalledTimes(1);
        const errorResponse = mockTransport.send.mock.calls[0][0];
        expect(errorResponse.jsonrpc).toBe('2.0');
        expect(errorResponse.id).toBe(42);
        expect(errorResponse.error.code).toBe(-32602);
        expect(errorResponse.result).toBeUndefined();
    });

    it('blocked responses are produced by the error sanitizer (correlation token present, payload not echoed)', async () => {
        await server.connect(mockTransport);
        await deliver(mockTransport, {
            jsonrpc: '2.0', method: 'tools/call', id: 7,
            params: { name: 'file-reader', arguments: { path: '../../../etc/passwd' } }
        });

        const errorResponse = mockTransport.send.mock.calls[0][0];
        expect(errorResponse.error.data).toMatchObject({ token: expect.any(String), timestamp: expect.any(String) });
        expect(JSON.stringify(errorResponse)).not.toContain('etc/passwd');
    });

    it('validator receives a context with timestamp, transportLevel and the server policy', async () => {
        const validateSpy = vi.spyOn(server._validationPipeline, 'validate');
        await server.connect(mockTransport);

        await deliver(mockTransport, { jsonrpc: '2.0', method: 'ping', id: 1 });

        expect(validateSpy).toHaveBeenCalledWith(
            expect.any(Object),
            expect.objectContaining({
                timestamp: expect.any(Number),
                transportLevel: true,
                policy: { allowNetwork: false, allowWrites: false }
            })
        );
    });
});

describe('SecureMcpServer with logging enabled (via connect())', () => {
    let server;
    let mockTransport;

    beforeEach(() => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            { enableLogging: true, verboseLogging: false, logPerformanceMetrics: false }
        );
        mockTransport = createMockTransport();
    });

    it('logs security decisions via securityLogger', async () => {
        const logSpy = vi.spyOn(server._securityLogger, 'logSecurityDecision');
        await server.connect(mockTransport);

        await deliver(mockTransport, { jsonrpc: '2.0', method: 'tools/list', id: 1 });

        expect(logSpy).toHaveBeenCalledWith(expect.any(Object), expect.any(Object), 'Transport');
    });

    it('logs requests with transport-level source', async () => {
        const logSpy = vi.spyOn(server._securityLogger, 'logRequest');
        await server.connect(mockTransport);

        await deliver(mockTransport, { jsonrpc: '2.0', method: 'ping', id: 1 });

        expect(logSpy).toHaveBeenCalledWith(expect.any(Object), expect.objectContaining({ source: 'transport-level' }));
    });

    it('tracks performance metrics when enabled', async () => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            { enableLogging: true, logPerformanceMetrics: true }
        );
        const perfSpy = vi.spyOn(server._securityLogger, 'logPerformance');
        await server.connect(mockTransport);

        await deliver(mockTransport, { jsonrpc: '2.0', method: 'ping', id: 1 });

        expect(perfSpy).toHaveBeenCalled();
        const [startTime, endTime] = perfSpy.mock.calls[0];
        expect(startTime).toBeTypeOf('number');
        expect(endTime).toBeTypeOf('number');
        expect(endTime).toBeGreaterThanOrEqual(startTime);
    });
});

describe('SecureTransport with ErrorSanitizer', () => {
    it('uses errorSanitizer for blocked responses when provided', async () => {
        const mockSanitizer = {
            createSanitizedErrorResponse: vi.fn().mockReturnValue({
                jsonrpc: '2.0',
                id: 1,
                error: {
                    code: -32602,
                    message: 'Sanitized error message'
                }
            })
        };

        const mockTransport = createMockTransport();
        const blockingValidator = vi.fn().mockResolvedValue({
            allowed: false,
            passed: false,
            reason: 'Blocked',
            severity: 'HIGH',
            violationType: 'PATH_TRAVERSAL'  // Use valid ViolationType
        });

        const secureTransport = new SecureTransport(mockTransport, blockingValidator, {
            errorSanitizer: mockSanitizer
        });
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'tools/call',
            id: 99,
            params: {}
        };

        await mockTransport.onmessage(request, {});

        expect(mockSanitizer.createSanitizedErrorResponse).toHaveBeenCalledWith(
            99,
            'Blocked',
            'HIGH',
            'PATH_TRAVERSAL'  // Use valid ViolationType
        );
        expect(mockTransport.send).toHaveBeenCalledWith({
            jsonrpc: '2.0',
            id: 1,
            error: {
                code: -32602,
                message: 'Sanitized error message'
            }
        });
    });

    it('falls back to default error format without errorSanitizer', async () => {
        const mockTransport = createMockTransport();
        const blockingValidator = vi.fn().mockResolvedValue({
            allowed: false,
            passed: false,
            reason: 'Test block reason'
        });

        const secureTransport = new SecureTransport(mockTransport, blockingValidator);
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'tools/call',
            id: 55,
            params: {}
        };

        await mockTransport.onmessage(request, {});

        expect(mockTransport.send).toHaveBeenCalledWith({
            jsonrpc: '2.0',
            id: 55,
            error: {
                code: -32602,
                message: 'Test block reason'
            }
        });
    });
});
