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

describe('SecureMcpServer transport wrapping', () => {
    let server;
    let mockTransport;

    beforeEach(() => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            { enableLogging: false }
        );
        mockTransport = createMockTransport();
    });

    it('_wrapTransport returns a SecureTransport instance', () => {
        const secureTransport = server._wrapTransport(mockTransport);
        expect(secureTransport).toBeInstanceOf(SecureTransport);
    });

    it('validation pipeline is called for requests', async () => {
        const secureTransport = server._wrapTransport(mockTransport);
        const protocolHandler = vi.fn();
        secureTransport.onmessage = protocolHandler;

        const request = {
            jsonrpc: '2.0',
            method: 'tools/list',
            id: 1
        };

        await mockTransport.onmessage(request, {});

        expect(protocolHandler).toHaveBeenCalledWith(request, {});
    });

    it('blocks malicious requests at transport level', async () => {
        const secureTransport = server._wrapTransport(mockTransport);
        const protocolHandler = vi.fn();
        secureTransport.onmessage = protocolHandler;

        const maliciousRequest = {
            jsonrpc: '2.0',
            method: 'tools/call',
            id: 42,
            params: {
                name: 'file-reader',
                arguments: {
                    path: '../../../etc/passwd'
                }
            }
        };

        await mockTransport.onmessage(maliciousRequest, {});

        expect(protocolHandler).not.toHaveBeenCalled();
        expect(mockTransport.send).toHaveBeenCalled();

        const errorResponse = mockTransport.send.mock.calls[0][0];
        expect(errorResponse.jsonrpc).toBe('2.0');
        expect(errorResponse.id).toBe(42);
        expect(typeof errorResponse.error).toBe('object');
        expect(errorResponse.error.code).toBe(-32602);
    });

    it('passes errorSanitizer to SecureTransport', async () => {
        const secureTransport = server._wrapTransport(mockTransport);
        expect(secureTransport._errorSanitizer).toBe(server._errorSanitizer);
    });

    it('context includes timestamp and transportLevel flag', async () => {
        const validateSpy = vi.spyOn(server._validationPipeline, 'validate');
        const secureTransport = server._wrapTransport(mockTransport);
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'ping',
            id: 1
        };

        await mockTransport.onmessage(request, {});

        expect(validateSpy).toHaveBeenCalledWith(
            expect.any(Object),
            expect.objectContaining({
                timestamp: expect.any(Number),
                transportLevel: true
            })
        );
    });
});

describe('SecureMcpServer with logging enabled', () => {
    let server;
    let mockTransport;

    beforeEach(() => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            {
                enableLogging: true,
                verboseLogging: false,
                logPerformanceMetrics: false
            }
        );
        mockTransport = createMockTransport();
    });

    it('_wrapTransport returns a SecureTransport instance', () => {
        const secureTransport = server._wrapTransport(mockTransport);
        expect(secureTransport).toBeInstanceOf(SecureTransport);
    });

    it('logs security decisions via securityLogger', async () => {
        const logSpy = vi.spyOn(server._securityLogger, 'logSecurityDecision');
        const secureTransport = server._wrapTransport(mockTransport);
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'tools/list',
            id: 1
        };

        await mockTransport.onmessage(request, {});

        expect(logSpy).toHaveBeenCalledWith(
            expect.any(Object),
            expect.any(Object),
            'Transport'
        );
    });

    it('logs requests with transport-level source', async () => {
        const logSpy = vi.spyOn(server._securityLogger, 'logRequest');
        const secureTransport = server._wrapTransport(mockTransport);
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'ping',
            id: 1
        };

        await mockTransport.onmessage(request, {});

        expect(logSpy).toHaveBeenCalledWith(
            expect.any(Object),
            expect.objectContaining({
                source: 'transport-level'
            })
        );
    });

    it('tracks performance metrics when enabled', async () => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            {
                enableLogging: true,
                logPerformanceMetrics: true
            }
        );
        const perfSpy = vi.spyOn(server._securityLogger, 'logPerformance');
        const secureTransport = server._wrapTransport(mockTransport);
        secureTransport.onmessage = vi.fn();

        const request = {
            jsonrpc: '2.0',
            method: 'ping',
            id: 1
        };

        await mockTransport.onmessage(request, {});

        expect(perfSpy).toHaveBeenCalled();
    });

    it('passes errorSanitizer to SecureTransport', () => {
        const secureTransport = server._wrapTransport(mockTransport);
        expect(secureTransport._errorSanitizer).toBe(server._errorSanitizer);
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
            violationType: 'TEST_VIOLATION'
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
            'TEST_VIOLATION'
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
