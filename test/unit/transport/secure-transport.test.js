import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SecureTransport } from '../../../src/security/transport/secure-transport.js';

function createMockTransport() {
    return {
        onmessage: null,
        onerror: null,
        onclose: null,
        start: vi.fn().mockResolvedValue(undefined),
        close: vi.fn().mockResolvedValue(undefined),
        send: vi.fn().mockResolvedValue(undefined),
        sessionId: 'test-session-123'
    };
}

function createAllowValidator() {
    return vi.fn().mockResolvedValue({
        allowed: true,
        passed: true,
        reason: 'Allowed',
        severity: 'NONE'
    });
}

function createBlockValidator(reason = 'Blocked by policy') {
    return vi.fn().mockResolvedValue({
        allowed: false,
        passed: false,
        reason,
        severity: 'HIGH',
        violationType: 'POLICY_VIOLATION'
    });
}

describe('SecureTransport', () => {
    let mockTransport;
    let validator;
    let secureTransport;

    beforeEach(() => {
        mockTransport = createMockTransport();
        validator = createAllowValidator();
        secureTransport = new SecureTransport(mockTransport, validator);
    });

    describe('constructor', () => {
        it('accepts transport and validator', () => {
            expect(secureTransport).toBeInstanceOf(SecureTransport);
            expect(secureTransport._transport).toBe(mockTransport);
            expect(secureTransport._validator).toBe(validator);
        });

        it('sets up transport callbacks', () => {
            expect(mockTransport.onmessage).toBeTypeOf('function');
            expect(mockTransport.onerror).toBeTypeOf('function');
            expect(mockTransport.onclose).toBeTypeOf('function');
        });
    });

    describe('onmessage interception', () => {
        it('calls validator for request messages', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 1,
                params: { name: 'test-tool' }
            };

            await mockTransport.onmessage(request, {});

            expect(validator).toHaveBeenCalledWith(request, expect.objectContaining({
                timestamp: expect.any(Number),
                transportLevel: true
            }));
        });

        it('forwards allowed requests to protocol handler', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 1,
                params: {}
            };

            await mockTransport.onmessage(request, { extra: 'data' });

            expect(protocolHandler).toHaveBeenCalledWith(request, { extra: 'data' });
        });

        it('blocks requests and sends JSON-RPC error when validation fails', async () => {
            const blockValidator = createBlockValidator('Malicious content detected');
            secureTransport = new SecureTransport(mockTransport, blockValidator);

            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 42,
                params: { path: '../../../etc/passwd' }
            };

            await mockTransport.onmessage(request, {});

            expect(protocolHandler).not.toHaveBeenCalled();
            expect(mockTransport.send).toHaveBeenCalledWith({
                jsonrpc: '2.0',
                id: 42,
                error: {
                    code: -32602,
                    message: 'Malicious content detected'
                }
            });
        });
    });

    describe('notification handling', () => {
        it('validates notifications', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const notification = {
                jsonrpc: '2.0',
                method: 'notifications/cancelled',
                params: { requestId: 1 }
            };

            await mockTransport.onmessage(notification, {});

            expect(validator).toHaveBeenCalled();
        });

        it('does not send response for blocked notifications', async () => {
            const blockValidator = createBlockValidator();
            secureTransport = new SecureTransport(mockTransport, blockValidator);

            const notification = {
                jsonrpc: '2.0',
                method: 'notifications/cancelled',
                params: {}
            };

            await mockTransport.onmessage(notification, {});

            expect(mockTransport.send).not.toHaveBeenCalled();
        });

        it('forwards allowed notifications', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const notification = {
                jsonrpc: '2.0',
                method: 'notifications/progress',
                params: { progress: 50 }
            };

            await mockTransport.onmessage(notification, {});

            expect(protocolHandler).toHaveBeenCalledWith(notification, {});
        });
    });

    describe('response pass-through', () => {
        it('passes responses through without validation', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const response = {
                jsonrpc: '2.0',
                id: 1,
                result: { tools: [] }
            };

            await mockTransport.onmessage(response, {});

            expect(validator).not.toHaveBeenCalled();
            expect(protocolHandler).toHaveBeenCalledWith(response, {});
        });

        it('passes error responses through without validation', async () => {
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const errorResponse = {
                jsonrpc: '2.0',
                id: 1,
                error: { code: -32600, message: 'Invalid request' }
            };

            await mockTransport.onmessage(errorResponse, {});

            expect(validator).not.toHaveBeenCalled();
            expect(protocolHandler).toHaveBeenCalledWith(errorResponse, {});
        });
    });

    describe('transport method delegation', () => {
        it('delegates start() to underlying transport', async () => {
            await secureTransport.start();
            expect(mockTransport.start).toHaveBeenCalled();
        });

        it('delegates close() to underlying transport', async () => {
            await secureTransport.close();
            expect(mockTransport.close).toHaveBeenCalled();
        });

        it('delegates send() to underlying transport', async () => {
            const message = { jsonrpc: '2.0', method: 'ping', id: 1 };
            const options = { timeout: 5000 };

            await secureTransport.send(message, options);

            expect(mockTransport.send).toHaveBeenCalledWith(message, options);
        });

        it('exposes sessionId from underlying transport', () => {
            expect(secureTransport.sessionId).toBe('test-session-123');
        });
    });

    describe('callback forwarding', () => {
        it('forwards onerror to protocol handler', () => {
            const errorHandler = vi.fn();
            secureTransport.onerror = errorHandler;

            const error = new Error('Connection failed');
            mockTransport.onerror(error);

            expect(errorHandler).toHaveBeenCalledWith(error);
        });

        it('forwards onclose to protocol handler', () => {
            const closeHandler = vi.fn();
            secureTransport.onclose = closeHandler;

            mockTransport.onclose();

            expect(closeHandler).toHaveBeenCalled();
        });
    });

    describe('validator error handling', () => {
        it('blocks request when validator throws', async () => {
            const throwingValidator = vi.fn().mockRejectedValue(new Error('Validator crashed'));
            secureTransport = new SecureTransport(mockTransport, throwingValidator);

            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 1,
                params: {}
            };

            await mockTransport.onmessage(request, {});

            expect(protocolHandler).not.toHaveBeenCalled();
            expect(mockTransport.send).toHaveBeenCalledWith(expect.objectContaining({
                jsonrpc: '2.0',
                id: 1,
                error: expect.objectContaining({
                    code: -32602,
                    message: 'Validation error'
                })
            }));
        });
    });

    describe('connection drop during validation', () => {
        it('handles transport close during slow validation', async () => {
            let resolveValidation;
            const slowValidator = vi.fn().mockImplementation(() => {
                return new Promise(resolve => {
                    resolveValidation = resolve;
                });
            });
            secureTransport = new SecureTransport(mockTransport, slowValidator);

            const protocolHandler = vi.fn();
            const closeHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;
            secureTransport.onclose = closeHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 1,
                params: {}
            };

            // Start validation (won't complete yet)
            const messagePromise = mockTransport.onmessage(request, {});

            // Simulate connection close during validation
            mockTransport.onclose();

            // Verify close handler was called
            expect(closeHandler).toHaveBeenCalled();

            // Now complete validation
            resolveValidation({ allowed: true, passed: true });
            await messagePromise;

            // Message should still be forwarded (transport handles actual delivery)
            expect(protocolHandler).toHaveBeenCalledWith(request, {});
        });

        it('handles transport error during slow validation', async () => {
            let resolveValidation;
            const slowValidator = vi.fn().mockImplementation(() => {
                return new Promise(resolve => {
                    resolveValidation = resolve;
                });
            });
            secureTransport = new SecureTransport(mockTransport, slowValidator);

            const protocolHandler = vi.fn();
            const errorHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;
            secureTransport.onerror = errorHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 2,
                params: {}
            };

            // Start validation (won't complete yet)
            const messagePromise = mockTransport.onmessage(request, {});

            // Simulate transport error during validation
            const transportError = new Error('Connection reset by peer');
            mockTransport.onerror(transportError);

            // Verify error handler was called
            expect(errorHandler).toHaveBeenCalledWith(transportError);

            // Complete validation
            resolveValidation({ allowed: true, passed: true });
            await messagePromise;

            // Message forwarding attempted despite error (let protocol handle it)
            expect(protocolHandler).toHaveBeenCalled();
        });

        it('reports error when send fails during blocked response', async () => {
            const blockValidator = createBlockValidator('Request blocked');
            mockTransport.send = vi.fn().mockRejectedValue(new Error('Connection closed'));
            secureTransport = new SecureTransport(mockTransport, blockValidator);

            const errorHandler = vi.fn();
            const protocolHandler = vi.fn();
            secureTransport.onerror = errorHandler;
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 3,
                params: {}
            };

            await mockTransport.onmessage(request, {});

            // Should not forward blocked request
            expect(protocolHandler).not.toHaveBeenCalled();

            // Should report send failure through error handler
            expect(errorHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    message: expect.stringContaining('Failed to send blocked response')
                })
            );
        });

        it('silently fails when send fails and no error handler set', async () => {
            const blockValidator = createBlockValidator('Request blocked');
            mockTransport.send = vi.fn().mockRejectedValue(new Error('Connection closed'));
            secureTransport = new SecureTransport(mockTransport, blockValidator);

            // Don't set error handler
            const protocolHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;

            const request = {
                jsonrpc: '2.0',
                method: 'tools/call',
                id: 4,
                params: {}
            };

            // Should not throw, should complete gracefully
            await expect(mockTransport.onmessage(request, {})).resolves.toBeUndefined();
            expect(protocolHandler).not.toHaveBeenCalled();
        });

        it('handles concurrent requests when one causes connection drop', async () => {
            let resolveFirst, resolveSecond;
            let callCount = 0;
            const slowValidator = vi.fn().mockImplementation(() => {
                callCount++;
                if (callCount === 1) {
                    return new Promise(resolve => { resolveFirst = resolve; });
                } else {
                    return new Promise(resolve => { resolveSecond = resolve; });
                }
            });
            secureTransport = new SecureTransport(mockTransport, slowValidator);

            const protocolHandler = vi.fn();
            const closeHandler = vi.fn();
            secureTransport.onmessage = protocolHandler;
            secureTransport.onclose = closeHandler;

            const request1 = { jsonrpc: '2.0', method: 'tools/call', id: 1, params: {} };
            const request2 = { jsonrpc: '2.0', method: 'tools/call', id: 2, params: {} };

            // Start both validations concurrently
            const promise1 = mockTransport.onmessage(request1, {});
            const promise2 = mockTransport.onmessage(request2, {});

            // Connection drops after first request validates but before second
            resolveFirst({ allowed: true, passed: true });
            await promise1;

            expect(protocolHandler).toHaveBeenCalledWith(request1, {});

            // Simulate connection drop
            mockTransport.onclose();
            expect(closeHandler).toHaveBeenCalled();

            // Complete second validation
            resolveSecond({ allowed: true, passed: true });
            await promise2;

            // Second message also forwarded (transport handles actual delivery state)
            expect(protocolHandler).toHaveBeenCalledTimes(2);
        });
    });
});
