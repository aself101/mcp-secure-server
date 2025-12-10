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
            expect(typeof mockTransport.onmessage).toBe('function');
            expect(typeof mockTransport.onerror).toBe('function');
            expect(typeof mockTransport.onclose).toBe('function');
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
});
