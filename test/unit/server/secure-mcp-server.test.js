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

describe('SecureMcpServer', () => {
    let server;
    let mockTransport;

    beforeEach(() => {
        server = new SecureMcpServer(
            { name: 'test-server', version: '1.0.0' },
            {
                enableLogging: false,
                maxRequestsPerMinute: 100
            }
        );
        mockTransport = createMockTransport();
    });

    describe('constructor', () => {
        it('creates internal McpServer instance', () => {
            expect(typeof server._mcpServer).toBe('object');
            expect(server._mcpServer).not.toBe(null);
            expect(server.mcpServer).toBe(server._mcpServer);
        });

        it('creates validation pipeline', () => {
            expect(typeof server._validationPipeline).toBe('object');
            expect(server._validationPipeline).not.toBe(null);
            expect(server.validationPipeline).toBe(server._validationPipeline);
        });

        it('creates error sanitizer', () => {
            expect(typeof server._errorSanitizer).toBe('object');
            expect(server._errorSanitizer).not.toBe(null);
        });

        it('stores server info', () => {
            expect(server._serverInfo).toEqual({ name: 'test-server', version: '1.0.0' });
        });

        it('does not create logger when logging disabled', () => {
            expect(server._securityLogger).toBe(null);
        });

        it('creates logger when logging enabled', () => {
            const serverWithLogging = new SecureMcpServer(
                { name: 'test-server', version: '1.0.0' },
                { enableLogging: true }
            );
            expect(serverWithLogging._securityLogger).not.toBe(null);
        });
    });

    describe('connect', () => {
        it('wraps transport with security before connecting', async () => {
            const wrapSpy = vi.spyOn(server, '_wrapTransport');
            const connectSpy = vi.spyOn(server._mcpServer, 'connect').mockResolvedValue(undefined);

            await server.connect(mockTransport);

            expect(wrapSpy).toHaveBeenCalledWith(mockTransport);
            expect(connectSpy).toHaveBeenCalled();
            expect(server._wrappedTransport).toBeInstanceOf(SecureTransport);
        });

        it('passes wrapped transport to McpServer', async () => {
            const connectSpy = vi.spyOn(server._mcpServer, 'connect').mockResolvedValue(undefined);

            await server.connect(mockTransport);

            const passedTransport = connectSpy.mock.calls[0][0];
            expect(passedTransport).toBeInstanceOf(SecureTransport);
            expect(passedTransport).toBe(server._wrappedTransport);
        });
    });

    describe('delegation methods', () => {
        it('delegates tool() to internal McpServer', () => {
            const toolSpy = vi.spyOn(server._mcpServer, 'tool').mockReturnValue({});

            server.tool('test-tool', 'description', {}, () => {});

            expect(toolSpy).toHaveBeenCalledWith('test-tool', 'description', {}, expect.any(Function));
        });

        it('delegates registerTool() to internal McpServer', () => {
            const registerSpy = vi.spyOn(server._mcpServer, 'registerTool').mockReturnValue({});

            const config = { description: 'test' };
            const callback = () => {};
            server.registerTool('test-tool', config, callback);

            expect(registerSpy).toHaveBeenCalledWith('test-tool', config, callback);
        });

        it('delegates resource() to internal McpServer', () => {
            const resourceSpy = vi.spyOn(server._mcpServer, 'resource').mockReturnValue({});

            server.resource('test-resource', 'file://test', () => {});

            expect(resourceSpy).toHaveBeenCalled();
        });

        it('delegates prompt() to internal McpServer', () => {
            const promptSpy = vi.spyOn(server._mcpServer, 'prompt').mockReturnValue({});

            server.prompt('test-prompt', 'description', () => {});

            expect(promptSpy).toHaveBeenCalled();
        });

        it('delegates close() to internal McpServer', async () => {
            const closeSpy = vi.spyOn(server._mcpServer, 'close').mockResolvedValue(undefined);

            await server.close();

            expect(closeSpy).toHaveBeenCalled();
        });

        it('delegates isConnected() to internal McpServer', () => {
            const isConnectedSpy = vi.spyOn(server._mcpServer, 'isConnected').mockReturnValue(true);

            const result = server.isConnected();

            expect(isConnectedSpy).toHaveBeenCalled();
            expect(result).toBe(true);
        });
    });

    describe('security methods', () => {
        it('getSecurityStats() returns stats', () => {
            const stats = server.getSecurityStats();

            expect(typeof stats).toBe('object');
            expect(typeof stats.server).toBe('object');
            expect(stats.server.totalLayers).toBe(4);
            expect(stats.server.loggingEnabled).toBe(false);
        });

        it('getVerboseSecurityReport() returns error when logging disabled', () => {
            const report = server.getVerboseSecurityReport();

            expect(typeof report).toBe('object');
            expect(report.error).toBe('Logging not enabled. Set enableLogging: true in options.');
        });

        it('getVerboseSecurityReport() returns report when logging enabled', () => {
            const serverWithLogging = new SecureMcpServer(
                { name: 'test-server', version: '1.0.0' },
                { enableLogging: true }
            );
            const report = serverWithLogging.getVerboseSecurityReport();

            expect(typeof report).toBe('object');
            expect(report.error).toBeUndefined();
        });

        it('generateSecurityReport() returns error when logging disabled', async () => {
            const report = await server.generateSecurityReport();

            expect(typeof report).toBe('object');
            expect(report.error).toBe('Logging not enabled. Set enableLogging: true in options.');
        });
    });

    describe('server property access', () => {
        it('exposes underlying Server via server property', () => {
            expect(server.server).toBe(server._mcpServer.server);
        });

        it('exposes McpServer via mcpServer property', () => {
            expect(server.mcpServer).toBe(server._mcpServer);
        });

        it('exposes validation pipeline via validationPipeline property', () => {
            expect(server.validationPipeline).toBe(server._validationPipeline);
        });
    });

    describe('shutdown', () => {
        it('closes server when logging disabled', async () => {
            const closeSpy = vi.spyOn(server._mcpServer, 'close').mockResolvedValue(undefined);

            const report = await server.shutdown();

            expect(closeSpy).toHaveBeenCalled();
            expect(report).toBe(null);
        });

        it('generates report and closes server when logging enabled', async () => {
            const serverWithLogging = new SecureMcpServer(
                { name: 'test-server', version: '1.0.0' },
                { enableLogging: true }
            );
            const closeSpy = vi.spyOn(serverWithLogging._mcpServer, 'close').mockResolvedValue(undefined);
            const reportSpy = vi.spyOn(serverWithLogging._securityLogger, 'generateReport').mockResolvedValue({ stats: 'test' });
            const flushSpy = vi.spyOn(serverWithLogging._securityLogger, 'flush').mockResolvedValue(undefined);

            const report = await serverWithLogging.shutdown();

            expect(reportSpy).toHaveBeenCalled();
            expect(flushSpy).toHaveBeenCalled();
            expect(closeSpy).toHaveBeenCalled();
            expect(report).toEqual({ stats: 'test' });
        });
    });
});

describe('SecureMcpServer Integration', () => {
    it('validates messages at transport level when connected', async () => {
        const server = new SecureMcpServer(
            { name: 'integration-test', version: '1.0.0' },
            { enableLogging: false }
        );

        const mockTransport = createMockTransport();

        // Spy on the validation pipeline
        const validateSpy = vi.spyOn(server._validationPipeline, 'validate');

        await server.connect(mockTransport);

        // Simulate an incoming request through the transport
        const request = {
            jsonrpc: '2.0',
            method: 'tools/list',
            id: 1
        };

        // The wrapped transport should intercept and validate
        await mockTransport.onmessage(request, {});

        // Validation pipeline should have been called
        expect(validateSpy).toHaveBeenCalled();
    });
});
