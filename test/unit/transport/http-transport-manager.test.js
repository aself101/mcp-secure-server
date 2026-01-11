import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HttpTransportManager } from '@/security/transport/http-transport-manager.js';

// Mock the SDK import
vi.mock('@modelcontextprotocol/sdk/server/streamableHttp.js', () => ({
  StreamableHTTPServerTransport: vi.fn().mockImplementation(() => ({
    mockTransport: true
  }))
}));

describe('HttpTransportManager', () => {
  let mockServer;
  let mockMcpServer;

  beforeEach(() => {
    mockMcpServer = {
      connect: vi.fn()
    };
    mockServer = {
      _mcpServer: mockMcpServer
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('constructor', () => {
    it('should use default options when none provided', () => {
      const manager = new HttpTransportManager(mockServer);
      expect(manager.isConnected).toBe(false);
      expect(manager.attempts).toBe(0);
    });

    it('should accept custom options', () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 10,
        baseBackoffMs: 200,
        maxBackoffMs: 10000,
        maxRetryDurationMs: 60000
      });
      expect(manager.isConnected).toBe(false);
    });
  });

  describe('ensureTransport', () => {
    it('should create transport and connect on first call', async () => {
      const manager = new HttpTransportManager(mockServer);
      mockMcpServer.connect.mockResolvedValueOnce(undefined);

      const transport = await manager.ensureTransport();

      expect(transport).toBeDefined();
      expect(transport.mockTransport).toBe(true);
      expect(manager.isConnected).toBe(true);
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(1);
    });

    it('should reuse existing transport on subsequent calls', async () => {
      const manager = new HttpTransportManager(mockServer);
      mockMcpServer.connect.mockResolvedValue(undefined);

      const transport1 = await manager.ensureTransport();
      const transport2 = await manager.ensureTransport();

      expect(transport1).toBe(transport2);
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(1);
    });
  });

  describe('connectWithBackoff', () => {
    it('should retry on connection failure and succeed', async () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 3,
        baseBackoffMs: 1, // Use tiny delays for testing
        maxBackoffMs: 5,
        maxRetryDurationMs: 30000
      });

      mockMcpServer.connect
        .mockRejectedValueOnce(new Error('Connection failed'))
        .mockResolvedValueOnce(undefined);

      const transport = await manager.ensureTransport();

      expect(transport).toBeDefined();
      expect(manager.isConnected).toBe(true);
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(2);
    });

    it('should throw after max reconnection attempts', async () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 2,
        baseBackoffMs: 1,
        maxBackoffMs: 2,
        maxRetryDurationMs: 30000
      });

      mockMcpServer.connect.mockRejectedValue(new Error('Connection failed'));

      await expect(manager.ensureTransport()).rejects.toThrow('Failed to connect after 2 attempts');
      expect(manager.isConnected).toBe(false);
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(2);
    });

    it('should throw when max retry duration exceeded', async () => {
      // Mock Date.now to simulate time passing
      const originalDateNow = Date.now;
      let callCount = 0;
      vi.spyOn(Date, 'now').mockImplementation(() => {
        callCount++;
        // First call is startTime, subsequent calls exceed duration
        return callCount === 1 ? 0 : 1000;
      });

      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 100,
        baseBackoffMs: 1,
        maxBackoffMs: 5,
        maxRetryDurationMs: 500
      });

      mockMcpServer.connect.mockRejectedValue(new Error('Connection failed'));

      await expect(manager.ensureTransport()).rejects.toThrow('exceeded maximum retry duration of 500ms');
      expect(manager.isConnected).toBe(false);

      Date.now = originalDateNow;
      vi.restoreAllMocks();
    });

    it('should reset attempts counter on successful connection', async () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 5,
        baseBackoffMs: 1,
        maxRetryDurationMs: 30000
      });

      mockMcpServer.connect
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined);

      await manager.ensureTransport();

      expect(manager.attempts).toBe(0);
      expect(manager.isConnected).toBe(true);
    });

    it('should retry multiple times before succeeding', async () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 5,
        baseBackoffMs: 1,
        maxBackoffMs: 2,
        maxRetryDurationMs: 30000
      });

      mockMcpServer.connect
        .mockRejectedValueOnce(new Error('fail 1'))
        .mockRejectedValueOnce(new Error('fail 2'))
        .mockRejectedValueOnce(new Error('fail 3'))
        .mockResolvedValueOnce(undefined);

      const transport = await manager.ensureTransport();

      expect(transport).toBeDefined();
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(4);
      expect(manager.isConnected).toBe(true);
    });
  });

  describe('handleConnectionFailure', () => {
    it('should reset transport state', async () => {
      const manager = new HttpTransportManager(mockServer);
      mockMcpServer.connect.mockResolvedValueOnce(undefined);

      await manager.ensureTransport();
      expect(manager.isConnected).toBe(true);

      manager.handleConnectionFailure();

      expect(manager.isConnected).toBe(false);
    });

    it('should allow fresh reconnection after failure', async () => {
      const manager = new HttpTransportManager(mockServer);
      mockMcpServer.connect.mockResolvedValue(undefined);

      const transport1 = await manager.ensureTransport();
      manager.handleConnectionFailure();
      const transport2 = await manager.ensureTransport();

      expect(transport2).not.toBe(transport1);
      expect(mockMcpServer.connect).toHaveBeenCalledTimes(2);
    });
  });

  describe('getters', () => {
    it('isConnected should reflect connection state', async () => {
      const manager = new HttpTransportManager(mockServer);
      expect(manager.isConnected).toBe(false);

      mockMcpServer.connect.mockResolvedValueOnce(undefined);
      await manager.ensureTransport();

      expect(manager.isConnected).toBe(true);
    });

    it('attempts should return reconnection attempts', () => {
      const manager = new HttpTransportManager(mockServer);
      expect(manager.attempts).toBe(0);
    });

    it('attempts should be reset after successful connection', async () => {
      const manager = new HttpTransportManager(mockServer, {
        maxReconnectAttempts: 5,
        baseBackoffMs: 1,
        maxRetryDurationMs: 30000
      });

      mockMcpServer.connect
        .mockRejectedValueOnce(new Error('fail'))
        .mockResolvedValueOnce(undefined);

      await manager.ensureTransport();
      expect(manager.attempts).toBe(0);
    });
  });
});
