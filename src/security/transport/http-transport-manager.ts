/**
 * HTTP transport lifecycle manager with exponential backoff.
 * @module http-transport-manager
 */

import type { McpHttpTransport, SecureServerHttpInterface } from './http-server-types.js';

/** Configuration for transport manager */
export interface TransportManagerOptions {
  /** Maximum reconnection attempts before giving up (default: 5) */
  maxReconnectAttempts?: number;
  /** Base backoff delay in milliseconds (default: 100) */
  baseBackoffMs?: number;
  /** Maximum backoff delay in milliseconds (default: 5000) */
  maxBackoffMs?: number;
  /** Maximum total retry duration in milliseconds (default: 30000) */
  maxRetryDurationMs?: number;
  /** Timeout for individual connect operations in milliseconds (default: 10000) */
  connectTimeoutMs?: number;
}

/** Delay helper */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Wrap a promise with a timeout */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, operation: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${operation} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    promise
      .then(result => {
        clearTimeout(timer);
        resolve(result);
      })
      .catch(err => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

/**
 * Manages MCP HTTP transport lifecycle with automatic reconnection.
 *
 * Features:
 * - Lazy transport initialization on first request
 * - Automatic reconnection with exponential backoff
 * - Configurable retry limits and backoff timing
 */
export class HttpTransportManager {
  private transport: McpHttpTransport | null = null;
  private connected = false;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts: number;
  private readonly baseBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly maxRetryDurationMs: number;
  private readonly connectTimeoutMs: number;
  private readonly server: SecureServerHttpInterface;

  constructor(server: SecureServerHttpInterface, options: TransportManagerOptions = {}) {
    this.server = server;
    this.maxReconnectAttempts = options.maxReconnectAttempts ?? 5;
    this.baseBackoffMs = options.baseBackoffMs ?? 100;
    this.maxBackoffMs = options.maxBackoffMs ?? 5000;
    this.maxRetryDurationMs = options.maxRetryDurationMs ?? 30000;
    this.connectTimeoutMs = options.connectTimeoutMs ?? 10000;
  }

  /**
   * Get or create transport, connecting if necessary.
   * Implements exponential backoff on connection failures.
   */
  async ensureTransport(): Promise<McpHttpTransport> {
    if (!this.transport) {
      const { StreamableHTTPServerTransport } = await import(
        '@modelcontextprotocol/sdk/server/streamableHttp.js'
      );
      this.transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    }

    if (!this.connected) {
      await this.connectWithBackoff();
    }

    return this.transport;
  }

  /**
   * Connect to MCP server with exponential backoff on failure.
   * Respects both maxReconnectAttempts and maxRetryDurationMs limits.
   */
  private async connectWithBackoff(): Promise<void> {
    const startTime = Date.now();

    while (this.reconnectAttempts < this.maxReconnectAttempts) {
      // Check if we've exceeded the maximum retry duration
      if (Date.now() - startTime > this.maxRetryDurationMs) {
        this.resetTransport();
        throw new Error(`Failed to connect: exceeded maximum retry duration of ${this.maxRetryDurationMs}ms`);
      }

      try {
        await withTimeout(
          this.server._mcpServer.connect(this.transport),
          this.connectTimeoutMs,
          'SDK transport connect'
        );
        this.connected = true;
        this.reconnectAttempts = 0;
        return;
      } catch (err) {
        this.reconnectAttempts++;

        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
          this.resetTransport();
          const error = new Error(`Failed to connect after ${this.maxReconnectAttempts} attempts`);
          error.cause = err;
          throw error;
        }

        const backoffMs = Math.min(
          this.baseBackoffMs * Math.pow(2, this.reconnectAttempts - 1),
          this.maxBackoffMs
        );
        await delay(backoffMs);
      }
    }
  }

  /**
   * Handle a connection failure during request handling.
   * Resets state for fresh reconnection on next request.
   */
  handleConnectionFailure(): void {
    this.resetTransport();
  }

  /**
   * Reset transport state for fresh initialization.
   */
  private resetTransport(): void {
    this.transport = null;
    this.connected = false;
  }

  /** Check if transport is currently connected */
  get isConnected(): boolean {
    return this.connected;
  }

  /** Get current reconnection attempt count */
  get attempts(): number {
    return this.reconnectAttempts;
  }
}
