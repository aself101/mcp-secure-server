/**
 * MCP Security Framework - Universal security middleware for MCP servers.
 *
 * @module mcp-secure-server
 *
 * @description
 * A secure-by-default MCP server with 5-layer validation pipeline.
 * Drop-in replacement for McpServer with automatic protection against
 * path traversal, command injection, SQL injection, XSS, and 20+ attack vectors.
 *
 * @example Basic Usage
 * ```typescript
 * import { SecureMcpServer } from 'mcp-secure-server';
 * import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
 *
 * const server = new SecureMcpServer({ name: 'my-server', version: '1.0.0' });
 * server.tool('echo', 'Echo input', { text: z.string() }, async ({ text }) => ({
 *   content: [{ type: 'text', text }]
 * }));
 * await server.connect(new StdioServerTransport());
 * ```
 *
 * @example HTTP Server
 * ```typescript
 * import { SecureMcpServer, createSecureHttpServer } from 'mcp-secure-server';
 *
 * const server = new SecureMcpServer({ name: 'http-server', version: '1.0.0' });
 * const httpServer = createSecureHttpServer(server, { port: 3000 });
 * ```
 */

export {
  SecureMcpServer,
  SecureTransport,
  // Layer 5 exports for advanced configuration
  ContextualValidationLayer,
  ContextualConfigBuilder,
  createContextualLayer,
  // HTTP transport
  createSecureHttpServer,
  createSecureHttpHandler
} from "./security/index.js";

// Re-export types from security module
export type {
  ServerInfo,
  SecureMcpServerOptions,
  HttpServerOptions,
  HttpHandlerOptions,
  SecureHttpHandler,
  McpTransport,
  McpMessage,
  TransportValidationResult,
  TransportValidator,
  TransportValidationContext,
  SecureTransportOptions,
  ContextualLayerOptions
} from "./security/index.js";

// Re-export common types for consumers
export type {
  Severity,
  ViolationType,
  ValidationResult,
  ValidationContext,
  SecurityOptions,
  ToolSpec,
  ResourcePolicy,
  ChainingRule
} from "./types/index.js";

// Re-export type guards
export {
  isSeverity,
  isViolationType,
  isError,
  getErrorMessage
} from "./types/index.js";
