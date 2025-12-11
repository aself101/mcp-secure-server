/**
 * Transport security module for MCP servers.
 * Provides SecureTransport wrapper for validating all incoming messages.
 */

export { SecureTransport } from './secure-transport.js';
export type {
  McpTransport,
  McpMessage,
  TransportValidationResult,
  TransportValidator,
  TransportValidationContext,
  SecureTransportOptions
} from './secure-transport.js';
