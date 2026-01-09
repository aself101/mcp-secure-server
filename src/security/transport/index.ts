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

export { createSecureHttpServer, createSecureHttpHandler } from './http-server.js';
export type { HttpServerOptions, HttpHandlerOptions, SecureHttpHandler, SecureServerHttpInterface } from './http-server.js';

export { createTransportValidator } from './transport-validator.js';
export type { TransportValidatorOptions, TransportValidatorDependencies } from './transport-validator.js';
