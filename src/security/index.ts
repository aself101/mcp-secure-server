/**
 * Security module exports for MCP servers.
 */

import { SecureMcpServer } from "./mcp-secure-server.js";
import { SecureTransport } from "./transport/index.js";
import ContextualValidationLayer, {
  ContextualConfigBuilder,
  createContextualLayer
} from "./layers/layer5-contextual.js";

/**
 * Drop-in replacement for McpServer with built-in 5-layer security validation.
 * Provides comprehensive protection against traditional attacks and AI-driven threats.
 * @see SecureMcpServerOptions for configuration options
 */
export { SecureMcpServer };

/**
 * Low-level transport wrapper that validates all incoming messages.
 * Use this for custom transport implementations or when you need direct control.
 * @see SecureTransportOptions for configuration options
 */
export { SecureTransport };

/**
 * Layer 5 validation class for adding custom validators, domain restrictions,
 * OAuth validation, and response filtering. Enabled by default in SecureMcpServer.
 * @see ContextualLayerOptions for configuration options
 */
export { ContextualValidationLayer };

/**
 * Fluent builder for constructing Layer 5 (Contextual) configuration.
 * Provides a chainable API for setting up domain restrictions, OAuth validation,
 * rate limiting, and custom validators.
 */
export { ContextualConfigBuilder };

/**
 * Factory function that creates a pre-configured ContextualValidationLayer
 * with sensible defaults. Use this for quick Layer 5 setup.
 * @param options - Optional configuration to override defaults
 * @returns Configured ContextualValidationLayer instance
 */
export { createContextualLayer };

// Re-export types for consumers
export type { ServerInfo, SecureMcpServerOptions } from "./mcp-secure-server.js";
export type {
  McpTransport,
  McpMessage,
  TransportValidationResult,
  TransportValidator,
  TransportValidationContext,
  SecureTransportOptions
} from "./transport/index.js";
export type { ContextualLayerOptions } from "./layers/layer5-contextual.js";
