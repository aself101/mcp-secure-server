/**
 * Security module exports for MCP servers.
 */

import { SecureMcpServer } from "./mcp-secure-server.js";
import { SecureTransport, createSecureHttpServer, createSecureHttpHandler } from "./transport/index.js";
import ContextualValidationLayer, {
  ContextualConfigBuilder,
  createContextualLayer
} from "./layers/layer5-contextual.js";
import {
  SECURITY_PRESETS,
  resolvePreset,
  getDefaultPreset,
  isValidPreset
} from "./presets.js";

// Tool policy configuration
import {
  getToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  registerToolPolicy,
  isValidSecurityLevel,
  defaultToolPolicies,
  // Config v2 exports
  loadToolPoliciesConfig,
  initializeToolPolicies,
  resetToolPolicies,
  getToolPoliciesConfig,
  matchesPattern,
  resolvePolicy,
  ToolPolicyError
} from "./config/index.js";

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

/**
 * Creates a standalone HTTP server with security validation.
 * Uses node:http directly for zero external dependencies.
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Server configuration options
 * @returns Node.js HTTP server (call .listen() to start)
 */
export { createSecureHttpServer };

/**
 * Creates an HTTP request handler with security validation.
 * Use this for composing multiple MCP endpoints on a single server.
 * @param secureMcpServer - SecureMcpServer instance
 * @param options - Handler configuration options
 * @returns Request handler function (req, res) => Promise<void>
 */
export { createSecureHttpHandler };

// Re-export types for consumers
export type { ServerInfo, SecureMcpServerOptions, HttpServerOptions } from "./mcp-secure-server.js";
export type {
  McpTransport,
  McpMessage,
  TransportValidationResult,
  TransportValidator,
  TransportValidationContext,
  SecureTransportOptions,
  HttpHandlerOptions,
  SecureHttpHandler
} from "./transport/index.js";
export type { ContextualLayerOptions } from "./layers/layer5-contextual.js";

// Tool policy exports for context-aware validation
export {
  getToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  registerToolPolicy,
  isValidSecurityLevel,
  defaultToolPolicies,
  // Config v2 exports
  loadToolPoliciesConfig,
  initializeToolPolicies,
  resetToolPolicies,
  getToolPoliciesConfig,
  matchesPattern,
  resolvePolicy,
  ToolPolicyError
};

export type {
  ToolSecurityLevel,
  ToolPolicy,
  ToolPoliciesConfig,
  ToolPolicyWithExtends,
  PatternEntry
} from "./config/index.js";

// Security preset exports
export {
  SECURITY_PRESETS,
  resolvePreset,
  getDefaultPreset,
  isValidPreset
};

export type {
  SecurityPreset,
  PresetConfiguration
} from "./presets.js";
