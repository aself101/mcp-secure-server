/**
 * MCP Security Framework - Universal security middleware for MCP servers.
 */

export {
  SecureMcpServer,
  SecureTransport,
  // Layer 5 exports for advanced configuration
  ContextualValidationLayer,
  ContextualConfigBuilder,
  createContextualLayer
} from "./security/index.js";

// Re-export types from security module
export type {
  ServerInfo,
  SecureMcpServerOptions,
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
  ResourcePolicy
} from "./types/index.js";

// Re-export type guards
export {
  isSeverity,
  isViolationType,
  isError,
  getErrorMessage
} from "./types/index.js";
