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
 * ## Export Categories
 *
 * ### Core Exports (Most Users)
 * - {@link SecureMcpServer} - Main secure server class (drop-in McpServer replacement)
 * - {@link createSecureHttpServer} - HTTP server factory for remote deployments
 * - {@link registerToolPolicy} - Register tool security policies at runtime
 *
 * ### Advanced Exports (Customization)
 * - {@link SecureTransport} - Low-level transport wrapper
 * - {@link ContextualValidationLayer} - Layer 5 for custom validators
 * - {@link ContextualConfigBuilder} - Fluent builder for Layer 5 config
 * - {@link createContextualLayer} - Factory function for Layer 5
 * - {@link createSecureHttpHandler} - HTTP handler for multi-endpoint servers
 *
 * ### Tool Policy Helpers
 * - {@link getToolPolicy} - Get resolved policy for a tool
 * - {@link isRelaxedField} - Check if field has relaxed validation
 * - {@link getToolsByLevel} - List tools by security level
 * - {@link isValidSecurityLevel} - Validate security level strings
 * - {@link defaultToolPolicies} - Default policy definitions
 *
 * ### Tool Policy Configuration (v2)
 * - {@link loadToolPoliciesConfig} - Load policies from JSON file
 * - {@link initializeToolPolicies} - Load policies from object
 * - {@link resetToolPolicies} - Reset to defaults
 * - {@link getToolPoliciesConfig} - Get current config
 * - {@link matchesPattern} - Test tool name against pattern
 * - {@link resolvePolicy} - Resolve policy with inheritance
 * - {@link ToolPolicyError} - Configuration error class
 *
 * ### Security Presets
 * - {@link SECURITY_PRESETS} - Preset configurations (basic/standard/paranoid)
 * - {@link resolvePreset} - Resolve preset to full config
 * - {@link getDefaultPreset} - Get default preset config
 * - {@link isValidPreset} - Validate preset name
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

// ═══════════════════════════════════════════════════════════════════════════════
// CORE EXPORTS - Most users only need these
// ═══════════════════════════════════════════════════════════════════════════════

export {
  SecureMcpServer,
  SecureTransport,
  // Layer 5 exports for advanced configuration
  ContextualValidationLayer,
  ContextualConfigBuilder,
  createContextualLayer,
  // HTTP transport
  createSecureHttpServer,
  createSecureHttpHandler,
  // Tool policy configuration
  getToolPolicy,
  isRelaxedField,
  getToolsByLevel,
  registerToolPolicy,
  isValidSecurityLevel,
  defaultToolPolicies,
  // Tool policy config v2
  loadToolPoliciesConfig,
  initializeToolPolicies,
  resetToolPolicies,
  getToolPoliciesConfig,
  matchesPattern,
  resolvePolicy,
  ToolPolicyError,
  // Security presets
  SECURITY_PRESETS,
  resolvePreset,
  getDefaultPreset,
  isValidPreset
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
  ContextualLayerOptions,
  ToolSecurityLevel,
  ToolPolicy,
  // Tool policy config v2 types
  ToolPoliciesConfig,
  ToolPolicyWithExtends,
  PatternEntry,
  // Security preset types
  SecurityPreset,
  PresetConfiguration
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

// Re-export ServerCapabilities from MCP SDK for convenience
export type { ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";
