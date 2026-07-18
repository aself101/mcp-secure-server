/**
 * Tool Security Classification Registry
 *
 * Defines security levels for MCP tools to enable context-aware validation.
 * Tools that store/display data have relaxed content checks compared to
 * tools that execute commands or access files.
 *
 * Supports configuration file loading with priority:
 * 1. TOOL_POLICIES_PATH environment variable
 * 2. ./tool-policies.json in current working directory
 * 3. ~/.config/mcp-secure-server/tool-policies.json
 * 4. Built-in defaults (this file)
 */

import { resolveToolPolicyFromConfig } from './tool-policies-config.js';

/**
 * Security classification levels for tools
 *
 * EXECUTION: Full validation - tools that run commands, execute code, or access files
 * QUERY: Standard validation - database queries, API requests, search tools
 * STORAGE: Relaxed content validation - issue trackers, notes, documentation
 * DISPLAY: Minimal validation - read-only query results, help output
 */
export type ToolSecurityLevel = 'EXECUTION' | 'QUERY' | 'STORAGE' | 'DISPLAY';

/**
 * Policy configuration for a specific tool
 */
export interface ToolPolicy {
  /** Security level determining which patterns to check */
  level: ToolSecurityLevel;
  /** Specific pattern names to skip for this tool */
  skipPatterns?: string[];
  /** Field names with relaxed validation (content in these fields uses STORAGE rules) */
  relaxedFields?: string[];
  /** Description for documentation/debugging */
  description?: string;
}

/**
 * Runtime tool policies registry
 *
 * This registry starts empty - policies are loaded from configuration files.
 * Use registerToolPolicy() for programmatic registration at runtime.
 */
export const defaultToolPolicies: Record<string, ToolPolicy> = {};

/**
 * Get the security policy for a tool
 *
 * Resolution order:
 * 1. Loaded configuration (explicit tools, then pattern matching)
 * 2. Built-in defaults (defaultToolPolicies)
 * 3. Config defaultLevel (if set)
 * 4. EXECUTION level (most restrictive fallback)
 *
 * @param toolName - Name of the MCP tool
 * @returns Policy for the tool, defaults to EXECUTION level
 */
export function getToolPolicy(toolName: string): ToolPolicy {
  // Check loaded config first (handles explicit tools, patterns, and defaultLevel)
  const configPolicy = resolveToolPolicyFromConfig(toolName, defaultToolPolicies);
  if (configPolicy) {
    return configPolicy;
  }

  // Fall back to built-in defaults
  return defaultToolPolicies[toolName] || {
    level: 'EXECUTION',
    description: 'Unknown tool - using maximum security'
  };
}

/**
 * Check if a field should use relaxed validation for a tool
 * @param toolName - Name of the MCP tool
 * @param fieldName - Name of the field to check
 * @returns true if the field should use relaxed validation
 */
export function isRelaxedField(toolName: string, fieldName: string): boolean {
  const policy = getToolPolicy(toolName);
  if (!policy.relaxedFields) return false;
  return policy.relaxedFields.includes(fieldName);
}

/**
 * Get all tools at a specific security level
 * @param level - Security level to filter by
 * @returns Array of tool names at that level
 */
export function getToolsByLevel(level: ToolSecurityLevel): string[] {
  return Object.entries(defaultToolPolicies)
    .filter(([_, policy]) => policy.level === level)
    .map(([name]) => name);
}

/**
 * Register a custom tool policy (for runtime configuration)
 * @param toolName - Name of the tool
 * @param policy - Policy to apply
 * @throws Error if the policy's level is not a valid security level — an invalid
 *   level would otherwise be stored silently and fall through to EXECUTION behavior
 *   at lookup time, leaving the caller wondering why their relaxed tool still rejects.
 */
export function registerToolPolicy(toolName: string, policy: ToolPolicy): void {
  if (!isValidSecurityLevel(policy.level)) {
    throw new Error(
      `Invalid security level "${String(policy.level)}" for tool "${toolName}". ` +
      `Valid levels: 'EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY'.`
    );
  }
  defaultToolPolicies[toolName] = policy;
}

/**
 * Validate that a security level is valid
 */
export function isValidSecurityLevel(level: string): level is ToolSecurityLevel {
  return ['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY'].includes(level);
}
