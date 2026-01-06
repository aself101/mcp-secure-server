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
 * Default tool policies for known MCP tools
 * Unknown tools default to EXECUTION level (most restrictive)
 */
export const defaultToolPolicies: Record<string, ToolPolicy> = {
  // ============================================
  // STORAGE Level - Documentation/Tracking Tools
  // ============================================

  // Validation tracker tools - store technical descriptions
  'save_features_list': {
    level: 'STORAGE',
    relaxedFields: ['description', 'title', 'raw_markdown', 'recommendations'],
    description: 'Stores validation results with technical descriptions'
  },
  'update_status': {
    level: 'STORAGE',
    relaxedFields: ['reason'],
    description: 'Updates issue status with optional reason'
  },
  'add_issue_note': {
    level: 'STORAGE',
    relaxedFields: ['content'],
    description: 'Adds notes to issues - may contain code snippets'
  },
  'bulk_update_status': {
    level: 'STORAGE',
    relaxedFields: ['reason'],
    description: 'Bulk status updates with reasons'
  },
  'edit_issue': {
    level: 'STORAGE',
    relaxedFields: ['title', 'category', 'file_path', 'description'],
    description: 'Edits issue metadata'
  },
  'update_run': {
    level: 'STORAGE',
    relaxedFields: ['raw_markdown'],
    description: 'Updates run metadata - raw_markdown can contain validator output'
  },
  'validate_features_list': {
    level: 'STORAGE',
    relaxedFields: ['description', 'title', 'raw_markdown', 'recommendations'],
    description: 'Preview/dry-run of save_features_list'
  },
  'archive_runs': {
    level: 'STORAGE',
    relaxedFields: ['reason'],
    description: 'Archives old runs with optional reason'
  },
  'rename_project': {
    level: 'STORAGE',
    description: 'Renames project - no sensitive fields'
  },
  'merge_issues': {
    level: 'STORAGE',
    description: 'Merges issues - no content fields'
  },
  'restore_issue': {
    level: 'STORAGE',
    description: 'Restores issue status'
  },
  'undo_status_update': {
    level: 'STORAGE',
    description: 'Undoes last status change'
  },
  'restore_project': {
    level: 'STORAGE',
    description: 'Restores soft-deleted project'
  },

  // Memory/context tools
  'mem-save': {
    level: 'STORAGE',
    relaxedFields: ['content', 'observation'],
    description: 'Saves observations to memory'
  },

  // ============================================
  // DISPLAY Level - Read-only Query Tools
  // ============================================

  'query_issues': {
    level: 'DISPLAY',
    description: 'Queries issues with filters'
  },
  'search_issues': {
    level: 'DISPLAY',
    description: 'Searches issues by text'
  },
  'get_project_summary': {
    level: 'DISPLAY',
    description: 'Gets project summary statistics'
  },
  'get_issue_details': {
    level: 'DISPLAY',
    description: 'Gets detailed issue information'
  },
  'get_run_details': {
    level: 'DISPLAY',
    description: 'Gets validation run details'
  },
  'get_issue_history': {
    level: 'DISPLAY',
    description: 'Gets issue history'
  },
  'diff_runs': {
    level: 'DISPLAY',
    description: 'Compares two validation runs'
  },
  'get_analytics': {
    level: 'DISPLAY',
    description: 'Gets analytics data'
  },
  'list_validators': {
    level: 'DISPLAY',
    description: 'Lists available validators'
  },
  'get_validator_reliability': {
    level: 'DISPLAY',
    description: 'Gets validator reliability stats'
  },

  // Memory search tools
  'mem-search': {
    level: 'DISPLAY',
    description: 'Searches memory observations'
  },
  'timeline': {
    level: 'DISPLAY',
    description: 'Gets timeline context'
  },
  'get_recent_context': {
    level: 'DISPLAY',
    description: 'Gets recent memory context'
  },
  'get_observation': {
    level: 'DISPLAY',
    description: 'Gets single memory observation'
  },
  'get_observations': {
    level: 'DISPLAY',
    description: 'Gets multiple memory observations'
  },
  'get_session': {
    level: 'DISPLAY',
    description: 'Gets session details'
  },
  'get_prompt': {
    level: 'DISPLAY',
    description: 'Gets prompt details'
  },
  'get_context_timeline': {
    level: 'DISPLAY',
    description: 'Gets timeline around anchor'
  },
  'help': {
    level: 'DISPLAY',
    description: 'Gets usage help'
  },

  // ============================================
  // QUERY Level - Data Access Tools
  // ============================================

  'query-users': {
    level: 'QUERY',
    description: 'Queries user database'
  },
  'generate-report': {
    level: 'QUERY',
    description: 'Generates reports from data'
  },
  'financial-query': {
    level: 'QUERY',
    description: 'Queries financial data'
  },
  'export-data': {
    level: 'QUERY',
    description: 'Exports datasets'
  },

  // ============================================
  // EXECUTION Level - Dangerous Operations
  // These get full validation (explicit for documentation)
  // ============================================

  'create-order': {
    level: 'EXECUTION',
    description: 'Creates orders - modifies database'
  },
  'batch-process': {
    level: 'EXECUTION',
    description: 'Runs batch operations'
  },
  'api-call': {
    level: 'EXECUTION',
    description: 'Makes external API calls'
  },
  'delete_project': {
    level: 'EXECUTION',
    description: 'Permanently deletes project data'
  },
  'soft_delete_project': {
    level: 'EXECUTION',
    description: 'Soft deletes project'
  }
};

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
 */
export function registerToolPolicy(toolName: string, policy: ToolPolicy): void {
  defaultToolPolicies[toolName] = policy;
}

/**
 * Validate that a security level is valid
 */
export function isValidSecurityLevel(level: string): level is ToolSecurityLevel {
  return ['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY'].includes(level);
}
