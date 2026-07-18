/**
 * Tool Policies Configuration Loader
 *
 * Loads tool security policies from configuration files with priority:
 * 1. TOOL_POLICIES_PATH environment variable
 * 2. ./tool-policies.json in current working directory
 * 3. ~/.config/mcp-secure-server/tool-policies.json
 * 4. Built-in defaults
 */

import { z } from 'zod';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { minimatch } from 'minimatch';
import type { ToolSecurityLevel, ToolPolicy } from './tool-policies.js';
import {
  ToolPolicyError,
  hasExtends,
  validateReferences,
  resolveWithExtends
} from './tool-policy-validation.js';

// Re-export for backward compatibility
export { ToolPolicyError } from './tool-policy-validation.js';
export type { ToolPolicyWithExtends } from './tool-policy-validation.js';

/**
 * Zod schema for tool policy
 *
 * level is optional when extends is present (will inherit from base)
 */
const toolPolicySchema = z.object({
  level: z.enum(['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY']).optional(),
  skipPatterns: z.array(z.string()).optional(),
  relaxedFields: z.array(z.string()).optional(),
  description: z.string().optional(),
  extends: z.string().optional()
}).refine(
  (data) => data.level !== undefined || data.extends !== undefined,
  { message: 'Either level or extends must be specified' }
);

/**
 * Zod schema for pattern entry
 */
const patternEntrySchema = z.object({
  match: z.string().min(1),
  policy: z.union([toolPolicySchema, z.string()])
});

/**
 * Zod schema for the complete configuration file
 */
const toolPoliciesConfigSchema = z.object({
  version: z.literal('2.0' as const),
  basePolicies: z.record(z.string(), toolPolicySchema).optional(),
  patterns: z.array(patternEntrySchema).optional(),
  tools: z.record(z.string(), z.union([toolPolicySchema, z.string()])).optional(),
  defaultLevel: z.enum(['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY']).optional()
});

/**
 * Configuration file structure
 */
export type ToolPoliciesConfig = z.infer<typeof toolPoliciesConfigSchema>;

/**
 * Pattern entry for matching tool names
 */
export interface PatternEntry {
  match: string;
  policy: ToolPolicy | string;
}

/**
 * Internal state for loaded configuration
 */
let loadedConfig: ToolPoliciesConfig | null = null;

/**
 * Get default config file paths in priority order
 */
function getConfigPaths(): string[] {
  const paths: string[] = [];

  // 1. Environment variable
  if (process.env.TOOL_POLICIES_PATH) {
    paths.push(process.env.TOOL_POLICIES_PATH);
  }

  // 2. Current working directory
  paths.push(join(process.cwd(), 'tool-policies.json'));

  // 3. User config directory
  paths.push(join(homedir(), '.config', 'mcp-secure-server', 'tool-policies.json'));

  return paths;
}

/**
 * Format Zod issues for error messages, unwrapping union branches.
 *
 * The `tools` and `patterns[].policy` values are unions of (inline policy | base-policy
 * reference string). When an inline policy has e.g. a bad `level`, Zod's union issue
 * surfaces only "Invalid input" — the enum diagnostic naming the failing field and the
 * valid values lives in the nested branch errors. Recurse into the most specific branch
 * (deepest issue paths) so the caller sees `tools.my_tool.level: Invalid option:
 * expected one of "EXECUTION"|"QUERY"|"STORAGE"|"DISPLAY"` instead of the generic line.
 */
function formatZodIssues(
  issues: readonly z.core.$ZodIssue[],
  basePath: PropertyKey[] = []
): string[] {
  return issues.flatMap((issue) => {
    const path = [...basePath, ...issue.path];
    if (issue.code === 'invalid_union' && Array.isArray(issue.errors) && issue.errors.length > 0) {
      const depth = (branch: readonly z.core.$ZodIssue[]): number =>
        Math.max(0, ...branch.map(b => b.path.length));
      const best = issue.errors.reduce((a, b) => (depth(b) > depth(a) ? b : a));
      return formatZodIssues(best, path);
    }
    return [`  - ${path.map(String).join('.')}: ${issue.message}`];
  });
}

/**
 * Find the first existing config file from priority list
 */
function findConfigFile(customPath?: string): string | null {
  if (customPath) {
    return existsSync(customPath) ? customPath : null;
  }

  const paths = getConfigPaths();
  for (const path of paths) {
    if (existsSync(path)) {
      return path;
    }
  }

  return null;
}

/**
 * Parse and validate a configuration file
 */
async function parseConfigFile(path: string): Promise<ToolPoliciesConfig> {
  let content: string;
  try {
    content = await readFile(path, 'utf-8');
  } catch {
    throw new ToolPolicyError(
      `Failed to read config file: ${path}`,
      'FILE_NOT_FOUND'
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new ToolPolicyError(
      `Invalid JSON in config file: ${path}`,
      'PARSE_ERROR'
    );
  }

  const result = toolPoliciesConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = formatZodIssues(result.error.issues).join('\n');
    throw new ToolPolicyError(
      `Invalid config schema in ${path}:\n${issues}`,
      'INVALID_CONFIG'
    );
  }

  // Validate base policy references
  validateReferences(result.data);

  return result.data;
}

/**
 * Resolve a policy reference or inline policy to a full ToolPolicy
 *
 * Handles:
 * - String references to base policies (with full chain resolution)
 * - Inline policies with extends
 * - Plain inline policies
 */
export function resolvePolicy(
  policy: ToolPolicy | string,
  basePolicies?: Record<string, ToolPolicy>
): ToolPolicy {
  if (typeof policy === 'string') {
    const resolved = basePolicies?.[policy];
    if (!resolved) {
      return { level: 'EXECUTION' as ToolSecurityLevel, description: 'Unknown reference - using default' };
    }
    // If the base policy itself has extends, resolve the chain
    if (hasExtends(resolved) && basePolicies) {
      return resolveWithExtends(resolved, basePolicies);
    }
    return resolved;
  }

  // Handle extends
  if (hasExtends(policy) && basePolicies) {
    return resolveWithExtends(policy, basePolicies);
  }

  return policy;
}

/**
 * Load tool policies configuration from file
 *
 * @param path - Optional explicit path to config file
 * @returns The loaded configuration, or null if no config file found
 */
export async function loadToolPoliciesConfig(
  path?: string
): Promise<ToolPoliciesConfig | null> {
  const configPath = findConfigFile(path);

  if (!configPath) {
    return null;
  }

  return parseConfigFile(configPath);
}

/**
 * Initialize the tool policies system with a configuration
 *
 * @param config - Configuration to use
 */
export function initializeToolPolicies(config: ToolPoliciesConfig): void {
  // Validate config
  const result = toolPoliciesConfigSchema.safeParse(config);
  if (!result.success) {
    const issues = formatZodIssues(result.error.issues).join('\n');
    throw new ToolPolicyError(
      `Invalid config:\n${issues}`,
      'INVALID_CONFIG'
    );
  }

  validateReferences(config);
  loadedConfig = config;
}

/**
 * Reset tool policies to defaults (clear loaded configuration)
 */
export function resetToolPolicies(): void {
  loadedConfig = null;
}

/**
 * Get the currently loaded configuration
 */
export function getToolPoliciesConfig(): ToolPoliciesConfig | null {
  return loadedConfig;
}

/**
 * Check if a tool name matches a glob pattern using minimatch
 *
 * Supports full glob syntax:
 * - `*` matches any characters (except path separators)
 * - `**` matches any characters including path separators
 * - `?` matches single character
 * - `[abc]` matches any character in brackets
 * - `{a,b}` matches either pattern
 * - `!(pattern)` negative match
 *
 * @example
 * matchesPattern('get_issues', 'get_*') // true
 * matchesPattern('query_issues', '*_issues') // true
 * matchesPattern('mem-search', 'mem-*') // true
 * matchesPattern('v1_tool', 'v?_tool') // true
 * matchesPattern('get_users', '{get,list}_*') // true
 */
export function matchesPattern(toolName: string, pattern: string): boolean {
  return minimatch(toolName, pattern, { nocase: true });
}

/**
 * Resolve tool policy from loaded configuration
 *
 * Resolution order:
 * 1. Explicit tools in config
 * 2. Pattern matching (first match wins)
 * 3. Built-in defaults (handled by caller)
 * 4. Config defaultLevel
 *
 * @returns The resolved policy, or null to use built-in defaults
 */
export function resolveToolPolicyFromConfig(
  toolName: string,
  builtInDefaults: Record<string, ToolPolicy>
): ToolPolicy | null {
  if (!loadedConfig) {
    return null;
  }

  // Cast basePolicies to the expected type (Zod inference is compatible)
  const basePolicies = loadedConfig.basePolicies as Record<string, ToolPolicy> | undefined;

  // 1. Explicit tool definition
  const toolPolicy = loadedConfig.tools?.[toolName];
  if (toolPolicy) {
    return resolvePolicy(toolPolicy as ToolPolicy | string, basePolicies);
  }

  // 2. Pattern matching
  for (const { match, policy } of loadedConfig.patterns || []) {
    if (matchesPattern(toolName, match)) {
      return resolvePolicy(policy as ToolPolicy | string, basePolicies);
    }
  }

  // 3. Check built-in defaults
  if (builtInDefaults[toolName]) {
    return null;  // Let caller use built-in default
  }

  // 4. Config default level
  if (loadedConfig.defaultLevel) {
    return {
      level: loadedConfig.defaultLevel,
      description: 'Using config defaultLevel'
    };
  }

  return null;
}

export { toolPoliciesConfigSchema };
