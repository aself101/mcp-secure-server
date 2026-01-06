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
import type { ToolSecurityLevel, ToolPolicy } from './tool-policies.js';

/**
 * Custom error class for tool policy configuration errors
 */
export class ToolPolicyError extends Error {
  constructor(
    message: string,
    public code: 'INVALID_CONFIG' | 'FILE_NOT_FOUND' | 'PARSE_ERROR' | 'INVALID_REFERENCE'
  ) {
    super(message);
    this.name = 'ToolPolicyError';
  }
}

/**
 * Zod schema for tool policy
 */
const toolPolicySchema = z.object({
  level: z.enum(['EXECUTION', 'QUERY', 'STORAGE', 'DISPLAY']),
  skipPatterns: z.array(z.string()).optional(),
  relaxedFields: z.array(z.string()).optional(),
  description: z.string().optional(),
  extends: z.string().optional()
});

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
 * Extended policy with inheritance support
 */
export interface ToolPolicyWithExtends extends ToolPolicy {
  extends?: string;
}

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
  } catch (err) {
    throw new ToolPolicyError(
      `Failed to read config file: ${path}`,
      'FILE_NOT_FOUND'
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new ToolPolicyError(
      `Invalid JSON in config file: ${path}`,
      'PARSE_ERROR'
    );
  }

  const result = toolPoliciesConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
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
 * Validate that all policy references point to valid base policies
 */
function validateReferences(config: ToolPoliciesConfig): void {
  const basePolicyNames = new Set(Object.keys(config.basePolicies || {}));

  // Check pattern references
  for (const pattern of config.patterns || []) {
    if (typeof pattern.policy === 'string' && !basePolicyNames.has(pattern.policy)) {
      throw new ToolPolicyError(
        `Pattern "${pattern.match}" references unknown base policy: "${pattern.policy}"`,
        'INVALID_REFERENCE'
      );
    }
  }

  // Check tool references
  for (const [toolName, policy] of Object.entries(config.tools || {})) {
    if (typeof policy === 'string' && !basePolicyNames.has(policy)) {
      throw new ToolPolicyError(
        `Tool "${toolName}" references unknown base policy: "${policy}"`,
        'INVALID_REFERENCE'
      );
    }
    if (typeof policy === 'object' && policy !== null) {
      const policyObj = policy as ToolPolicyWithExtends;
      if (policyObj.extends && !basePolicyNames.has(policyObj.extends)) {
        throw new ToolPolicyError(
          `Tool "${toolName}" extends unknown base policy: "${policyObj.extends}"`,
          'INVALID_REFERENCE'
        );
      }
    }
  }
}

/**
 * Resolve a policy reference or inline policy to a full ToolPolicy
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
    return resolved;
  }

  // Handle extends
  const policyWithExtends = policy as ToolPolicyWithExtends;
  if (policyWithExtends.extends && basePolicies) {
    return resolveWithExtends(policyWithExtends, basePolicies);
  }

  return policy;
}

/**
 * Resolve a policy that extends a base policy
 */
function resolveWithExtends(
  policy: ToolPolicyWithExtends,
  basePolicies: Record<string, ToolPolicy>
): ToolPolicy {
  if (!policy.extends) return policy;

  const base = basePolicies[policy.extends];
  if (!base) return policy;

  // Create new policy without extends field
  const { extends: _, ...policyWithoutExtends } = policy;

  return {
    ...base,
    ...policyWithoutExtends,
    // Merge arrays
    relaxedFields: [
      ...(base.relaxedFields || []),
      ...(policy.relaxedFields || [])
    ],
    skipPatterns: [
      ...(base.skipPatterns || []),
      ...(policy.skipPatterns || [])
    ]
  };
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
    const issues = result.error.issues.map(i => `  - ${i.path.join('.')}: ${i.message}`).join('\n');
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
 * Check if a tool name matches a glob-like pattern
 *
 * Supports:
 * - `*` matches any characters
 * - `?` matches single character
 * - Exact matches
 */
export function matchesPattern(toolName: string, pattern: string): boolean {
  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special regex chars except * and ?
    .replace(/\*/g, '.*')                   // * matches anything
    .replace(/\?/g, '.');                   // ? matches single char

  const regex = new RegExp(`^${regexPattern}$`, 'i');
  return regex.test(toolName);
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
