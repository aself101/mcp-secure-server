/**
 * Tool Policy Validation and Resolution
 *
 * Provides validation for policy references, circular inheritance detection,
 * and inheritance chain resolution for tool policies.
 */

import type { ToolPolicy } from './tool-policies.js';

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
 * Extended policy with inheritance support
 */
export interface ToolPolicyWithExtends extends ToolPolicy {
  extends?: string;
}

/**
 * Type guard to check if a policy object has an extends property.
 * Works with both ToolPolicy and Zod-inferred config types.
 */
export function hasExtends(policy: object): policy is { extends: string } {
  return 'extends' in policy && typeof (policy as { extends?: unknown }).extends === 'string';
}

/**
 * Validate a policy reference or inline policy with extends.
 *
 * @param policy - Policy to validate (string reference or object)
 * @param basePolicyNames - Set of valid base policy names
 * @param itemType - Type of item for error messages ('Pattern', 'Tool', 'Base policy')
 * @param itemName - Name of item for error messages
 */
export function validatePolicyReference(
  policy: PartialToolPolicy | string,
  basePolicyNames: Set<string>,
  itemType: string,
  itemName: string
): void {
  if (typeof policy === 'string') {
    if (!basePolicyNames.has(policy)) {
      throw new ToolPolicyError(
        `${itemType} "${itemName}" references unknown base policy: "${policy}"`,
        'INVALID_REFERENCE'
      );
    }
  } else if (policy !== null && hasExtends(policy)) {
    if (!basePolicyNames.has(policy.extends)) {
      throw new ToolPolicyError(
        `${itemType} "${itemName}" extends unknown base policy: "${policy.extends}"`,
        'INVALID_REFERENCE'
      );
    }
  }
}

/**
 * Detect circular inheritance chains in base policies.
 *
 * @param startName - Starting policy name to check
 * @param basePolicies - Record of all base policies
 * @throws ToolPolicyError if circular inheritance detected
 */
export function detectCircularInheritance(
  startName: string,
  basePolicies: Record<string, unknown>
): void {
  const visited = new Set<string>();
  let current = startName;

  while (current) {
    if (visited.has(current)) {
      throw new ToolPolicyError(
        `Circular inheritance detected: ${[...visited, current].join(' -> ')}`,
        'INVALID_CONFIG'
      );
    }
    visited.add(current);

    const policy = basePolicies[current] as ToolPolicyWithExtends | undefined;
    current = policy?.extends ?? '';
  }
}

/**
 * Partial policy type for validation (level may be undefined when extends is used)
 */
export type PartialToolPolicy = Partial<ToolPolicy> & { extends?: string };

/**
 * Configuration structure for validation
 */
export interface ToolPoliciesConfigForValidation {
  basePolicies?: Record<string, PartialToolPolicy>;
  patterns?: Array<{ match: string; policy: PartialToolPolicy | string }>;
  tools?: Record<string, PartialToolPolicy | string>;
}

/**
 * Validate that all policy references point to valid base policies
 * and detect circular inheritance chains.
 *
 * @param config - Configuration to validate
 * @throws ToolPolicyError if invalid references or circular inheritance found
 */
export function validateReferences(config: ToolPoliciesConfigForValidation): void {
  const basePolicyNames = new Set(Object.keys(config.basePolicies || {}));

  // Check for circular references in base policies
  if (config.basePolicies) {
    for (const [name, policy] of Object.entries(config.basePolicies)) {
      if (hasExtends(policy)) {
        // Validate reference exists
        if (!basePolicyNames.has(policy.extends)) {
          throw new ToolPolicyError(
            `Base policy "${name}" extends unknown base policy: "${policy.extends}"`,
            'INVALID_REFERENCE'
          );
        }
        // Check for circular reference
        detectCircularInheritance(name, config.basePolicies);
      }
    }
  }

  // Check pattern references and extends
  for (const pattern of config.patterns || []) {
    validatePolicyReference(pattern.policy, basePolicyNames, 'Pattern', pattern.match);
  }

  // Check tool references and extends
  for (const [toolName, policy] of Object.entries(config.tools || {})) {
    validatePolicyReference(policy, basePolicyNames, 'Tool', toolName);
  }
}

/**
 * Resolve a policy that extends a base policy with full inheritance chain support.
 *
 * Features:
 * - Chain inheritance: base policies can extend other base policies
 * - Array deduplication: merged arrays have no duplicates
 * - Circular reference detection: prevents infinite loops
 *
 * @param policy - Policy with extends property
 * @param basePolicies - Record of all base policies
 * @param visited - Set of already visited policy names (for circular detection)
 * @returns Resolved policy with inheritance applied
 *
 * @example
 * // Chain inheritance
 * basePolicies: {
 *   "base": { level: "STORAGE", relaxedFields: ["content"] },
 *   "extended": { extends: "base", relaxedFields: ["title"] }
 * }
 * // "extended" gets: level: "STORAGE", relaxedFields: ["content", "title"]
 */
export function resolveWithExtends(
  policy: ToolPolicyWithExtends & { extends: string },
  basePolicies: Record<string, ToolPolicy>,
  visited: Set<string> = new Set()
): ToolPolicy {
  // Circular reference detection
  if (visited.has(policy.extends)) {
    throw new ToolPolicyError(
      `Circular inheritance detected: ${[...visited, policy.extends].join(' -> ')}`,
      'INVALID_REFERENCE'
    );
  }

  const base = basePolicies[policy.extends];
  if (!base) return policy;

  // Recursively resolve base if it also extends something
  const resolvedBase = hasExtends(base)
    ? resolveWithExtends(base, basePolicies, new Set([...visited, policy.extends]))
    : base;

  // Create new policy without extends field
  const { extends: _, ...policyWithoutExtends } = policy;

  // Deduplicate helper
  const dedupe = (arr: string[]): string[] => [...new Set(arr)];

  return {
    ...resolvedBase,
    ...policyWithoutExtends,
    // Merge and deduplicate arrays
    relaxedFields: dedupe([
      ...(resolvedBase.relaxedFields || []),
      ...(policy.relaxedFields || [])
    ]),
    skipPatterns: dedupe([
      ...(resolvedBase.skipPatterns || []),
      ...(policy.skipPatterns || [])
    ])
  };
}
