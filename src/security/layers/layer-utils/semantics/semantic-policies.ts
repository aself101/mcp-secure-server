/**
 * Policy definitions and enforcement helpers for semantic validation
 * - Tool registry with contracts and constraints
 * - Resource access policies and path validation
 * - Method specifications and chaining rules
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { globToRegExp } from './glob-utils.js';

// Re-export types for backward compatibility
export type {
  ArgType,
  ArgDefinition,
  SideEffects,
  ToolSpec,
  ResourcePolicy,
  MethodParamSpec,
  MethodSpec,
  ChainingRule,
  Policies,
  NormalizedPolicies,
  PolicyValidationResult,
  PathContext,
  ToolCallParams
} from './semantic-policies-types.js';

// Import types for internal use
import type {
  ArgType,
  ToolSpec,
  ResourcePolicy,
  MethodSpec,
  ChainingRule,
  Policies,
  NormalizedPolicies,
  PolicyValidationResult,
  ToolCallParams
} from './semantic-policies-types.js';

// Re-export resource validation functions for backward compatibility
export {
  validateResourceAccess,
  isUnderAllowedRoots,
  matchesDenyGlobs
} from './semantic-resource-validation.js';

// Re-export glob utilities for backward compatibility
export { simpleGlobMatch, GLOB_CACHE_MAX_SIZE } from './glob-utils.js';

/**
 * Get default policy configuration
 */
export function getDefaultPolicies(): Policies {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const testData = path.resolve(__dirname, '../../../../test-data');

  return {
    tools: [
      {
        name: 'debug-calculator',
        sideEffects: 'none',
        maxArgsSize: 2_000,
        maxEgressBytes: 8_000,
        quotaPerMinute: 120,
        quotaPerHour: 3_000,
        argsShape: { expression: { type: 'string' } }
      },
      {
        name: 'debug-file-reader',
        sideEffects: 'read',
        maxArgsSize: 2_000,
        maxEgressBytes: 1_000_000,
        quotaPerMinute: 60,
        quotaPerHour: 1_000,
        argsShape: { path: { type: 'string' } }
      },
      {
        name: 'debug-echo',
        sideEffects: 'none',
        maxArgsSize: 8_000,
        maxEgressBytes: 64_000,
        quotaPerMinute: 240,
        quotaPerHour: 5_000,
        argsShape: { text: { type: 'string' } }
      },
    ],
    resourcePolicy: {
      allowedSchemes: ['file'],
      rootDirs: [testData],
      denyGlobs: [
        '/proc/**', '/sys/**', '/dev/**', '/var/**', '/run/**',
        '**/*.key', '**/*.pem', '**/*.pfx', '**/*.p12', '**/.env',
        '**/id_rsa', '**/id_dsa', '**/id_ecdsa'
      ],
      maxPathLength: 4096,
      maxUriLength: 2048,
      maxReadBytes: 2_000_000
    },
    methodSpec: {
      shape: {
        'initialize': { required: [] },
        'ping': { required: [] },
        'tools/list': { required: [] },
        'tools/call': { required: ['name'] },
        'resources/list': { required: [] },
        'resources/read': { required: ['uri'] },
        'prompts/list': { required: [] },
        'prompts/get': { required: ['name'] },
        'notifications/initialized': { required: [] },
        'notifications/cancelled': { required: [] },
        'notifications/progress': { required: [] },
      }
    },
    chainingRules: [
      { from: '*', to: 'initialize' },
      { from: 'initialize', to: 'tools/list' },
      { from: 'initialize', to: 'resources/list' },
      { from: 'initialize', to: 'prompts/list' },
      { from: '*', to: 'ping' },
      { from: 'tools/list', to: 'tools/call' },
      { from: 'prompts/list', to: 'prompts/get' },
      { from: 'prompts/get', to: 'tools/call' },
      { from: 'resources/list', to: 'resources/read' },
      { from: 'tools/call', to: 'tools/call' },
      { from: 'resources/read', to: 'resources/read' }
    ]
  };
}

/**
 * Normalize policies by resolving paths and compiling globs
 */
export function normalizePolicies({ resourcePolicy, methodSpec, chainingRules }: {
  resourcePolicy: ResourcePolicy;
  methodSpec: MethodSpec;
  chainingRules: ChainingRule[];
}): NormalizedPolicies {
  const normalizedRoots = (resourcePolicy.rootDirs || [])
    .map(p => path.normalize(path.resolve(p)));

  const normalizedGlobs = (resourcePolicy.denyGlobs || [])
    .map(g => g instanceof RegExp ? g : globToRegExp(g));

  return {
    resourcePolicy: {
      ...resourcePolicy,
      rootDirs: normalizedRoots,
      denyGlobs: normalizedGlobs
    },
    methodSpec,
    chainingRules
  };
}

/**
 * Validate tool call against tool specification
 */
export function validateToolCall(tool: ToolSpec, params: ToolCallParams | null | undefined): PolicyValidationResult {
  if (tool.argsShape) {
    const args = params?.arguments ?? params?.args ?? {};
    if (typeof args !== 'object' || args === null) {
      return {
        passed: false,
        reason: `Tool "${tool.name}" requires an arguments object`,
        severity: 'MEDIUM',
        violationType: 'INVALID_TOOL_ARGUMENTS'
      };
    }

    for (const [key, definition] of Object.entries(tool.argsShape)) {
      if (!definition.optional && !(key in args)) {
        return {
          passed: false,
          reason: `Tool "${tool.name}" missing required argument: "${key}"`,
          severity: 'MEDIUM',
          violationType: 'MISSING_REQUIRED_PARAM'
        };
      }
      if (key in args && !typeMatches((args as Record<string, unknown>)[key], definition.type)) {
        return {
          passed: false,
          reason: `Tool "${tool.name}" argument "${key}" must be type ${definition.type}`,
          severity: 'MEDIUM',
          violationType: 'INVALID_TOOL_ARGUMENTS'
        };
      }
    }

    if (tool.maxArgsSize) {
      const sizeResult = safeSizeOrFail(args);
      if (!sizeResult.passed) return sizeResult;
      if (sizeResult.bytes !== undefined && sizeResult.bytes > tool.maxArgsSize) {
        return {
          passed: false,
          reason: `Tool "${tool.name}" arguments too large: ${sizeResult.bytes} > ${tool.maxArgsSize}`,
          severity: 'MEDIUM',
          violationType: 'ARGS_EGRESS_LIMIT'
        };
      }
    }
  }

  return { passed: true };
}

/**
 * Check if value matches expected argument type
 */
function typeMatches(value: unknown, type: ArgType): boolean {
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  return typeof value === type;
}

/**
 * Safely serialize and return size, or return failure
 */
function safeSizeOrFail(obj: unknown): PolicyValidationResult {
  try {
    const serialized = JSON.stringify(obj);
    return { passed: true, bytes: serialized.length };
  } catch (e) {
    return {
      passed: false,
      reason: `Argument serialization error: ${(e as Error)?.message || 'unknown'}`,
      severity: 'MEDIUM',
      violationType: 'ARG_SERIALIZATION_ERROR'
    };
  }
}
