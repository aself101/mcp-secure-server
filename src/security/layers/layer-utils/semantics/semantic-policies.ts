/**
 * Policy definitions and enforcement helpers for semantic validation
 * - Tool registry with contracts and constraints
 * - Resource access policies and path validation
 * - Method specifications and chaining rules
 */

import path from 'path';
import { fileURLToPath } from 'url';
import { canonicalizeString } from '../content/canonicalize.js';

import type { Severity, ViolationType } from '../../../../types/index.js';

/** Argument type definitions */
export type ArgType = 'string' | 'number' | 'boolean' | 'array' | 'object';

/** Argument shape definition */
export interface ArgDefinition {
  type: ArgType;
  optional?: boolean;
}

/** Side effect levels for tools */
export type SideEffects = 'none' | 'read' | 'write' | 'network';

/** Tool specification */
export interface ToolSpec {
  name: string;
  sideEffects: SideEffects;
  maxArgsSize?: number;
  maxEgressBytes?: number;
  argsShape?: Record<string, ArgDefinition>;
  quotaPerMinute?: number;
  quotaPerHour?: number;
}

/** Resource policy configuration */
export interface ResourcePolicy {
  allowedSchemes: string[];
  allowedHosts?: string[];
  rootDirs?: string[];
  denyGlobs?: (string | RegExp)[];
  maxPathLength?: number;
  maxUriLength?: number;
  maxReadBytes?: number;
}

/** Method parameter specification */
export interface MethodParamSpec {
  required?: string[];
}

/** Method specification */
export interface MethodSpec {
  shape: Record<string, MethodParamSpec>;
}

/** Chaining rule definition */
export interface ChainingRule {
  /** Method to transition from ('*' for any) */
  from: string;
  /** Method to transition to ('*' for any) */
  to: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  fromTool?: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  toTool?: string;
  /** Side effect of the 'from' tool */
  fromSideEffect?: SideEffects;
  /** Side effect of the 'to' tool */
  toSideEffect?: SideEffects;
  /** Action to take when rule matches. Default: 'allow' */
  action?: 'allow' | 'deny';
  /** Rule identifier for logging */
  id?: string;
}

/** Complete policies configuration */
export interface Policies {
  tools: ToolSpec[];
  resourcePolicy: ResourcePolicy;
  methodSpec: MethodSpec;
  chainingRules: ChainingRule[];
}

/** Normalized policies with processed globs */
export interface NormalizedPolicies {
  resourcePolicy: ResourcePolicy & { denyGlobs: RegExp[] };
  methodSpec: MethodSpec;
  chainingRules: ChainingRule[];
}

/** Validation result */
export interface PolicyValidationResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  bytes?: number;
}

/** Context for path resolution */
export interface PathContext {
  baseDir?: string;
}

/** Tool call parameters */
export interface ToolCallParams {
  name?: string;
  arguments?: Record<string, unknown>;
  args?: Record<string, unknown>;
}

function globToRegExp(glob: string | RegExp): RegExp {
  if (glob instanceof RegExp) return glob;
  let g = String(glob).trim();
  const esc = (s: string) => s.replace(/[.*+^${}()|[\]\\]/g, '\\$&');
  g = g.replace(/\\/g, '/');
  g = esc(g)
    .replace(/\\*\\*/g, '.*')
    .replace(/\\*/g, '[^/]*')
    .replace(/\\?/g, '[^/]');
  return new RegExp('^' + g + '$', 'i');
}

/** Cache for compiled glob patterns */
const globCache = new Map<string, RegExp>();
const MAX_GLOB_CACHE_SIZE = 100;

/**
 * Simple glob matching for tool names
 * Supports: * (any sequence), ? (single char)
 * @param pattern - Glob pattern or undefined (matches everything)
 * @param value - Value to match against
 * @returns true if matches or pattern is undefined
 */
export function simpleGlobMatch(pattern: string | undefined, value: string | undefined): boolean {
  // Undefined pattern matches everything
  if (pattern === undefined) return true;
  // Undefined value only matches if pattern is '*' or undefined
  if (value === undefined) return pattern === '*';
  // Exact '*' matches everything
  if (pattern === '*') return true;

  // Check cache first
  let regex = globCache.get(pattern);
  if (!regex) {
    // Evict oldest entry if cache is full (FIFO eviction)
    if (globCache.size >= MAX_GLOB_CACHE_SIZE) {
      const firstKey = globCache.keys().next().value;
      if (firstKey !== undefined) globCache.delete(firstKey);
    }
    // Convert glob to regex: escape special chars, then convert * and ?
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    const regexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
    regex = new RegExp(`^${regexStr}$`, 'i');
    globCache.set(pattern, regex);
  }

  return regex.test(value);
}

/** Export cache size constant for testing */
export const GLOB_CACHE_MAX_SIZE = MAX_GLOB_CACHE_SIZE;

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

export function validateToolCall(tool: ToolSpec, params: ToolCallParams | null | undefined, _method: string): PolicyValidationResult {
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

function validateFileScheme(uri: string, resourcePolicy: ResourcePolicy, context: PathContext | null | undefined): PolicyValidationResult {
  const absolutePath = toAbsolutePath(uri, context);

  if (resourcePolicy.maxPathLength && absolutePath.length > resourcePolicy.maxPathLength) {
    return {
      passed: false,
      reason: 'Path too long',
      severity: 'MEDIUM',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  if (!isUnderAllowedRoots(absolutePath, resourcePolicy.rootDirs)) {
    return {
      passed: false,
      reason: `Path "${absolutePath}" not under allowed roots`,
      severity: 'HIGH',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  if (matchesDenyGlobs(absolutePath, resourcePolicy.denyGlobs)) {
    return {
      passed: false,
      reason: `Path "${absolutePath}" matches deny list`,
      severity: 'HIGH',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  return { passed: true };
}

function validateHttpScheme(uri: string, resourcePolicy: ResourcePolicy): PolicyValidationResult {
  try {
    const url = new URL(uri);
    if (resourcePolicy.allowedHosts && resourcePolicy.allowedHosts.length) {
      const hostAllowed = resourcePolicy.allowedHosts.some(h => hostEquals(url.host, h));
      if (!hostAllowed) {
        return {
          passed: false,
          reason: `Host "${url.host}" not allowed`,
          severity: 'HIGH',
          violationType: 'RESOURCE_POLICY_VIOLATION'
        };
      }
    }
  } catch {
    return {
      passed: false,
      reason: 'Malformed URI',
      severity: 'MEDIUM',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  return { passed: true };
}

export function validateResourceAccess(uri: string, resourcePolicy: ResourcePolicy, context?: PathContext | null): PolicyValidationResult {
  if (resourcePolicy.maxUriLength && uri.length > resourcePolicy.maxUriLength) {
    return {
      passed: false,
      reason: 'URI too long',
      severity: 'MEDIUM',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  const schemeMatch = uri.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const scheme = schemeMatch?.[1]?.toLowerCase() ?? 'file';

  if (!resourcePolicy.allowedSchemes.includes(scheme)) {
    return {
      passed: false,
      reason: `Scheme "${scheme}" not allowed`,
      severity: 'HIGH',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  if (scheme === 'file') {
    const fileResult = validateFileScheme(uri, resourcePolicy, context);
    if (!fileResult.passed) return fileResult;
  } else if (scheme === 'http' || scheme === 'https') {
    const httpResult = validateHttpScheme(uri, resourcePolicy);
    if (!httpResult.passed) return httpResult;
  }

  if (resourcePolicy.maxReadBytes != null) {
    const estimatedBytes = estimateReadBytes(uri);
    if (estimatedBytes > resourcePolicy.maxReadBytes) {
      return {
        passed: false,
        reason: `Estimated read exceeds policy: ${estimatedBytes} > ${resourcePolicy.maxReadBytes}`,
        severity: 'MEDIUM',
        violationType: 'RESOURCE_EGRESS_LIMIT'
      };
    }
  }

  return { passed: true };
}

export function isUnderAllowedRoots(absolutePath: string, roots: string[] = []): boolean {
  const normalizedPath = path.normalize(absolutePath).replace(/\\/g, '/');
  return roots.some(root => {
    const normalizedRoot = path.normalize(root).replace(/\\/g, '/');
    return normalizedPath === normalizedRoot ||
           normalizedPath.startsWith(normalizedRoot.endsWith('/') ? normalizedRoot : normalizedRoot + '/');
  });
}

export function matchesDenyGlobs(absolutePath: string, globs: (string | RegExp)[] = []): boolean {
  const unixPath = path.normalize(absolutePath).replace(/\\/g, '/');
  for (const glob of globs) {
    const regex = glob instanceof RegExp ? glob : globToRegExp(glob);
    if (regex.test(unixPath)) return true;
  }
  return false;
}

function toAbsolutePath(uriOrPath: string, context: PathContext | null | undefined): string {
  const canonicalized = canonicalizeString(String(uriOrPath));
  const schemeMatch = canonicalized.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);

  if (schemeMatch) {
    if (schemeMatch[1]?.toLowerCase() === 'file') {
      try {
        const url = new URL(canonicalized);
        return path.normalize(url.pathname);
      } catch {
        return path.normalize(canonicalized.replace(/^file:/i, ''));
      }
    }
    return canonicalized;
  }

  const baseDirectory = (context && context.baseDir) || process.cwd();
  return path.normalize(path.resolve(baseDirectory, canonicalized));
}

function typeMatches(value: unknown, type: ArgType): boolean {
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  return typeof value === type;
}

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

function estimateReadBytes(uri: string): number {
  return Math.min(10_000_000, Math.max(0, String(uri).length * 1024));
}

function hostEquals(hostA: string, hostB: string): boolean {
  const normalize = (host: string) => String(host).toLowerCase().replace(/:80$|:443$/, '');
  return normalize(hostA) === normalize(hostB);
}
