// src/security/layers/layer-utils/semantics/semantic-policies.js
// Policy definitions and enforcement helpers for semantic validation
// - Tool registry with contracts and constraints
// - Resource access policies and path validation
// - Method specifications and chaining rules

import path from 'path';
import { fileURLToPath } from 'url';
import { canonicalizeString } from '../content/canonicalize.js';

/**
 * @typedef {Object} ToolSpec
 * @property {string} name
 * @property {'none'|'read'|'write'|'network'} sideEffects
 * @property {number} [maxArgsSize]
 * @property {number} [maxEgressBytes]
 * @property {Record<string, { type: 'string'|'number'|'boolean'|'array'|'object', optional?: boolean }>} [argsShape]
 * @property {number} [quotaPerMinute]
 * @property {number} [quotaPerHour]
 */

/**
 * @typedef {Object} ResourcePolicy
 * @property {string[]} allowedSchemes
 * @property {string[]} [allowedHosts]
 * @property {string[]} [rootDirs]
 * @property {(string|RegExp)[]} [denyGlobs]
 * @property {number} [maxPathLength]
 * @property {number} [maxUriLength]
 * @property {number} [maxReadBytes]
 */

/**
 * @typedef {Object} MethodSpec
 * @property {Record<string, {required?: string[], optional?: string[]}>} shape
 */

/**
 * @typedef {Object} ChainingRule
 * @property {string} from
 * @property {string} to
 */

function globToRegExp(glob) {
  let g = String(glob).trim();
  const esc = (s) => s.replace(/[.*+^${}()|[\]\\]/g, '\\$&');
  g = g.replace(/\\/g, '/');
  g = esc(g)
    .replace(/\\*\\*/g, '.*')
    .replace(/\\*/g, '[^/]*')
    .replace(/\\?/g, '[^/]');
  return new RegExp('^' + g + '$', 'i');
}

export function getDefaultPolicies() {
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
        'initialize': { required: [], optional: [] },
        'ping': { required: [], optional: [] },
        'tools/list': { required: [], optional: [] },
        'tools/call': { required: ['name'], optional: ['arguments', 'args'] },
        'resources/list': { required: [], optional: [] },
        'resources/read': { required: ['uri'], optional: [] },
        'prompts/list': { required: [], optional: [] },
        'prompts/get': { required: ['name'], optional: [] },
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

export function normalizePolicies({ resourcePolicy, methodSpec, chainingRules }) {
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

export function validateToolCall(tool, params, method) {
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
      if (key in args && !typeMatches(args[key], definition.type)) {
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
      if (sizeResult.bytes > tool.maxArgsSize) {
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

function validateFileScheme(uri, resourcePolicy, context) {
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

function validateHttpScheme(uri, resourcePolicy) {
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

export function validateResourceAccess(uri, resourcePolicy, context) {
  if (resourcePolicy.maxUriLength && uri.length > resourcePolicy.maxUriLength) {
    return {
      passed: false,
      reason: 'URI too long',
      severity: 'MEDIUM',
      violationType: 'RESOURCE_POLICY_VIOLATION'
    };
  }

  const schemeMatch = uri.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'file';

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

export function isUnderAllowedRoots(absolutePath, roots = []) {
  const normalizedPath = path.normalize(absolutePath).replace(/\\/g, '/');
  return roots.some(root => {
    const normalizedRoot = path.normalize(root).replace(/\\/g, '/');
    return normalizedPath === normalizedRoot || 
           normalizedPath.startsWith(normalizedRoot.endsWith('/') ? normalizedRoot : normalizedRoot + '/');
  });
}

export function matchesDenyGlobs(absolutePath, globs = []) {
  const unixPath = path.normalize(absolutePath).replace(/\\/g, '/');
  for (const glob of globs) {
    const regex = glob instanceof RegExp ? glob : globToRegExp(glob);
    if (regex.test(unixPath)) return true;
  }
  return false;
}

function toAbsolutePath(uriOrPath, context) {
  const canonicalized = canonicalizeString(String(uriOrPath));
  const schemeMatch = canonicalized.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  
  if (schemeMatch) {
    if (schemeMatch[1].toLowerCase() === 'file') {
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

function typeMatches(value, type) {
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value && typeof value === 'object' && !Array.isArray(value);
  return typeof value === type;
}

function safeSizeOrFail(obj) {
  try {
    const serialized = JSON.stringify(obj);
    return { passed: true, bytes: serialized.length };
  } catch (e) {
    return {
      passed: false,
      reason: `Argument serialization error: ${e?.message || 'unknown'}`,
      severity: 'MEDIUM',
      violationType: 'ARG_SERIALIZATION_ERROR'
    };
  }
}

function estimateReadBytes(uri) {
  return Math.min(10_000_000, Math.max(0, String(uri).length * 1024));
}

function hostEquals(hostA, hostB) {
  const normalize = (host) => String(host).toLowerCase().replace(/:80$|:443$/, '');
  return normalize(hostA) === normalize(hostB);
}