/**
 * Resource access validation for semantic policies
 * - File scheme validation with path security
 * - HTTP/HTTPS scheme validation with host allowlists
 * - Path utilities for resource access
 * @module semantic-resource-validation
 */

import path from 'path';
import { canonicalizeString } from '../content/canonicalize.js';
import { globToRegExp } from './glob-utils.js';
import type { ResourcePolicy, PolicyValidationResult, PathContext } from './semantic-policies-types.js';

/**
 * Validate file:// scheme access
 */
export function validateFileScheme(
  uri: string,
  resourcePolicy: ResourcePolicy,
  context: PathContext | null | undefined
): PolicyValidationResult {
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

/**
 * Validate http:// or https:// scheme access
 */
export function validateHttpScheme(uri: string, resourcePolicy: ResourcePolicy): PolicyValidationResult {
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

/**
 * Main resource access validation
 */
export function validateResourceAccess(
  uri: string,
  resourcePolicy: ResourcePolicy,
  context?: PathContext | null
): PolicyValidationResult {
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

/**
 * Check if path is under allowed root directories
 */
export function isUnderAllowedRoots(absolutePath: string, roots: string[] = []): boolean {
  const normalizedPath = path.normalize(absolutePath).replace(/\\/g, '/');
  return roots.some(root => {
    const normalizedRoot = path.normalize(root).replace(/\\/g, '/');
    return normalizedPath === normalizedRoot ||
           normalizedPath.startsWith(normalizedRoot.endsWith('/') ? normalizedRoot : normalizedRoot + '/');
  });
}

/**
 * Check if path matches any deny glob patterns
 */
export function matchesDenyGlobs(absolutePath: string, globs: (string | RegExp)[] = []): boolean {
  const unixPath = path.normalize(absolutePath).replace(/\\/g, '/');
  for (const glob of globs) {
    const regex = glob instanceof RegExp ? glob : globToRegExp(glob);
    if (regex.test(unixPath)) return true;
  }
  return false;
}

/**
 * Convert URI or path to absolute path
 */
export function toAbsolutePath(uriOrPath: string, context: PathContext | null | undefined): string {
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

/**
 * Estimate bytes that would be read from a URI
 */
export function estimateReadBytes(uri: string): number {
  return Math.min(10_000_000, Math.max(0, String(uri).length * 1024));
}

/**
 * Compare two hosts for equality (normalizes ports)
 */
export function hostEquals(hostA: string, hostB: string): boolean {
  const normalize = (host: string) => String(host).toLowerCase().replace(/:80$|:443$/, '');
  return normalize(hostA) === normalize(hostB);
}
