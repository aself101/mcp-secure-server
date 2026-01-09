/**
 * Glob pattern matching utilities for security policy enforcement.
 * Provides efficient pattern matching with caching for tool names and paths.
 */

/** Cache for compiled glob patterns */
const globCache = new Map<string, RegExp>();
const MAX_GLOB_CACHE_SIZE = 100;

/**
 * Convert a glob pattern to a regular expression for path matching.
 * Supports: ** (any path), * (single segment), ? (single char)
 *
 * @param glob - Glob pattern string or RegExp
 * @returns Compiled RegExp for matching
 */
export function globToRegExp(glob: string | RegExp): RegExp {
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

/**
 * Simple glob matching for tool names.
 * Supports: * (any sequence), ? (single char)
 *
 * Uses LRU-style cache eviction when cache exceeds MAX_GLOB_CACHE_SIZE.
 *
 * @param pattern - Glob pattern or undefined (matches everything)
 * @param value - Value to match against
 * @returns true if matches or pattern is undefined
 *
 * @example
 * simpleGlobMatch('debug-*', 'debug-calculator') // true
 * simpleGlobMatch('*-reader', 'file-reader') // true
 * simpleGlobMatch('tool?', 'tool1') // true
 * simpleGlobMatch(undefined, 'anything') // true
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

/**
 * Clear the glob cache. Useful for testing.
 */
export function clearGlobCache(): void {
  globCache.clear();
}

/**
 * Get current glob cache size. Useful for testing.
 */
export function getGlobCacheSize(): number {
  return globCache.size;
}
