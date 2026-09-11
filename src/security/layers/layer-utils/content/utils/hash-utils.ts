/**
 * Hash and cache key utilities for content validation.
 *
 * The key produced here selects a cached CANONICALIZED CONTENT string in Layer 2
 * (`layer2-content.ts` `processedContentCache`), and that string is what the
 * injection/traversal patterns are run against. A collision therefore does not
 * cost performance — it hands Layer 2 a different message's text to scan. The
 * key must be injective on content, which rules out both defects the previous
 * implementation carried (found 2026-09-10, ship run #1):
 *
 *  1. `JSON.stringify(obj, Object.keys(obj).sort())` — a replacer ARRAY is a
 *     whitelist applied at EVERY depth, not a sort. `params.arguments.path`
 *     was dropped because `path` is not a top-level key, so every
 *     `{name, arguments:{...}}` with the same tool name hashed identically.
 *  2. A 32-bit `hash * 31 + c` string hash — collisions are findable in ~65K
 *     tries even with the content included.
 *
 * Verified consequence: a path-traversal payload blocked cold was ALLOWED after
 * one same-length benign call to the same tool warmed the cache.
 */
import { createHash } from 'node:crypto';

/**
 * Deterministic JSON with object keys sorted at every depth and array order
 * preserved. Throws on circular references (the caller falls back).
 * Non-JSON values (undefined, functions, symbols) serialize as JSON.stringify
 * would inside objects/arrays — dropped or `null` respectively — so the
 * canonical form matches what the validators see after their own stringify.
 */
export const canonicalJson = (value: unknown, seen: WeakSet<object> = new WeakSet()): string => {
  if (value === null || typeof value !== 'object') {
    const s = JSON.stringify(value);
    return s === undefined ? 'null' : s;
  }
  if (seen.has(value)) throw new TypeError('Converting circular structure to JSON');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((v) => canonicalJson(v, seen)).join(',')}]`;
    }
    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of Object.keys(obj).sort()) {
      const v = obj[k];
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') continue;
      parts.push(`${JSON.stringify(k)}:${canonicalJson(v, seen)}`);
    }
    return `{${parts.join(',')}}`;
  } finally {
    seen.delete(value);
  }
};

/** Message structure for cache key generation */
interface MessageLike {
  method?: string;
  params?: unknown;
  [key: string]: unknown;
}

/**
 * Content-injective hash of any value for cache key generation: SHA-256 over
 * the canonical JSON (keys sorted at every depth). Primitives keep their
 * legible `type-value` form; circular structures fall back to a non-content
 * marker that Layer 2 will never match against real content.
 */
export const hashObject = (obj: unknown): string => {
  if (obj === null) return 'null';
  if (obj === undefined) return 'undefined';
  if (typeof obj !== 'object') return `${typeof obj}-${String(obj)}`;

  try {
    return createHash('sha256').update(canonicalJson(obj)).digest('hex');
  } catch {
    // Handle circular references or other JSON.stringify errors
    return `error-${typeof obj}-${Object.keys((obj as object) || {}).length}`;
  }
};

/** Generates a cache key from an MCP message based on method, params hash, and size */
export const getMessageCacheKey = (message: unknown): string => {
  // Handle null/undefined inputs explicitly
  if (message === null) return 'null-message';
  if (message === undefined) return 'undefined-message';
  if (typeof message !== 'object') return `invalid-${typeof message}`;

  const msg = message as MessageLike;
  let messageSize = 0;
  try {
    messageSize = JSON.stringify(message).length;
  } catch {
    // Handle circular references - use approximation
    messageSize = Object.keys(msg).length * 50; // Rough estimate
  }

  const keyData = {
    method: msg.method || 'unknown',
    paramsHash: hashObject(msg.params),
    size: messageSize
  };

  try {
    return JSON.stringify(keyData);
  } catch {
    // Fallback for any remaining JSON issues
    return `fallback-${keyData.method}-${keyData.size}`;
  }
};
