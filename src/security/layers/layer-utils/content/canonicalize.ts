/**
 * Canonicalization utilities
 * Single source of truth for decoding/normalization across layers.
 */

import {
  decodeUnicodeEscapes,
  decodeEntities,
  normalizeUnicode,
  removePostDecodingZeroWidth
} from './unicode.js';

import {
  normalizeWhitespace,
  decodeSingleUrlEncoding,
  decodeURIComponentSafe
} from './helper-utils.js';

/**
 * Canonicalize a raw string (already JSON-stringified, or plain input).
 * Order matters. Keep this the *only* place that defines the sequence.
 */
export function canonicalizeString(input: unknown): string {
  let s = String(input);

  // 1) Escape sequences first (\uXXXX, \xNN)
  s = decodeUnicodeEscapes(s);

  // 2) Unicode normalization (NFKC + fullwidth/homoglyph handling, zero-width strip)
  s = normalizeUnicode(s);

  // 3) HTML entities (&lt; &#x3c; etc.)
  s = decodeEntities(s);

  // 4) URL decoding with guarded multi-pass
  s = decodeUrlsCanonical(s);

  // 5) Post-URL Unicode normalization (handles fullwidth chars revealed by URL decoding)
  s = normalizeUnicode(s);

  // 6) Whitespace unification
  s = normalizeWhitespace(s);

  // 7) Final zero-width sweep
  s = removePostDecodingZeroWidth(s);

  return s;
}

/**
 * Convenience: canonicalize an MCP JSON-RPC message by stringifying it first.
 */
export function canonicalizeFromMessage(message: unknown): string {
  try {
    return canonicalizeString(JSON.stringify(message));
  } catch {
    return canonicalizeString(String(message));
  }
}

/**
 * Check if a field path should be relaxed based on the relaxedFields config.
 * Supports both exact matches and ancestor inheritance.
 *
 * Examples:
 * - fieldPath="recommendations.0.description", relaxedFields=["recommendations"] → true
 * - fieldPath="params.arguments.title", relaxedFields=["title"] → true
 * - fieldPath="params.arguments.data", relaxedFields=["title"] → false
 *
 * @param fieldPath - Dot-notation path like "params.arguments.recommendations.0.description"
 * @param relaxedFields - Array of relaxed field names from tool policy
 * @returns true if this field or any ancestor is relaxed
 */
export function isFieldPathRelaxed(fieldPath: string, relaxedFields: string[]): boolean {
  if (!relaxedFields.length) return false;

  const parts = fieldPath.split('.');

  // Check progressively shorter suffixes (ancestor inheritance)
  // e.g., "params.arguments.recommendations.0.description" checks:
  //   - "params.arguments.recommendations.0.description"
  //   - "arguments.recommendations.0.description"
  //   - "recommendations.0.description"
  //   - "0.description"
  //   - "description"
  for (let i = 0; i < parts.length; i++) {
    const segment = parts.slice(i).join('.');
    if (relaxedFields.includes(segment)) return true;
  }

  // Also check each individual path component (handles array-nested fields)
  // e.g., if "recommendations" is relaxed, "recommendations.0.description" should be relaxed
  for (const part of parts) {
    // Skip numeric indices (array positions)
    if (/^\d+$/.test(part)) continue;
    if (relaxedFields.includes(part)) return true;
  }

  return false;
}

/**
 * Recursively extract content from message, replacing relaxed fields with placeholder.
 * This preserves structure for logging while excluding relaxed content from pattern detection.
 *
 * @param obj - Object to process
 * @param relaxedFields - Array of relaxed field names
 * @param path - Current path in dot notation (used internally for recursion)
 * @returns Object with relaxed fields replaced by "[RELAXED]" placeholder
 */
function extractNonRelaxedContent(
  obj: unknown,
  relaxedFields: string[],
  path = ''
): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== 'object') return obj;

  if (Array.isArray(obj)) {
    return obj.map((item, i) => {
      const itemPath = path ? `${path}.${i}` : String(i);
      return extractNonRelaxedContent(item, relaxedFields, itemPath);
    });
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const fieldPath = path ? `${path}.${key}` : key;

    if (isFieldPathRelaxed(fieldPath, relaxedFields)) {
      // Replace with placeholder to preserve structure but exclude from pattern detection
      result[key] = '[RELAXED]';
      continue;
    }

    result[key] = extractNonRelaxedContent(value, relaxedFields, fieldPath);
  }
  return result;
}

/**
 * Canonicalize a message with relaxed field exclusion.
 * Fields listed in relaxedFields (or their children) are replaced with "[RELAXED]"
 * before pattern detection runs.
 *
 * @param message - MCP message to canonicalize
 * @param relaxedFields - Array of field names to exclude from pattern detection
 * @returns Canonicalized string with relaxed fields excluded
 */
export function canonicalizeWithRelaxedFields(
  message: unknown,
  relaxedFields: string[]
): string {
  try {
    const filtered = relaxedFields.length > 0
      ? extractNonRelaxedContent(message, relaxedFields)
      : message;
    return canonicalizeString(JSON.stringify(filtered));
  } catch {
    return canonicalizeString(String(message));
  }
}

/** Maximum input size for URL decoding to prevent memory exhaustion (1MB) */
const MAX_URL_DECODE_INPUT_SIZE = 1024 * 1024;

/**
 * URL decoding that is safe for multi-encoded inputs.
 * - Fixes %25xx -> %xx (double-encoded percent)
 * - Performs one targeted single-encoding replace before strict decode
 * - Iterates up to maxIterations with progress checks
 * - Never throws (falls back to previous on error)
 * - Rejects inputs exceeding MAX_URL_DECODE_INPUT_SIZE to prevent memory exhaustion
 */
export function decodeUrlsCanonical(input: string, maxIterations = 8): string {
  const str = String(input);

  // Guard against memory exhaustion from large inputs
  if (str.length > MAX_URL_DECODE_INPUT_SIZE) {
    return str;
  }

  let decoded = str;
  let prev: string | null = null;
  let iterations = 0;

  while (decoded !== prev && iterations < maxIterations) {
    prev = decoded;

    // Normalize obvious double/triple encodings of percent
    if (decoded.includes('%25')) {
      decoded = decoded.replace(/%25([0-9A-F]{2})/gi, '%$1');
    }
    if (decoded.includes('%252')) {
      decoded = decoded.replace(/%252([0-9A-F])/gi, '%2$1');
    }
    if (decoded.includes('%2525')) {
      decoded = decoded.replace(/%2525([0-9A-F])/gi, '%25$1');
    }

    // One pass of targeted replacements for high-risk tokens
    const beforeSingle = decoded;
    decoded = decodeSingleUrlEncoding(decoded);

    // If nothing changed, try a strict percent-decoding step.
    // Use safe variant that returns input on failure.
    const step = decodeURIComponentSafe(decoded);

    // Stop if no improvement
    if (step === decoded && decoded === beforeSingle) break;
    decoded = step;
    iterations += 1;
  }

  return decoded;
}
