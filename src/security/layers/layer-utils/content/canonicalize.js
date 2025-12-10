// utils/canonicalize.js
// Single source of truth for decoding/normalization across layers.
// ES modules only.

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
export function canonicalizeString(input) {
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
export function canonicalizeFromMessage(message) {
  try {
    return canonicalizeString(JSON.stringify(message));
  } catch {
    return canonicalizeString(String(message));
  }
}

/**
 * URL decoding that is safe for multi-encoded inputs.
 * - Fixes %25xx -> %xx (double-encoded percent)
 * - Performs one targeted single-encoding replace before strict decode
 * - Iterates up to maxIterations with progress checks
 * - Never throws (falls back to previous on error)
 */
export function decodeUrlsCanonical(input, maxIterations = 8) {
  let decoded = String(input);
  let prev = null;
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
