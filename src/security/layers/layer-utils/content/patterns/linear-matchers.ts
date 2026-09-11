/**
 * Linear-time matchers for pattern shapes that have no linear regex form.
 *
 * Why this file exists (ship run #1, 2026-09-10): the response-splitting
 * patterns were `A.*A.*B` with A = a CRLF token in three spellings. Every A
 * occurrence is a branch point for two greedy `.*`, and `.test()` retries from
 * every start position, so a slash-free run of `%0d%0a` tokens cost ~n^2.7:
 * 1K chars 9 ms, 4K 300 ms, 8K ~2 s, 20K 27 s — single-threaded, no regex
 * timeout, inside Layer 2's 2 MB input cap. One request froze the server.
 *
 * No regex rewrite fixes that: a tempered dot makes each start position
 * deterministic but the engine still tries every start, which is quadratic,
 * and quadratic at 2 MB is still minutes. The scan below is one pass.
 */
import type { ContentMatcher } from './injection.js';

/** ASCII case-fold compare of `token` (already lowercase) at `pos`. Unicode-safe: never re-encodes. */
function startsWithFold(content: string, pos: number, token: string): boolean {
  if (pos + token.length > content.length) return false;
  for (let i = 0; i < token.length; i++) {
    let c = content.charCodeAt(pos + i);
    if (c >= 65 && c <= 90) c += 32;
    if (c !== token.charCodeAt(i)) return false;
  }
  return true;
}

/**
 * Equivalent to the regex `(?:T1|T2|...)  .*  (?:T1|T2|...)  .*  (?:B1|B2|...)`
 * with the `i` flag (no `s` flag), in O(n). Without `s`, JS `.` excludes
 * exactly four code points — `\n`, `\r`, U+2028, U+2029 — so a bare one of
 * those (not inside a matched token) ends the span. The first draft reset on
 * `\n` only; the equivalence test in linear-matchers.test.js caught it on
 * `\r` within a few hundred random strings. Trust that test, not this prose.
 *
 * Equivalence argument: a match needs tokens at i < j and a terminal at k > j
 * with no line terminator inside (i, j) or (j, k). Taking the EARLIEST token
 * on the current terminator-free span as the first A can never lose a match
 * that a later A would have found, because the later A is itself a valid
 * second A for the earlier one. So a 3-state scan that resets on a bare line
 * terminator and promotes on every token decides the language exactly.
 */
export function createSeparatedSequenceMatcher(
  separators: readonly string[],
  terminals: readonly string[],
  description: string
): ContentMatcher {
  const seps = separators.map((s) => s.toLowerCase());
  const terms = terminals.map((t) => t.toLowerCase());
  return {
    lastIndex: 0,
    source: description,
    test(content: string): boolean {
      let state = 0; // 0: need first separator, 1: need second, 2: need terminal
      let pos = 0;
      const n = content.length;
      while (pos < n) {
        let consumed = 0;
        for (const s of seps) {
          if (startsWithFold(content, pos, s)) { consumed = s.length; break; }
        }
        if (consumed > 0) {
          if (state < 2) state++;
          pos += consumed;
          continue;
        }
        const c = content.charCodeAt(pos);
        if (c === 10 || c === 13 || c === 0x2028 || c === 0x2029) {
          state = 0; // what `.` cannot cross
          pos++;
          continue;
        }
        if (state === 2) {
          for (const t of terms) {
            if (startsWithFold(content, pos, t)) return true;
          }
        }
        pos++;
      }
      return false;
    }
  };
}

/** The three CRLF spellings the response-splitting patterns accept, unchanged. */
export const CRLF_TOKENS = ['%0d%0a', '\\r\\n', '\r\n'] as const;
