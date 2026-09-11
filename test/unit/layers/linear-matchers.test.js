import { describe, it, expect } from 'vitest';
import { createSeparatedSequenceMatcher, CRLF_TOKENS } from '../../../src/security/layers/layer-utils/content/patterns/linear-matchers.js';
import { ATTACK_PATTERNS } from '../../../src/security/layers/layer-utils/content/patterns/index.js';

// The regexes these matchers replaced (ship run #1, 2026-09-10). Kept here as
// the oracle: on inputs short enough that their backtracking is affordable,
// the replacement must agree with them on every string.
const OLD = {
  xss: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*<script/i,
  html: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*<html/i,
  js: /(?:%0d%0a|\\r\\n|\r\n).*(?:%0d%0a|\\r\\n|\r\n).*javascript:/i,
  dots: /\.{4,}[\/\\]{3,}/
};

const byName = (name) => {
  for (const cat of Object.values(ATTACK_PATTERNS.crlf)) for (const p of cat) if (p.name === name) return p.pattern;
  for (const p of ATTACK_PATTERNS.pathTraversal.patterns) if (p.name === name) return p.pattern;
  throw new Error(name);
};
const test = (pattern, s) => { pattern.lastIndex = 0; return pattern.test(s); };

// Deterministic PRNG so a failure is reproducible from the seed.
function rng(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
function randomString(rand, alphabet, maxTokens) {
  const n = 1 + Math.floor(rand() * maxTokens);
  let out = '';
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

describe('linear-matchers: equivalence with the regexes they replaced', () => {
  const CRLF_ALPHABET = ['%0d%0a', '%0D%0A', '\\r\\n', '\r\n', '\r', '\n', '\u2028', 'a', ' ', '<script', '<SCRIPT', '<html', 'javascript:', 'JavaScript:', '<', 'script', '%0d', '%0a'];

  it.each([
    ['Response Splitting XSS', OLD.xss],
    ['Response Splitting HTML', OLD.html],
    ['Response Splitting JavaScript', OLD.js]
  ])('%s agrees with the old regex on 3000 random strings', (name, oldRe) => {
    const matcher = byName(name);
    const rand = rng(name.length * 7919);
    let positives = 0;
    for (let i = 0; i < 3000; i++) {
      const s = randomString(rand, CRLF_ALPHABET, 24); // short enough for the old regex to finish
      const expected = oldRe.test(s);
      if (expected) positives++;
      expect(test(matcher, s), `input ${JSON.stringify(s)}`).toBe(expected);
    }
    // A corpus the oracle never matches would prove nothing.
    expect(positives).toBeGreaterThan(100);
  });

  it('Extended Dot Traversal agrees with the old regex on 3000 random strings', () => {
    const p = byName('Extended Dot Traversal');
    const rand = rng(4242);
    let positives = 0;
    for (let i = 0; i < 3000; i++) {
      const s = randomString(rand, ['....', '...', '.', '///', '//', '/', '\\\\\\', '\\', 'a', '\n'], 12);
      const expected = OLD.dots.test(s);
      if (expected) positives++;
      expect(test(p, s), `input ${JSON.stringify(s)}`).toBe(expected);
    }
    expect(positives).toBeGreaterThan(100);
  });

  it('hand-picked boundary cases', () => {
    const xss = byName('Response Splitting XSS');
    expect(test(xss, '%0d%0aX-Injected: 1%0d%0a<script>alert(1)</script>')).toBe(true);
    expect(test(xss, 'a\r\nb\r\n<SCRIPT>')).toBe(true);
    expect(test(xss, '\\r\\n\\r\\n<script')).toBe(true);
    // A bare newline between the tokens breaks the chain, as `.` did.
    expect(test(xss, '%0d%0aX\n%0d%0a<script')).toBe(false);
    // Only one separator: no split.
    expect(test(xss, '%0d%0a<script')).toBe(false);
    // Terminal before the second separator does not count.
    expect(test(xss, '%0d%0a<script%0d%0a')).toBe(false);
  });
});

describe('linear-matchers: cost is linear (the ReDoS regression)', () => {
  const time = (pattern, s) => { const t = performance.now(); test(pattern, s); return performance.now() - t; };

  it('response-splitting matchers stay flat as the pathological input doubles', () => {
    const xss = byName('Response Splitting XSS');
    // The exact shape that cost ~2 s at 8K with the old regex: a run of CRLF
    // tokens with no terminal.
    const at = (n) => '%0d%0a'.repeat(Math.ceil(n / 6)).slice(0, n);
    const t8k = time(xss, at(8_000));
    const t256k = time(xss, at(256_000));
    expect(t256k).toBeLessThan(200);
    // 32x more input, well under 32x... the point is it is not super-linear.
    expect(t256k / Math.max(t8k, 0.05)).toBeLessThan(200);
  });

  it('Extended Dot Traversal stays flat on a long dot run', () => {
    const p = byName('Extended Dot Traversal');
    expect(time(p, '.'.repeat(500_000))).toBeLessThan(200);
  });

  it('control: the OLD response-splitting regex is super-linear on the same input', () => {
    // Proves the timing assertions above can fail: 2K -> 4K should cost ~5x, not ~2x.
    // (8K is ~2 s on the old regex; kept small so the suite does not pay for the proof.)
    const at = (n) => '%0d%0a'.repeat(Math.ceil(n / 6)).slice(0, n);
    const t2k = time(OLD.xss, at(2_000));
    const t4k = time(OLD.xss, at(4_000));
    expect(t4k / Math.max(t2k, 1)).toBeGreaterThan(3);
  });

  it('matchers implement the RegExp calling convention the loops use', () => {
    const m = createSeparatedSequenceMatcher(CRLF_TOKENS, ['<script'], 'x');
    expect(typeof m.test).toBe('function');
    expect(m.lastIndex).toBe(0);
    m.lastIndex = 0;
    expect(m.source).toBe('x');
  });
});
