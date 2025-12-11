/**
 * Unicode normalization and decoding utilities for security validation.
 */

/** Character mapping type */
type CharacterMap = Record<string, string>;

/** CJK code point mapping type */
type CodePointMap = Record<number, number>;

export function normalizeUnicode(input: string): string {
  const fullwidthMap: CharacterMap = {
    // Basic punctuation and operators
    '＜': '<', '＞': '>', '（': '(', '）': ')',
    '／': '/', '？': '?', '：': ':', '；': ';',
    '＆': '&', '＝': '=', '＋': '+', '－': '-',
    '＊': '*', '％': '%', '＃': '#', '＠': '@',
    '！': '!', '｜': '|', '＼': '\\', '｀': '`',
    '～': '~', '＾': '^', '［': '[', '］': ']',
    '｛': '{', '｝': '}', '｢': '"', '｣': '"',

    // Fullwidth letters and numbers
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
    'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J',
    'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O',
    'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R', 'Ｓ': 'S', 'Ｔ': 'T',
    'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',

    // lowercase fullwidth letters
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
    'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
    'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
    'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
    'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z'
  };

  let normalized = input.normalize('NFKC');

  const extendedMappings: CharacterMap = {
    '＋': '+', '－': '-', '×': '*', '÷': '/',
    '＝': '=', '＜': '<', '＞': '>',
    '≤': '<=', '≥': '>=', '≠': '!=',
    // Mathematical script variants
    '𝒽': 'h', '𝓉': 't', '𝓂': 'm', '𝓁': 'l',
    // Enclosed alphanumerics that might be used for evasion
    '⒜': 'a', '⒝': 'b', '⒞': 'c', '⒟': 'd', '⒠': 'e',
    // Superscript and subscript numbers
    '⁰': '0', '¹': '1', '²': '2', '³': '3', '⁴': '4',
    '₀': '0', '₁': '1', '₂': '2', '₃': '3', '₄': '4'
  };

  const homoglyphMap: CharacterMap = {
    // Cyrillic → Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's', 'т': 't',

    // Greek → Latin
    'α': 'a', 'β': 'b', 'γ': 'y', 'δ': 'd', 'ε': 'e',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y', 'χ': 'x',

    // Mathematical → Latin
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e',
    '𝑎': 'a', '𝑏': 'b', '𝑐': 'c', '𝑑': 'd', '𝑒': 'e'
  };

  const allMappings: CharacterMap = {
    ...fullwidthMap,
    ...extendedMappings,
    ...homoglyphMap
  };

  for (const [source, target] of Object.entries(allMappings)) {
    normalized = normalized.replaceAll(source, target);
  }

  const zeroWidthChars = [
    '\u200B', // Zero width space
    '\u200C', // Zero width non-joiner
    '\u200D', // Zero width joiner
    '\u2060', // Word joiner
    '\uFEFF', // Zero width no-break space (BOM)
    '\u180E', // Mongolian vowel separator
  ];

  for (const char of zeroWidthChars) {
    normalized = normalized.replaceAll(char, '');
  }

  return normalized;
}

export function decodeUnicodeEscapes(input: string): string {
  // Handle double-backslash sequences first (from JSON escaping)
  let decoded = input.replace(/\\\\x([0-9A-Fa-f]{2})/g, (match, hex: string) => {
    try {
      const codePoint = parseInt(hex, 16);
      if (codePoint < 0 || codePoint > 0xFFFF) {
        return match;
      }
      return String.fromCharCode(codePoint);
    } catch {
      return match;
    }
  });

  // Then handle single-backslash sequences (normal case)
  decoded = decoded.replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex: string) => {
    try {
      const codePoint = parseInt(hex, 16);
      if (codePoint < 0 || codePoint > 0xFFFF) {
        return match;
      }
      return String.fromCharCode(codePoint);
    } catch {
      return match;
    }
  });

  // Handle double-backslash unicode sequences
  decoded = decoded.replace(/\\\\u([0-9A-Fa-f]{4})/g, (match, hex: string) => {
    try {
      const codePoint = parseInt(hex, 16);
      if (codePoint < 0 || codePoint > 0xFFFF) {
        return match;
      }
      return String.fromCharCode(codePoint);
    } catch {
      return match;
    }
  });

  // Then handle single-backslash unicode sequences (normal case)
  decoded = decoded.replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex: string) => {
    try {
      const codePoint = parseInt(hex, 16);
      if (codePoint < 0 || codePoint > 0xFFFF) {
        return match;
      }
      return String.fromCharCode(codePoint);
    } catch {
      return match;
    }
  });

  // Handle extended hex sequences with braces (double-backslash first)
  decoded = decoded.replace(/\\\\x\{([0-9A-Fa-f]{1,6})\}/g, (match, hex: string) => {
    try {
      const cp = parseInt(hex, 16);
      if (cp <= 0x10FFFF) {
        return cp <= 0xFFFF ? String.fromCharCode(cp) : String.fromCodePoint(cp);
      }
      return match;
    } catch {
      return match;
    }
  });

  // Handle extended hex sequences with braces (single-backslash)
  decoded = decoded.replace(/\\x\{([0-9A-Fa-f]{1,6})\}/g, (match, hex: string) => {
    try {
      const cp = parseInt(hex, 16);
      if (cp <= 0x10FFFF) {
        return cp <= 0xFFFF ? String.fromCharCode(cp) : String.fromCodePoint(cp);
      }
      return match;
    } catch {
      return match;
    }
  });

  return decoded;
}

export function removePostDecodingZeroWidth(input: string): string {
  return input.replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '');
}

/**
 * Comprehensive HTML entity decoding with extended Unicode support
 */
export const decodeEntities = (input: string): string => {
  let decoded = input;

  decoded = decoded.replace(/&#x0*([0-9A-Fa-f]+);?/gi, (match, hex: string) => {
    try {
      const codePoint = parseInt(hex, 16);
      if (codePoint < 0 || codePoint > 0x10FFFF) return match;
      if (codePoint >= 0xFF00 && codePoint <= 0xFFEF) {
        const halfwidth = codePoint - 0xFEE0;
        return String.fromCharCode(halfwidth);
      }

      if (codePoint >= 0xFE30 && codePoint <= 0xFE4F) {
        const normalized = normalizeCJKCompatibility(codePoint);
        if (normalized !== codePoint) {
          return String.fromCharCode(normalized);
        }
      }

      return String.fromCharCode(codePoint);

    } catch {
      return match;
    }
  });

  decoded = decoded.replace(/&#0*(\d+);?/g, (match, dec: string) => {
    try {
      const codePoint = parseInt(dec, 10);

      if (codePoint < 0 || codePoint > 0x10FFFF) return match;
      if (codePoint >= 0xFF00 && codePoint <= 0xFFEF) {
        const halfwidth = codePoint - 0xFEE0;
        return String.fromCharCode(halfwidth);
      }

      return String.fromCharCode(codePoint);

    } catch {
      return match;
    }
  });

  const entities: CharacterMap = {
    '&lt;': '<', '&LT;': '<',
    '&gt;': '>', '&GT;': '>',
    '&amp;': '&', '&AMP;': '&',
    '&quot;': '"', '&QUOT;': '"',
    '&apos;': "'", '&APOS;': "'",
    '&#x27;': "'", '&#X27;': "'",
    '&#x2F;': '/', '&#X2F;': '/',
    '&nbsp;': ' ', '&NBSP;': ' ',
    '&copy;': '©', '&COPY;': '©',
    '&reg;': '®', '&REG;': '®',
    '&trade;': '™', '&TRADE;': '™',
    '&euro;': '€', '&EURO;': '€',
    '&pound;': '£', '&POUND;': '£',
    '&yen;': '¥', '&YEN;': '¥'
  };

  for (const [entity, char] of Object.entries(entities)) {
    decoded = decoded.replaceAll(entity, char);
  }

  return decoded;
};

/**
 * CJK Compatibility Forms normalization
 */
export const normalizeCJKCompatibility = (codePoint: number): number => {
  const cjkMappings: CodePointMap = {
    0xFE30: 0x2025, // Two dots
    0xFE31: 0x2014, // Em dash
    0xFE32: 0x2013, // En dash
    0xFE33: 0x005F, // Low line (underscore)
    0xFE34: 0x005F, // Wavy low line -> underscore
    0xFE35: 0x0028, // Left parenthesis
    0xFE36: 0x0029, // Right parenthesis
    0xFE37: 0x007B, // Left curly bracket
    0xFE38: 0x007D, // Right curly bracket
  };

  return cjkMappings[codePoint] ?? codePoint;
};
