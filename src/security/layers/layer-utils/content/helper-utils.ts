/**
 * Re-export from split utility files for backward compatibility.
 * Original file split into: utils/hash-utils.ts, utils/structural-analysis.ts, utils/text-decoding.ts
 */

export {
  hashObject,
  getMessageCacheKey,
  calculateNestingLevel,
  countParameters,
  normalizeWhitespace,
  decodeSingleUrlEncoding,
  decodeURIComponentStrict,
  decodeURIComponentSafe
} from './utils/index.js';
