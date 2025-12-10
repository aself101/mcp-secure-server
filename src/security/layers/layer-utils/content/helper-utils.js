// Re-export from split utility files for backward compatibility
// Original file split into: utils/hash-utils.js, utils/structural-analysis.js, utils/text-decoding.js

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
