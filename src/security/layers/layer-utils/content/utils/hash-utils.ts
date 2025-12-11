/**
 * Hash and cache key utilities for content validation.
 */

/** Message structure for cache key generation */
interface MessageLike {
  method?: string;
  params?: unknown;
  [key: string]: unknown;
}

export const hashObject = (obj: unknown): string => {
  if (obj === null) return 'null';
  if (obj === undefined) return 'undefined';
  if (typeof obj !== 'object') return `${typeof obj}-${String(obj)}`;

  try {
    const str = JSON.stringify(obj, Object.keys(obj as object).sort());
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(36);
  } catch {
    // Handle circular references or other JSON.stringify errors
    return `error-${typeof obj}-${Object.keys((obj as object) || {}).length}`;
  }
};

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
