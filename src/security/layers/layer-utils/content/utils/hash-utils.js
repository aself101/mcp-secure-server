// Hash and cache key utilities

export const hashObject = (obj) => {
    if (obj === null) return 'null';
    if (obj === undefined) return 'undefined';
    if (typeof obj !== 'object') return `${typeof obj}-${String(obj)}`;

    try {
        const str = JSON.stringify(obj, Object.keys(obj).sort());
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash.toString(36);
    } catch (error) {
        // Handle circular references or other JSON.stringify errors
        return `error-${typeof obj}-${Object.keys(obj || {}).length}`;
    }
}

export const getMessageCacheKey = (message) => {
    // Handle null/undefined inputs explicitly
    if (message === null) return 'null-message';
    if (message === undefined) return 'undefined-message';
    if (typeof message !== 'object') return `invalid-${typeof message}`;

    let messageSize = 0;
    try {
        messageSize = JSON.stringify(message).length;
    } catch (error) {
        // Handle circular references - use approximation
        messageSize = Object.keys(message).length * 50; // Rough estimate
    }

    const keyData = {
        method: message.method || 'unknown',
        paramsHash: hashObject(message.params),
        size: messageSize
    };

    try {
        return JSON.stringify(keyData);
    } catch (error) {
        // Fallback for any remaining JSON issues
        return `fallback-${keyData.method}-${keyData.size}`;
    }
}
