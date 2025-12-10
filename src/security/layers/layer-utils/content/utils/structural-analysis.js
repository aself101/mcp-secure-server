// Structural analysis utilities for nested objects

export const calculateNestingLevel = (obj, currentLevel = 0) => {
    if (typeof obj !== 'object' || obj === null || obj === undefined) {
        return currentLevel;
    }

    // Handle arrays
    if (Array.isArray(obj)) {
        let maxLevel = currentLevel;
        for (const item of obj) {
            const level = calculateNestingLevel(item, currentLevel + 1);
            maxLevel = Math.max(maxLevel, level);
        }
        return maxLevel;
    }

    // Handle objects
    let maxLevel = currentLevel;
    try {
        for (const value of Object.values(obj)) {
            const level = calculateNestingLevel(value, currentLevel + 1);
            maxLevel = Math.max(maxLevel, level);
        }
    } catch (error) {
        // Return current level if we can't enumerate the object
        return currentLevel;
    }

    return maxLevel;
}

/**
 * Helper: Calculate parameter count recursively
 */
export const countParameters = (obj) => {
    if (obj === null || obj === undefined || typeof obj !== 'object') {
        return 0;
    }

    let count = 0;
    const stack = [obj];
    const seen = new Set();

    while (stack.length) {
        const cur = stack.pop();
        if (!cur || typeof cur !== 'object' || seen.has(cur)) continue;
        seen.add(cur);

        try {
            count += Object.keys(cur).length;
            for (const v of Object.values(cur)) {
                if (v && typeof v === 'object') stack.push(v);
            }
        } catch (error) {
            // Skip objects that can't be enumerated
            continue;
        }
    }
    return count;
}
