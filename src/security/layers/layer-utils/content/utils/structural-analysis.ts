/**
 * Structural analysis utilities for nested objects.
 */

export const calculateNestingLevel = (obj: unknown, currentLevel = 0): number => {
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
  } catch {
    // Return current level if we can't enumerate the object
    return currentLevel;
  }

  return maxLevel;
};

/**
 * Helper: Calculate parameter count recursively
 */
export const countParameters = (obj: unknown): number => {
  if (obj === null || obj === undefined || typeof obj !== 'object') {
    return 0;
  }

  let count = 0;
  const stack: unknown[] = [obj];
  const seen = new Set<unknown>();

  while (stack.length) {
    const cur = stack.pop();
    if (!cur || typeof cur !== 'object' || seen.has(cur)) continue;
    seen.add(cur);

    try {
      count += Object.keys(cur as object).length;
      for (const v of Object.values(cur as object)) {
        if (v && typeof v === 'object') stack.push(v);
      }
    } catch {
      // Skip objects that can't be enumerated
      continue;
    }
  }
  return count;
};
