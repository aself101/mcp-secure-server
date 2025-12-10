// Re-export from split pattern files for backward compatibility
// Original file split into: patterns/path-traversal.js, patterns/injection.js,
// patterns/network.js, patterns/overflow-validation.js, patterns/index.js

export {
  ATTACK_PATTERNS,
  attackConfigs,
  getPatternsByType,
  getPatternsBySeverity,
  getAllPatterns
} from './patterns/index.js';
