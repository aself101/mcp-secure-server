/**
 * Re-export from split pattern files for backward compatibility
 * Original file split into: patterns/path-traversal.ts, patterns/injection.ts,
 * patterns/network.ts, patterns/overflow-validation.ts, patterns/index.ts
 */

export {
  ATTACK_PATTERNS,
  attackConfigs,
  getPatternsByType,
  getPatternsBySeverity,
  getAllPatterns
} from './patterns/index.js';

export type {
  AttackPattern,
  AttackConfig,
  AttackPatternKey,
  ExtendedAttackPattern
} from './patterns/index.js';
