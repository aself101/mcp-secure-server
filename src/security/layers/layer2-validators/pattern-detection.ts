/**
 * Pattern detection functions for Layer 2
 */

import type { Severity, ViolationType } from '../../../types/index.js';
import type { AttackPattern } from '../layer-utils/content/patterns/index.js';
import { ATTACK_PATTERNS, attackConfigs } from '../layer-utils/content/dangerous-patterns.js';

/** Validation result from pattern detection */
export interface PatternDetectionResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  confidence?: number;
}

/**
 * Consolidated malicious pattern detection for decoded content
 */
export function containsMaliciousPatterns(content: string): boolean {
  const patternGroups: AttackPattern[] = [
    ...ATTACK_PATTERNS.xss.basicVectors,
    ...ATTACK_PATTERNS.xss.eventHandlers,
    ...ATTACK_PATTERNS.xss.jsExecution,
    ...ATTACK_PATTERNS.xss.extraAttributes,
    ...ATTACK_PATTERNS.css.expressions,
    ...ATTACK_PATTERNS.script.pythonInjection,
    ...ATTACK_PATTERNS.script.nodeInjection,
    ...ATTACK_PATTERNS.command.basicInjection,
    ...ATTACK_PATTERNS.command.executionWrappers
  ];

  return patternGroups.some(({ pattern }) => pattern.test(content));
}

/**
 * Generic pattern detection method
 */
export function detectPatternCategories(
  content: string,
  attackType: string,
  patternCategories: readonly AttackPattern[][],
  violationType: ViolationType,
  confidence = 0.85
): PatternDetectionResult {
  for (const category of patternCategories) {
    for (const { pattern, name, severity } of category) {
      if (pattern.test(content)) {
        return {
          passed: false,
          reason: `${attackType} detected: ${name}`,
          severity,
          violationType,
          confidence
        };
      }
    }
  }
  return { passed: true };
}

/**
 * Validate payload safety against all attack configs
 */
export function validatePayloadSafety(content: string): PatternDetectionResult {
  for (const config of attackConfigs) {
    const result = detectPatternCategories(
      content,
      config.name,
      config.categories,
      config.violationType,
      config.confidence
    );
    if (!result.passed) return result;
  }

  return { passed: true };
}
