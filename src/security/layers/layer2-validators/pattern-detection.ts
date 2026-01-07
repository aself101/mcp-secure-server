/**
 * Pattern detection functions for Layer 2
 *
 * Supports context-aware validation based on tool security levels.
 */

import type { Severity, ViolationType } from '../../../types/index.js';
import type { AttackPattern, AttackConfig } from '../layer-utils/content/patterns/index.js';
import { ATTACK_PATTERNS, attackConfigs, sensitiveFileCategories } from '../layer-utils/content/dangerous-patterns.js';
import {
  type ToolSecurityLevel,
  getCategoriesForLevel,
  type PatternCategoryKey
} from '../../config/index.js';

/**
 * Path context indicators that suggest file system access intent.
 * Sensitive file patterns only trigger when these are present.
 * These patterns are designed to work on JSON-stringified content.
 */
const PATH_CONTEXT_PATTERNS = [
  /\.\.[/\\]/,            // Path traversal: ../ or ..\
  /["'][/\\]/,            // Absolute path in JSON: "/" or "\" at start of value
  /[/\\]\.\.[/\\]/,       // Mid-path traversal: /../
  /[/\\]etc[/\\]/,        // Unix system path: /etc/
  /[/\\]proc[/\\]/,       // Unix proc filesystem: /proc/
  /[/\\]var[/\\]/,        // Unix var path: /var/
  /[/\\]home[/\\]/,       // Unix home path: /home/
  /[/\\]usr[/\\]/,        // Unix usr path: /usr/
  /[a-zA-Z]:[/\\]/,       // Windows absolute path: C:\ or C:/
  /%2e%2e[%/\\]/i,        // URL-encoded traversal
  /%252e/i,               // Double-encoded dot
  /file:\/\//i,           // File protocol
  /\.\.%c0%af/i,          // UTF-8 overlong encoding
];

/** Validation result from pattern detection */
export interface PatternDetectionResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  confidence?: number;
  /** Name of the specific pattern that matched */
  patternName?: string;
  /** Category of the matched pattern (e.g., "pathTraversal.encodings") */
  patternCategory?: string;
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
    ...ATTACK_PATTERNS.command.executionWrappers,
    ...ATTACK_PATTERNS.sql.basicInjection,
    ...ATTACK_PATTERNS.sql.commandExecution
  ];

  return patternGroups.some(({ pattern }) => pattern.test(content));
}

/**
 * Generic pattern detection method
 * @param content - Content to check
 * @param attackType - Type of attack being checked (e.g., "Path traversal")
 * @param patternCategories - Array of pattern arrays to check
 * @param violationType - Violation type to return on match
 * @param confidence - Confidence score (default 0.85)
 * @param categoryName - Optional category name for enhanced logging
 */
export function detectPatternCategories(
  content: string,
  attackType: string,
  patternCategories: readonly AttackPattern[][],
  violationType: ViolationType,
  confidence = 0.85,
  categoryName?: string
): PatternDetectionResult {
  for (const category of patternCategories) {
    for (const { pattern, name, severity } of category) {
      if (pattern.test(content)) {
        return {
          passed: false,
          reason: `${attackType} detected: ${name}`,
          severity,
          violationType,
          confidence,
          patternName: name,
          patternCategory: categoryName ?? attackType
        };
      }
    }
  }
  return { passed: true };
}

/**
 * Check if content contains path context indicators.
 * Used to determine if sensitive file patterns should be checked.
 */
function hasPathContext(content: string): boolean {
  return PATH_CONTEXT_PATTERNS.some(pattern => pattern.test(content));
}

/**
 * Validate payload safety against all attack configs.
 * Uses context-aware detection for sensitive file patterns.
 */
export function validatePayloadSafety(content: string): PatternDetectionResult {
  // Check all standard attack patterns
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

  // Context-aware check: Only check sensitive file patterns
  // when path context is present (path separators, traversal, etc.)
  if (hasPathContext(content)) {
    const result = detectPatternCategories(
      content,
      'Sensitive file access',
      sensitiveFileCategories,
      'PATH_TRAVERSAL',
      0.85
    );
    if (!result.passed) return result;
  }

  return { passed: true };
}

/**
 * Map attack config names to their category keys for level filtering
 */
const CONFIG_TO_CATEGORY: Record<string, PatternCategoryKey[]> = {
  'Path traversal': ['pathTraversal.patterns'],
  'XSS pattern': [
    'xss.basicVectors', 'xss.eventHandlers', 'xss.htmlElements',
    'xss.advancedVectors', 'xss.jsExecution', 'xss.domManipulation',
    'xss.templateInjection'
  ],
  'SSRF attack': [
    'ssrf.cloudMetadata', 'ssrf.dangerousSchemes'
  ],
  'Command injection': [
    'command.basicInjection', 'command.networkOperations',
    'command.shellAccess', 'command.executionWrappers',
    'command.fileOperations', 'command.systemInfo'
  ],
  'SQL injection': [
    'sql.basicInjection', 'sql.commandExecution',
    'sql.fileOperations', 'sql.timeBasedAttacks', 'sql.informationGathering'
  ],
  'Script injection': [
    'script.pythonInjection', 'script.nodeInjection'
  ],
  'Buffer overflow pattern': [
    'bufferOverflow.nopSleds', 'bufferOverflow.formatStrings'
  ],
  'CRLF injection': [
    'crlf.basicInjection', 'crlf.httpHeaders'
  ],
  'LOLBins': ['lolbins.tools'],
  'NoSQL injection': ['nosql.operators'],
  'Graphql injection': ['graphql.introspection'],
  'Deserialization injection': ['deserialization.markers'],
  'Prototype pollution': ['script.prototypePollution'],
  'XML entity attack': ['xml.entityAttacks', 'xml.billionLaughs'],
  'CSV injection': ['csv.formula', 'csv.payloads'],
  'SVG injection': ['svg.vectors'],
  'Secret exposure': ['secrets.common'],
  'CSS injection': ['css.expressions', 'css.protocolInjection']
};

/**
 * Check if an attack config should be checked for a given security level
 */
function shouldCheckConfig(configName: string, level: ToolSecurityLevel): boolean {
  const categoryKeys = CONFIG_TO_CATEGORY[configName];
  if (!categoryKeys) return true; // Unknown configs are always checked

  const allowedCategories = getCategoriesForLevel(level);
  // Check if ANY of the config's categories are in the allowed list
  return categoryKeys.some(key => allowedCategories.includes(key));
}

/**
 * Validate payload safety with security level awareness.
 * Lower security levels skip patterns that commonly cause false positives.
 *
 * @param content - Content to validate
 * @param level - Tool security level (defaults to EXECUTION for full validation)
 * @returns Validation result
 */
export function validatePayloadSafetyWithLevel(
  content: string,
  level: ToolSecurityLevel = 'EXECUTION'
): PatternDetectionResult {
  // Filter attack configs based on security level
  for (const config of attackConfigs) {
    if (!shouldCheckConfig(config.name, level)) {
      continue; // Skip this config for this security level
    }

    const result = detectPatternCategories(
      content,
      config.name,
      config.categories,
      config.violationType,
      config.confidence
    );
    if (!result.passed) return result;
  }

  // Context-aware check for sensitive files (always checked for all levels)
  if (hasPathContext(content)) {
    const result = detectPatternCategories(
      content,
      'Sensitive file access',
      sensitiveFileCategories,
      'PATH_TRAVERSAL',
      0.85
    );
    if (!result.passed) return result;
  }

  return { passed: true };
}

/**
 * Get filtered attack configs for a security level
 * @param level - Security level to filter for
 * @returns Filtered array of attack configs
 */
export function getAttackConfigsForLevel(level: ToolSecurityLevel): readonly AttackConfig[] {
  return attackConfigs.filter(config => shouldCheckConfig(config.name, level));
}
