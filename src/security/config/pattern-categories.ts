/**
 * Pattern Categories for Security Levels
 *
 * Defines which attack patterns are checked at each security level.
 * This enables context-aware validation where storage tools skip
 * patterns that cause false positives on documentation content.
 */

import type { ToolSecurityLevel } from './tool-policies.js';

/**
 * Attack categories that should ALWAYS be checked regardless of security level.
 * These represent serious threats that are unlikely to appear in legitimate content.
 */
export const ALWAYS_CHECK_CATEGORIES = [
  // Critical injection vectors
  'xss.basicVectors',           // <script>, javascript:, etc.
  'xss.advancedVectors',        // data:text/html, srcdoc, etc.

  // Deserialization attacks
  'deserialization.markers',    // Java, PHP, Python pickle, JNDI

  // Path traversal attacks
  'pathTraversal.patterns',     // ../, encoded variants

  // Encoded attacks
  'encoding.suspicious',        // Script tags, protocols in encoded form

  // Critical SQL attacks
  'sql.commandExecution',       // exec(), xp_cmdshell

  // Critical command execution
  'command.shellAccess',        // bash -i, /bin/sh, powershell
  'command.executionWrappers',  // system(), exec(), shell_exec

  // Protocol injection
  'css.protocolInjection',      // url(javascript:)
  'ssrf.cloudMetadata',         // 169.254.169.254, metadata services
  'ssrf.dangerousSchemes',      // file://, gopher://, etc.

  // Living off the land
  'lolbins.tools',              // PowerShell encoded, certutil, etc.

  // Buffer overflow
  'bufferOverflow.nopSleds',    // Shellcode indicators
  'bufferOverflow.formatStrings' // Format string attacks
] as const;

/**
 * Categories checked at QUERY level and above (not STORAGE/DISPLAY).
 * These can cause false positives in documentation but are important for data queries.
 */
export const QUERY_LEVEL_CATEGORIES = [
  // SQL injection (standard patterns)
  'sql.basicInjection',         // OR 1=1, UNION SELECT, DROP TABLE
  'sql.fileOperations',         // LOAD_FILE, INTO OUTFILE
  'sql.timeBasedAttacks',       // SLEEP(), BENCHMARK()
  'sql.informationGathering',   // information_schema, version()

  // NoSQL injection
  'nosql.operators',            // $where, $ne, $gt

  // GraphQL attacks
  'graphql.introspection',      // __schema, __type

  // Script injection in queries
  'script.pythonInjection',     // import os, subprocess
  'script.nodeInjection',       // require(), child_process
  'script.prototypePollution',  // __proto__, constructor.prototype
] as const;

/**
 * Categories checked ONLY at EXECUTION level.
 * These frequently cause false positives on documentation/technical content.
 */
export const EXECUTION_ONLY_CATEGORIES = [
  // Command injection patterns that match common text
  'command.basicInjection',     // ; cmd, && cmd, || cmd, | cmd
  'command.networkOperations',  // wget, curl, nc (when mentioned in docs)
  'command.fileOperations',     // cat, head, tail, grep
  'command.systemInfo',         // env, whoami, ps, history

  // CSS expressions (match "behavior:" in docs)
  'css.expressions',            // expression(), behavior:

  // XSS patterns that match documentation
  'xss.eventHandlers',          // onclick=, onerror= (in HTML context now)
  'xss.htmlElements',           // <iframe>, <object> (common in docs)
  'xss.jsExecution',            // eval(), setTimeout() (common in code docs)
  'xss.domManipulation',        // document.write, window.location
  'xss.templateInjection',      // {{, ${} (common in docs)

  // CRLF patterns
  'crlf.basicInjection',        // %0d%0a patterns
  'crlf.httpHeaders',           // Header injection

  // CSV injection
  'csv.formula',                // =cmd|, @SUM
  'csv.payloads',               // CSV formula payloads

  // SVG vectors
  'svg.vectors',                // SVG event handlers

  // XML attacks
  'xml.entityAttacks',          // DOCTYPE, ENTITY
  'xml.billionLaughs',          // Entity expansion

  // Secrets (may appear in documentation examples)
  'secrets.common',             // API keys, tokens (placeholder patterns)

  // Data validation
  'dataValidation.testCredentials', // admin/password in examples
] as const;

/**
 * Map of category strings to their pattern group accessors
 */
export type PatternCategoryKey =
  | typeof ALWAYS_CHECK_CATEGORIES[number]
  | typeof QUERY_LEVEL_CATEGORIES[number]
  | typeof EXECUTION_ONLY_CATEGORIES[number];

/**
 * Get the pattern categories that should be checked for a given security level
 * @param level - The tool's security level
 * @returns Array of pattern category keys to check
 */
export function getCategoriesForLevel(level: ToolSecurityLevel): PatternCategoryKey[] {
  const categories: PatternCategoryKey[] = [...ALWAYS_CHECK_CATEGORIES];

  if (level === 'DISPLAY') {
    // DISPLAY: Only always-check categories
    return categories;
  }

  if (level === 'STORAGE') {
    // STORAGE: Always-check categories only (same as DISPLAY for now)
    // Could be adjusted to add specific patterns if needed
    return categories;
  }

  if (level === 'QUERY') {
    // QUERY: Always-check + query-level categories
    return [...categories, ...QUERY_LEVEL_CATEGORIES];
  }

  // EXECUTION: All categories
  return [...categories, ...QUERY_LEVEL_CATEGORIES, ...EXECUTION_ONLY_CATEGORIES];
}

/**
 * Check if a specific pattern category should be checked for a security level
 * @param category - Pattern category key
 * @param level - Tool security level
 * @returns true if the category should be checked
 */
export function shouldCheckCategory(
  category: string,
  level: ToolSecurityLevel
): boolean {
  const allowedCategories = getCategoriesForLevel(level);
  return allowedCategories.includes(category as PatternCategoryKey);
}

/**
 * Get a human-readable description of what's checked at each level
 */
export function getLevelDescription(level: ToolSecurityLevel): string {
  switch (level) {
    case 'DISPLAY':
      return 'Minimal validation: Only critical injection vectors and deserialization attacks';
    case 'STORAGE':
      return 'Relaxed validation: Critical attacks only, skips patterns that match documentation';
    case 'QUERY':
      return 'Standard validation: Critical attacks + SQL/NoSQL injection + script injection';
    case 'EXECUTION':
      return 'Full validation: All attack patterns checked';
  }
}
