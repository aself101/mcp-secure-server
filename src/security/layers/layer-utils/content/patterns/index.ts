/**
 * Pattern index - re-exports all patterns as ATTACK_PATTERNS
 */

import type { Severity, ViolationType } from '../../../../../types/index.js';
import type { AttackPattern } from './injection.js';

import { pathTraversal, command, crlf } from './path-traversal.js';
import { xss, sql, script, nosql, graphql, deserialization } from './injection.js';
import { ssrf, lolbins, csv } from './network.js';
import { bufferOverflow, dataValidation, encoding, secrets, css, svg, xml } from './overflow-validation.js';

/** All attack patterns organized by category */
export const ATTACK_PATTERNS = {
  pathTraversal,
  xss,
  sql,
  command,
  script,
  css,
  bufferOverflow,
  dataValidation,
  encoding,
  ssrf,
  lolbins,
  nosql,
  graphql,
  deserialization,
  svg,
  secrets,
  crlf,
  csv,
  xml
} as const;

export type AttackPatternKey = keyof typeof ATTACK_PATTERNS;

/** Configuration for an attack detection category */
export interface AttackConfig {
  name: string;
  categories: readonly AttackPattern[][];
  violationType: ViolationType;
  confidence: number;
}

export const attackConfigs: readonly AttackConfig[] = [
  {
    name: 'File access pattern',
    categories: [
      ATTACK_PATTERNS.pathTraversal.patterns,
      ATTACK_PATTERNS.pathTraversal.sensitiveFiles,
      ATTACK_PATTERNS.pathTraversal.unixSystemFiles,
      ATTACK_PATTERNS.pathTraversal.macosSystemFiles,
      ATTACK_PATTERNS.pathTraversal.windowsAbsolutePaths,
      ATTACK_PATTERNS.pathTraversal.windowsSystemFiles
    ],
    violationType: 'PATH_TRAVERSAL',
    confidence: 0.9
  },
  {
    name: 'XSS pattern',
    categories: [
      ATTACK_PATTERNS.xss.basicVectors,
      ATTACK_PATTERNS.xss.eventHandlers,
      ATTACK_PATTERNS.xss.htmlElements,
      ATTACK_PATTERNS.xss.advancedVectors,
      ATTACK_PATTERNS.xss.jsExecution,
      ATTACK_PATTERNS.xss.domManipulation,
      ATTACK_PATTERNS.xss.templateInjection,
      ATTACK_PATTERNS.xss.extraAttributes
    ],
    violationType: 'XSS_ATTEMPT',
    confidence: 0.9
  },
  {
    name: 'SSRF attack',
    categories: [
      ATTACK_PATTERNS.ssrf.cloudMetadata,
      ATTACK_PATTERNS.ssrf.loopback,
      ATTACK_PATTERNS.ssrf.privateNetworks,
      ATTACK_PATTERNS.ssrf.specialAddresses,
      ATTACK_PATTERNS.ssrf.dangerousSchemes,
      ATTACK_PATTERNS.ssrf.internalServices,
      ATTACK_PATTERNS.ssrf.cloudServices,
      ATTACK_PATTERNS.ssrf.exfiltrationEndpoints,
      ATTACK_PATTERNS.ssrf.encodingBypass,
      ATTACK_PATTERNS.ssrf.redirectServices
    ],
    violationType: 'SSRF_ATTEMPT',
    confidence: 0.95
  },
  {
    name: 'Command injection',
    categories: [
      ATTACK_PATTERNS.command.basicInjection,
      ATTACK_PATTERNS.command.networkOperations,
      ATTACK_PATTERNS.command.shellAccess,
      ATTACK_PATTERNS.command.executionWrappers,
      ATTACK_PATTERNS.command.fileOperations,
      ATTACK_PATTERNS.command.systemInfo
    ],
    violationType: 'COMMAND_INJECTION',
    confidence: 0.85
  },
  {
    name: 'SQL injection',
    categories: [
      ATTACK_PATTERNS.sql.basicInjection,
      ATTACK_PATTERNS.sql.commandExecution,
      ATTACK_PATTERNS.sql.fileOperations,
      ATTACK_PATTERNS.sql.timeBasedAttacks,
      ATTACK_PATTERNS.sql.informationGathering
    ],
    violationType: 'SQL_INJECTION',
    confidence: 0.85
  },
  {
    name: 'Script injection',
    categories: [
      ATTACK_PATTERNS.script.pythonInjection,
      ATTACK_PATTERNS.script.nodeInjection,
      ATTACK_PATTERNS.script.dynamicExecution
    ],
    violationType: 'SCRIPT_INJECTION',
    confidence: 0.8
  },
  {
    name: 'Buffer overflow pattern',
    categories: [
      ATTACK_PATTERNS.bufferOverflow.repeatedChars,
      ATTACK_PATTERNS.bufferOverflow.formatStrings,
      ATTACK_PATTERNS.bufferOverflow.nopSleds
    ],
    violationType: 'BUFFER_OVERFLOW_ATTEMPT',
    confidence: 0.8
  },
  {
    name: 'CRLF injection',
    categories: [
      ATTACK_PATTERNS.crlf.basicInjection,
      ATTACK_PATTERNS.crlf.doubleEncoded,
      ATTACK_PATTERNS.crlf.httpHeaders,
      ATTACK_PATTERNS.crlf.responseSplitting,
      ATTACK_PATTERNS.crlf.utfOverlong,
      ATTACK_PATTERNS.crlf.logInjection
    ],
    violationType: 'CRLF_INJECTION',
    confidence: 0.85
  },
  {
    name: 'LOLBins',
    categories: [
      ATTACK_PATTERNS.lolbins.tools
    ],
    violationType: 'CRLF_INJECTION',
    confidence: 0.85
  },
  {
    name: 'NoSQL injection',
    categories: [
      ATTACK_PATTERNS.nosql.operators
    ],
    violationType: 'NOSQL_INJECTION',
    confidence: 0.85
  },
  {
    name: 'Graphql injection',
    categories: [
      ATTACK_PATTERNS.graphql.costHints,
      ATTACK_PATTERNS.graphql.introspection
    ],
    violationType: 'GRAPHQL_INJECTION',
    confidence: 0.85
  },
  {
    name: 'Deserialization injection',
    categories: [
      ATTACK_PATTERNS.deserialization.markers
    ],
    violationType: 'DESERIALIZATION_INJECTION',
    confidence: 0.85
  },
  {
    name: 'Prototype pollution',
    categories: [
      ATTACK_PATTERNS.script.prototypePollution
    ],
    violationType: 'PROTOTYPE_POLLUTION',
    confidence: 0.95
  },
  {
    name: 'XML entity attack',
    categories: [
      ATTACK_PATTERNS.xml.entityAttacks,
      ATTACK_PATTERNS.xml.billionLaughs
    ],
    violationType: 'XML_ENTITY_ATTACK',
    confidence: 0.9
  }
] as const;

/** Get patterns for a specific attack type */
export function getPatternsByType(type: AttackPatternKey): typeof ATTACK_PATTERNS[AttackPatternKey] {
  return ATTACK_PATTERNS[type] || {};
}

/** Severity order for filtering */
const severityOrder: Record<Severity, number> = {
  'NONE': 0,
  'LOW': 1,
  'MEDIUM': 2,
  'HIGH': 3,
  'CRITICAL': 4
};

type FilteredPatterns = Record<string, Record<string, AttackPattern[] | unknown>>;

/** Get patterns filtered by minimum severity */
export function getPatternsBySeverity(minSeverity: Severity): FilteredPatterns {
  const minLevel = severityOrder[minSeverity] || 0;
  const result: FilteredPatterns = {};

  for (const [category, subcategories] of Object.entries(ATTACK_PATTERNS)) {
    result[category] = {};
    for (const [subcat, patterns] of Object.entries(subcategories)) {
      if (Array.isArray(patterns)) {
        result[category][subcat] = (patterns as AttackPattern[]).filter(p =>
          (severityOrder[p.severity] ?? 0) >= minLevel
        );
      } else {
        result[category][subcat] = patterns;
      }
    }
  }

  return result;
}

/** Extended pattern with category info */
export interface ExtendedAttackPattern extends AttackPattern {
  category: string;
  subcategory: string;
}

/** Get all patterns as a flat array with category metadata */
export function getAllPatterns(): ExtendedAttackPattern[] {
  const allPatterns: ExtendedAttackPattern[] = [];

  for (const [category, subcategories] of Object.entries(ATTACK_PATTERNS)) {
    for (const [subcat, patterns] of Object.entries(subcategories)) {
      if (Array.isArray(patterns)) {
        allPatterns.push(...(patterns as AttackPattern[]).map(p => ({
          ...p,
          category,
          subcategory: subcat
        })));
      }
    }
  }

  return allPatterns;
}

// Re-export types
export type { AttackPattern } from './injection.js';
