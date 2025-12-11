/**
 * Default tool and resource policy registry
 */

import type { ToolSpec, ResourcePolicy } from '../layers/layer-utils/semantics/semantic-policies.js';

/**
 * Get default tool specifications
 */
export const defaultToolRegistry = (): ToolSpec[] => {
  return [
    {
      name: 'debug-calculator',
      sideEffects: 'none',
      maxArgsSize: 2_000,
      maxEgressBytes: 8_000,
      quotaPerMinute: 120,
      quotaPerHour: 3_000,
      argsShape: { expression: { type: 'string' } }
    },
    {
      name: 'debug-file-reader',
      sideEffects: 'read',
      maxArgsSize: 2_000,
      maxEgressBytes: 1_000_000,
      quotaPerMinute: 60,
      quotaPerHour: 1_000,
      argsShape: { path: { type: 'string' } }
    },
    {
      name: 'debug-echo',
      sideEffects: 'none',
      maxArgsSize: 8_000,
      maxEgressBytes: 64_000,
      quotaPerMinute: 240,
      quotaPerHour: 5_000,
      argsShape: { text: { type: 'string' } }
    }
  ];
};

/**
 * Get default resource policy
 */
export const defaultResourcePolicy = (rootDirs?: string): ResourcePolicy => {
  return {
    allowedSchemes: ['file'],
    rootDirs: [rootDirs || './test-data'],
    denyGlobs: [
      '/proc/**', '/sys/**', '/dev/**', '/var/**', '/run/**',
      '**/*.key', '**/*.pem', '**/*.pfx', '**/*.p12', '**/.env',
      '**/id_rsa', '**/id_dsa', '**/id_ecdsa'
    ],
    maxPathLength: 4096,
    maxUriLength: 2048,
    maxReadBytes: 2_000_000
  };
};
