/**
 * Security preset configurations for SecureMcpServer.
 *
 * Presets provide a simple way to configure security levels without
 * understanding all individual options. Each preset represents a
 * different security posture:
 *
 * - `basic`: Relaxed limits for development/testing
 * - `standard`: Balanced security for most production use cases (default)
 * - `paranoid`: Maximum security for high-risk environments
 * - `custom`: Full control - preset ignored, all options explicit
 */

import type { ContextualConfig } from '../types/server.js';
import type { AutomationDetectionOptions } from '../types/layers.js';

/** Available security preset names */
export type SecurityPreset = 'basic' | 'standard' | 'paranoid' | 'custom';

/** Resolved configuration values from a preset */
export interface PresetConfiguration {
  // Layer 1: Structure
  maxMessageSize: number;
  maxParamCount: number;

  // Layer 2: Content
  contentValidation: 'minimal' | 'standard' | 'full';

  // Layer 3: Behavior
  maxRequestsPerMinute: number;
  maxRequestsPerHour: number;
  burstThreshold: number;
  burstWindowMs?: number;
  suspiciousMessageSize?: number;
  automationDetection?: AutomationDetectionOptions;

  // Layer 4: Semantics
  enforceChaining: boolean;
  quotas: Record<string, unknown> | null;

  // Layer 5: Contextual
  contextual: ContextualConfig | null;
}

/**
 * Security preset definitions.
 *
 * @example Using presets
 * ```typescript
 * import { SecureMcpServer } from 'mcp-secure-server';
 *
 * // Development: relaxed limits
 * const devServer = new SecureMcpServer(
 *   { name: 'dev', version: '1.0.0' },
 *   { securityLevel: 'basic' }
 * );
 *
 * // Production: balanced security (default)
 * const prodServer = new SecureMcpServer(
 *   { name: 'prod', version: '1.0.0' },
 *   { securityLevel: 'standard' }
 * );
 *
 * // High-security: maximum protection
 * const secureServer = new SecureMcpServer(
 *   { name: 'secure', version: '1.0.0' },
 *   { securityLevel: 'paranoid' }
 * );
 *
 * // Override specific values within a preset
 * const customServer = new SecureMcpServer(
 *   { name: 'custom', version: '1.0.0' },
 *   {
 *     securityLevel: 'standard',
 *     maxRequestsPerMinute: 60  // Override just this value
 *   }
 * );
 * ```
 */
export const SECURITY_PRESETS: Record<Exclude<SecurityPreset, 'custom'>, PresetConfiguration> = {
  /**
   * Basic preset - relaxed limits for development and testing.
   *
   * Use when:
   * - Local development
   * - Integration testing
   * - Internal tools with trusted users
   *
   * NOT recommended for production with untrusted input.
   */
  basic: {
    // Layer 1: Structure - relaxed
    maxMessageSize: 100 * 1024,  // 100KB
    maxParamCount: 200,

    // Layer 2: Content - critical patterns only
    contentValidation: 'minimal',

    // Layer 3: Behavior - relaxed rate limits
    maxRequestsPerMinute: 120,
    maxRequestsPerHour: 3000,
    burstThreshold: 30,
    burstWindowMs: 10_000,
    suspiciousMessageSize: 50_000,
    automationDetection: { enabled: false },  // Disabled for development

    // Layer 4: Semantics - disabled
    enforceChaining: false,
    quotas: null,

    // Layer 5: Contextual - disabled
    contextual: null
  },

  /**
   * Standard preset - balanced security for production (DEFAULT).
   *
   * Use when:
   * - Production deployments
   * - Services exposed to LLM clients
   * - General-purpose MCP servers
   *
   * Provides defense-in-depth without excessive false positives.
   */
  standard: {
    // Layer 1: Structure - reasonable limits
    maxMessageSize: 50 * 1024,  // 50KB
    maxParamCount: 100,

    // Layer 2: Content - standard pattern set
    contentValidation: 'standard',

    // Layer 3: Behavior - moderate rate limits
    maxRequestsPerMinute: 30,
    maxRequestsPerHour: 500,
    burstThreshold: 10,

    // Layer 4: Semantics - disabled by default
    enforceChaining: false,
    quotas: null,

    // Layer 5: Contextual - enabled with defaults
    contextual: { enabled: true }
  },

  /**
   * Paranoid preset - maximum security for high-risk environments.
   *
   * Use when:
   * - Processing untrusted input
   * - High-value targets
   * - Compliance requirements
   * - Financial or healthcare applications
   *
   * May produce more false positives. Tune tool policies for your use case.
   */
  paranoid: {
    // Layer 1: Structure - strict limits
    maxMessageSize: 25 * 1024,  // 25KB
    maxParamCount: 50,

    // Layer 2: Content - full pattern set (381 patterns)
    contentValidation: 'full',

    // Layer 3: Behavior - strict rate limits
    maxRequestsPerMinute: 15,
    maxRequestsPerHour: 200,
    burstThreshold: 5,
    burstWindowMs: 5_000,           // Shorter window (5s)
    suspiciousMessageSize: 10_000,  // Lower threshold (10KB)
    automationDetection: {
      enabled: true,
      sampleSize: 3,      // Detect faster
      maxVariance: 100,   // More lenient variance
      minInterval: 50,    // Catch faster automation
      maxInterval: 3_000  // Wider detection range
    },

    // Layer 4: Semantics - enabled
    enforceChaining: true,
    quotas: {
      default: {
        maxCallsPerMinute: 10,
        maxCallsPerHour: 100
      }
    },

    // Layer 5: Contextual - fully enabled
    contextual: {
      enabled: true,
      rateLimiting: { enabled: true }
    }
  }
};

/**
 * Resolve a security preset to its configuration values.
 *
 * @param preset - The preset name or 'custom'
 * @returns The preset configuration or null if 'custom'
 */
export function resolvePreset(preset: SecurityPreset): PresetConfiguration | null {
  if (preset === 'custom') {
    return null;
  }
  return SECURITY_PRESETS[preset];
}

/**
 * Get the default preset name.
 * @returns 'standard'
 */
export function getDefaultPreset(): SecurityPreset {
  return 'standard';
}

/**
 * Check if a string is a valid security preset name.
 * @param value - Value to check
 * @returns True if valid preset name
 */
export function isValidPreset(value: unknown): value is SecurityPreset {
  return typeof value === 'string' &&
    ['basic', 'standard', 'paranoid', 'custom'].includes(value);
}
