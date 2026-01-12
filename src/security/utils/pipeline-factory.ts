/**
 * Pipeline factory - creates configured 5-layer validation pipeline
 */

import { ValidationPipeline, ValidationLayerInterface } from './validation-pipeline.js';
import { LIMITS, RATE_LIMITS } from '../constants.js';
import StructureValidationLayer from '../layers/layer1-structure.js';
import ContentValidationLayer from '../layers/layer2-content.js';
import BehaviorValidationLayer from '../layers/layer3-behavior.js';
import SemanticsValidationLayer from '../layers/layer4-semantics.js';
import ContextualValidationLayer, { type ContextualLayerOptions } from '../layers/layer5-contextual.js';
import { InMemoryQuotaProvider } from '../layers/layer-utils/semantics/semantic-quotas.js';
import { defaultToolRegistry, defaultResourcePolicy } from './tool-registry.js';
import { resolvePreset, getDefaultPreset, type PresetConfiguration } from '../presets.js';
import type { SecureMcpServerOptions } from '../../types/server.js';

/**
 * Create the 5-layer validation pipeline with resolved configuration.
 *
 * Layers:
 * 1. Structure - JSON-RPC format, size limits
 * 2. Content - Injection detection, XSS, path traversal
 * 3. Behavior - Rate limiting, burst detection
 * 4. Semantics - Tool contracts, resource policies
 * 5. Contextual - Custom validators, response filtering (optional)
 *
 * @param options - Server options for pipeline configuration
 * @param resolvedPreset - Pre-resolved preset to avoid duplicate resolution
 */
export function createValidationPipeline(
  options: SecureMcpServerOptions = {},
  resolvedPreset?: PresetConfiguration | null
): ValidationPipeline {
  // Use passed preset or resolve if not provided (for standalone usage)
  const preset = resolvedPreset ?? resolvePreset(options.securityLevel ?? getDefaultPreset());

  // Resolve individual options with preset fallbacks
  const maxParamCount = options.maxParamCount ?? preset?.maxParamCount ?? LIMITS.PARAM_COUNT_MAX;
  const enforceChaining = options.enforceChaining ?? preset?.enforceChaining ?? false;
  const quotas = options.quotas ?? (preset?.quotas as SecureMcpServerOptions['quotas']);

  const layers: ValidationLayerInterface[] = [
    new StructureValidationLayer({
      maxMessageSize: options.maxMessageSize ?? preset?.maxMessageSize ?? LIMITS.MESSAGE_SIZE_MAX,
      maxParamCount,
      maxStringLength: LIMITS.STRING_LENGTH_MAX
    }),
    new ContentValidationLayer({
      maxParamCount,
      validationLevel: options.contentValidation ?? preset?.contentValidation ?? 'standard'
    }),
    new BehaviorValidationLayer({
      requestsPerMinute: options.maxRequestsPerMinute ?? preset?.maxRequestsPerMinute ?? RATE_LIMITS.REQUESTS_PER_MINUTE,
      requestsPerHour: options.maxRequestsPerHour ?? preset?.maxRequestsPerHour ?? RATE_LIMITS.REQUESTS_PER_HOUR,
      burstThreshold: options.burstThreshold ?? preset?.burstThreshold ?? RATE_LIMITS.BURST_THRESHOLD,
      burstWindowMs: options.burstWindowMs ?? preset?.burstWindowMs,
      suspiciousMessageSize: options.suspiciousMessageSize ?? preset?.suspiciousMessageSize,
      automationDetection: options.automationDetection ?? preset?.automationDetection
    }),
    new SemanticsValidationLayer({
      toolRegistry: options.toolRegistry ?? defaultToolRegistry(),
      resourcePolicy: options.resourcePolicy ?? defaultResourcePolicy(),
      methodSpec: options.methodSpec,
      chainingRules: options.chainingRules,
      enforceChaining,
      quotas,
      quotaProvider: options.quotaProvider ?? new InMemoryQuotaProvider({
        clockSkewMs: options.clockSkewMs ?? 1000
      }),
      maxSessions: options.maxSessions ?? 5000,
      sessionTtlMs: options.sessionTtlMs ?? 30 * 60_000
    })
  ];

  // Layer 5: Contextual Validation - use preset config if not explicitly provided
  const contextualConfig = options.contextual ?? preset?.contextual ?? {};
  if (contextualConfig && (contextualConfig as { enabled?: boolean }).enabled !== false) {
    layers.push(new ContextualValidationLayer(contextualConfig as ContextualLayerOptions));
  }

  return new ValidationPipeline(layers);
}
