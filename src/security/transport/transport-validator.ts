/**
 * Transport-level message validator factory
 * Creates validators that integrate with the 5-layer validation pipeline.
 * @module transport-validator
 */

import { normalizeRequest } from '../utils/request-normalizer.js';
import type { ValidationPipeline, PipelineContext, PipelineLogger } from '../utils/validation-pipeline.js';
import type { ValidationResult } from '../../types/index.js';
import type { McpMessage } from '../../types/server.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import type { TransportValidator } from './secure-transport.js';

/** Options for creating a transport validator */
export interface TransportValidatorOptions {
  /** Whether to log performance metrics */
  logPerformanceMetrics: boolean;
  /** Whether to enable verbose logging */
  verboseLogging: boolean;
  /** Default policy for validation */
  defaultPolicy: {
    allowNetwork: boolean;
    allowWrites: boolean;
  };
}

/** Dependencies for the transport validator */
export interface TransportValidatorDependencies {
  /** The validation pipeline to use */
  validationPipeline: ValidationPipeline;
  /** Optional security logger */
  securityLogger: SecurityLogger | null;
  /** Map of JSON-RPC IDs to internal request IDs */
  requestIdByJsonrpcId: Map<string | number | null | undefined, number>;
  /** Function to track requests */
  trackRequest: (message: McpMessage) => void;
}

/**
 * Create a transport validator function that validates messages through the pipeline.
 *
 * @param options - Validation options (performance, logging, policy)
 * @param deps - Dependencies (pipeline, logger, ID map, tracker)
 * @returns A validator function for use with SecureTransport
 */
export function createTransportValidator(
  options: TransportValidatorOptions,
  deps: TransportValidatorDependencies
): TransportValidator {
  const { logPerformanceMetrics, verboseLogging, defaultPolicy } = options;
  const { validationPipeline, securityLogger, requestIdByJsonrpcId, trackRequest } = deps;

  return async (
    message: McpMessage,
    context: { timestamp: number; transportLevel: boolean }
  ): Promise<ValidationResult> => {
    const startTime = logPerformanceMetrics ? performance.now() : 0;
    const normalizedMessage = normalizeRequest(message);

    // Optional logging
    if (securityLogger) {
      let internalId = requestIdByJsonrpcId.get(normalizedMessage.id);
      if (!internalId) {
        internalId = securityLogger.nextRequestId();
        requestIdByJsonrpcId.set(normalizedMessage.id, internalId);
      }

      securityLogger.logRequest(normalizedMessage, {
        timestamp: context.timestamp ?? Date.now(),
        source: 'transport-level',
        requestSize: JSON.stringify(message).length,
        pipelineLayers: validationPipeline.getLayers(),
        requestId: internalId
      });
    }

    // Run validation pipeline
    // SecurityLogger has more specific types than PipelineLogger, but is structurally compatible
    const pipelineLogger = securityLogger as PipelineLogger | undefined;
    const pipelineContext: PipelineContext = {
      timestamp: context.timestamp ?? Date.now(),
      transportLevel: true,
      originalMessage: message,
      logger: pipelineLogger,
      verbose: verboseLogging,
      requestId: normalizedMessage.id,
      policy: defaultPolicy
    };

    const result = await validationPipeline.validate(normalizedMessage, pipelineContext);

    // Performance tracking
    if (logPerformanceMetrics && securityLogger) {
      const endTime = performance.now();
      (result as ValidationResult & { validationTime?: number }).validationTime = endTime - startTime;
      securityLogger.logPerformance(startTime, endTime, normalizedMessage);
    }

    // Log decision
    if (securityLogger) {
      securityLogger.logSecurityDecision(result, normalizedMessage, 'Transport');
    }

    // JsonRpcMessage is structurally compatible with McpMessage (both have index signatures)
    trackRequest(normalizedMessage);
    return result;
  };
}
