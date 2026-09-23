/**
 * Transport-level message validator factory
 * Creates validators that integrate with the 5-layer validation pipeline.
 * @module transport-validator
 */

import { serializedByteLength } from '../utils/byte-size.js';
import { normalizeRequest } from '../utils/request-normalizer.js';
import { safeLogDecision, type ValidationPipeline, type PipelineContext, type PipelineLogger } from '../utils/validation-pipeline.js';
import type { ValidationResult } from '../../types/index.js';
import type { McpMessage } from '../../types/server.js';
import type { SecurityLogger } from '../utils/security-logger.js';
import type { TransportValidator } from './secure-transport.js';

/** Correlation window for JSON-RPC id -> internal request id (entries, FIFO). */
export const REQUEST_ID_MAP_MAX = 10_000;

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
  /**
   * Builds the pipeline context from the owning server's options. When
   * supplied (SecureMcpServer always does), option-derived fields — policy,
   * logger, verbose — come from there so the stdio and HTTP paths cannot
   * drift; `options.defaultPolicy` / `verboseLogging` / `securityLogger` are
   * then only the fallback for standalone callers of this factory.
   */
  createContext?: (transportFields: Record<string, unknown>) => PipelineContext;
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
  const { validationPipeline, securityLogger, requestIdByJsonrpcId, trackRequest, createContext } = deps;

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
        // Bounded FIFO. The map's only purpose is to hand a RETRIED JSON-RPC id
        // the same internal id; nothing else reads it and this code never sees
        // the response that would retire an entry. Until 0.0.21 nothing evicted,
        // so with logging on it grew one entry per unique id for the life of the
        // process (ship run #1, issues d186a70c / e72a6b5f). Map iteration is
        // insertion-ordered, so the first key is the oldest.
        if (requestIdByJsonrpcId.size >= REQUEST_ID_MAP_MAX) {
          const oldest = requestIdByJsonrpcId.keys().next();
          if (!oldest.done) requestIdByJsonrpcId.delete(oldest.value);
        }
        requestIdByJsonrpcId.set(normalizedMessage.id, internalId);
      }

      securityLogger.logRequest(normalizedMessage, {
        timestamp: context.timestamp ?? Date.now(),
        source: 'transport-level',
        requestSize: serializedByteLength(message),
        pipelineLayers: validationPipeline.getLayers(),
        requestId: internalId
      });
    }

    // Run validation pipeline
    // SecurityLogger has more specific types than PipelineLogger, but is structurally compatible
    const pipelineLogger = securityLogger as PipelineLogger | undefined;
    const transportFields = {
      timestamp: context.timestamp ?? Date.now(),
      transportLevel: true,
      originalMessage: message,
      requestId: normalizedMessage.id
    };
    const pipelineContext: PipelineContext = createContext
      ? createContext(transportFields)
      : { ...transportFields, logger: pipelineLogger, verbose: verboseLogging, policy: defaultPolicy };

    const result = await validationPipeline.validate(normalizedMessage, pipelineContext);

    // Performance tracking
    if (logPerformanceMetrics && securityLogger) {
      const endTime = performance.now();
      (result as ValidationResult & { validationTime?: number }).validationTime = endTime - startTime;
      securityLogger.logPerformance(startTime, endTime, normalizedMessage);
    }

    // Log decision (fire-and-forget, cannot reject into the transport)
    safeLogDecision(pipelineLogger, result, normalizedMessage, 'Transport');

    // JsonRpcMessage is structurally compatible with McpMessage (both have index signatures)
    trackRequest(normalizedMessage);
    return result;
  };
}
