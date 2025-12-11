/**
 * Validation pipeline - orchestrates sequential layer execution
 */

import type { Severity, ViolationType } from '../../types/index.js';
import { getErrorMessage } from '../../types/index.js';
import { ErrorSanitizer } from './error-sanitizer.js';

/** Logger interface for security decisions */
export interface PipelineLogger {
  logSecurityDecision?: (result: unknown, message: unknown, layer: string) => void | Promise<void>;
}

/** Context passed through the pipeline */
export interface PipelineContext {
  logger?: PipelineLogger;
  [key: string]: unknown;
}

/** Validation layer interface */
export interface ValidationLayerInterface {
  isEnabled(): boolean;
  getName(): string;
  validate(message: unknown, context?: PipelineContext): Promise<LayerResult>;
}

/** Result from individual layer */
export interface LayerResult {
  passed?: boolean;
  allowed?: boolean;
  severity?: Severity;
  reason?: string | null;
  violationType?: ViolationType | string | null;
  confidence?: number;
  layerName?: string | null;
}

/** Normalized pipeline result */
export interface PipelineResult {
  passed: boolean;
  allowed: boolean;
  severity: Severity;
  reason: string;
  violationType: ViolationType | string | null;
  confidence: number;
  layerName: string;
  timestamp: number;
}

/**
 * Validation pipeline that runs messages through multiple layers
 */
export class ValidationPipeline {
  private _layers: ValidationLayerInterface[];
  private errorSanitizer: ErrorSanitizer;

  /** Get all validation layers */
  get layers(): ValidationLayerInterface[] {
    return this._layers;
  }

  constructor(layers: ValidationLayerInterface[] = []) {
    this._layers = layers;
    this.errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());
  }

  async validate(message: unknown, context: PipelineContext = {}): Promise<PipelineResult> {
    const logger = context.logger;

    for (let i = 0; i < this._layers.length; i++) {
      const layer = this._layers[i];
      if (!layer) continue;

      if (!layer.isEnabled()) continue;

      try {
        const result = await layer.validate(message, context);

        const normalizedResult: PipelineResult = {
          passed: result.passed !== undefined ? result.passed : result.allowed !== undefined ? result.allowed : true,
          allowed: result.allowed !== undefined ? result.allowed : result.passed !== undefined ? result.passed : true,
          severity: result.severity || 'LOW',
          reason: result.reason || 'No reason provided',
          violationType: result.violationType || 'UNKNOWN',
          confidence: result.confidence || 1.0,
          layerName: result.layerName || layer.getName(),
          timestamp: Date.now()
        };

        if (logger?.logSecurityDecision) {
          logger.logSecurityDecision(normalizedResult, message, layer.getName());
        }


        if (!normalizedResult.passed && !normalizedResult.allowed) return normalizedResult;

      } catch (error) {
        const sanitizedMessage = this.errorSanitizer.redact(getErrorMessage(error));

        const errorResult: PipelineResult = {
          passed: false,
          allowed: false,
          severity: 'CRITICAL',
          reason: `Layer validation error: ${sanitizedMessage}`,
          violationType: 'VALIDATION_ERROR',
          confidence: 1.0,
          layerName: layer.getName(),
          timestamp: Date.now()
        };

        if (logger?.logSecurityDecision) {
          logger.logSecurityDecision(errorResult, message, layer.getName());
        }

        return errorResult;
      }
    }

    const successResult: PipelineResult = {
      passed: true,
      allowed: true,
      severity: 'NONE',
      reason: 'All validation layers passed',
      violationType: null,
      confidence: 1.0,
      layerName: 'Pipeline',
      timestamp: Date.now()
    };

    if (logger?.logSecurityDecision) {
      logger.logSecurityDecision(successResult, message, 'Pipeline');
    }

    return successResult;
  }

  addLayer(layer: ValidationLayerInterface): void {
    this._layers.push(layer);
  }

  getLayers(): string[] {
    return this._layers.map(layer => layer.getName());
  }
}
