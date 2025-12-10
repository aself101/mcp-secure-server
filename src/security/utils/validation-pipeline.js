// validation-pipeline.js - Error sanitizer integration
// ADD: Import ErrorSanitizer
import { ErrorSanitizer } from './error-sanitizer.js';

export class ValidationPipeline {
    constructor(layers = []) {
        this.layers = layers;
        this.errorSanitizer = new ErrorSanitizer(ErrorSanitizer.createProductionConfig());
    }

    async validate(message, context = {}) {
        const logger = context.logger;
        
        for (let i = 0; i < this.layers.length; i++) {
            const layer = this.layers[i];
            
            if (!layer.isEnabled()) continue;

            try {
                const result = await layer.validate(message, context);

                const normalizedResult = {
                    passed: result.passed !== undefined ? result.passed : result.allowed !== undefined ? result.allowed : true,
                    allowed: result.allowed !== undefined ? result.allowed : result.passed !== undefined ? result.passed : true,
                    severity: result.severity || 'LOW',
                    reason: result.reason || 'No reason provided',
                    violationType: result.violationType || 'UNKNOWN',
                    confidence: result.confidence || 1.0,
                    layerName: result.layerName || layer.getName(),
                    timestamp: Date.now()
                };
                
                if (logger && logger.logSecurityDecision) {
                   logger.logSecurityDecision(normalizedResult, message, layer.getName());
                }
                
                
                if (!normalizedResult.passed && !normalizedResult.allowed) return normalizedResult;

            } catch (error) {
                
                const sanitizedMessage = this.errorSanitizer.redact(error.message);
                
                const errorResult = {
                    passed: false,
                    allowed: false,
                    severity: 'CRITICAL',
                    reason: `Layer validation error: ${sanitizedMessage}`,
                    violationType: 'VALIDATION_ERROR',
                    confidence: 1.0,
                    layerName: layer.getName(),
                    timestamp: Date.now()
                };
                
                if (logger && logger.logSecurityDecision) {
                   logger.logSecurityDecision(errorResult, message, layer.getName());
                }
                
                return errorResult;
            }
        }

        const successResult = {
            passed: true,
            allowed: true,
            severity: 'NONE',
            reason: 'All validation layers passed',
            violationType: null,
            confidence: 1.0,
            layerName: 'Pipeline',
            timestamp: Date.now()
        };

        if (logger && logger.logSecurityDecision) {
            logger.logSecurityDecision(successResult, message, 'Pipeline');
        }

        return successResult;
    }

    addLayer(layer) {
        this.layers.push(layer);
    }

    getLayers() {
        return this.layers.map(layer => layer.getName());
    }
}