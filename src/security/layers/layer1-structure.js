// src/security/layers/layer1-structure.js

import { ValidationLayer } from './validation-layer-base.js';
import { LIMITS } from '../constants.js';

/**
 * Layer 1: Structure Validation
 * Validates basic message structure, encoding, size, and schema
 */
export default class StructureValidationLayer extends ValidationLayer {
    constructor(options = {}) {
        super(options);
        
        // Layer 1 specific options
        this.maxMessageSize = options.maxMessageSize || LIMITS.MESSAGE_SIZE_MAX;
        this.maxParamCount = options.maxParamCount || LIMITS.PARAM_COUNT_MAX;
        this.maxStringLength = options.maxStringLength || LIMITS.STRING_LENGTH_MAX;
    }

    /**
     * Main validation entry point for Layer 1
     */
    async validate(message, _context) {
        // Early null/undefined check
        if (message === null || message === undefined) {
            return this.createFailureResult(
                "Message is null or undefined",
                'CRITICAL',
                'INVALID_MESSAGE'
            );
        }

        // Ensure message is an object
        if (typeof message !== 'object') {
            return this.createFailureResult(
                "Message must be an object",
                'CRITICAL',
                'INVALID_MESSAGE'
            );
        }

        // Run all Layer 1 validations
        const validations = [
            this.validateJsonRpcStructure(message),
            this.validateEncoding(message),
            this.validateMessageSize(message),
            this.validateSchema(message)
        ];

        // Check each validation
        for (const validation of validations) {
            const result = await validation;
            if (!result.passed) {
                return result; // Return first failure
            }
        }

        // All validations passed
        return this.createSuccessResult();
    }

    /**
     * Validate basic JSON-RPC 2.0 structure
     */
    async validateJsonRpcStructure(message) {
        // Check for required JSON-RPC 2.0 fields
        if (!message.jsonrpc || message.jsonrpc !== "2.0") {
            return this.createFailureResult(
                "Invalid or missing JSON-RPC version",
                'HIGH',
                'INVALID_PROTOCOL'
            );
        }

        if (!message.method || typeof message.method !== 'string') {
            return this.createFailureResult(
                "Missing or invalid method field",
                'HIGH', 
                'INVALID_PROTOCOL'
            );
        }

        // Method name should be reasonable length and format
        if (message.method.length > LIMITS.METHOD_NAME_MAX || !/^[a-zA-Z0-9_/-]+$/.test(message.method)) {
            return this.createFailureResult(
                "Invalid method name format",
                'MEDIUM',
                'INVALID_METHOD'
            );
        }

        // ID should be present and reasonable type
        if (message.id !== undefined && 
            typeof message.id !== 'string' && 
            typeof message.id !== 'number' && 
            message.id !== null) {
            return this.createFailureResult(
                "Invalid ID field type",
                'MEDIUM',
                'INVALID_PROTOCOL'
            );
        }

        return this.createSuccessResult();
    }

    /**
     * Validate character encoding and detect hidden/dangerous characters
     */
    async validateEncoding(message) {
        const messageString = this.getMessageString(message);

        // Check for null bytes (common in binary attacks)
        if (messageString.includes('\0')) {
            return this.createFailureResult(
                "Null bytes detected in message",
                'HIGH',
                'DANGEROUS_ENCODING'
            );
        }

        // Check for common hidden unicode characters used in attacks
        const dangerousUnicode = [
            '\u200B', // Zero width space
            '\u200C', // Zero width non-joiner  
            '\u200D', // Zero width joiner
            '\u2060', // Word joiner
            '\uFEFF', // Zero width no-break space
            '\u202E'  // Right-to-left override (used in filename spoofing)
        ];

        for (const char of dangerousUnicode) {
            if (messageString.includes(char)) {
                return this.createFailureResult(
                    `Suspicious unicode character detected: ${char.charCodeAt(0).toString(16)}`,
                    'MEDIUM',
                    'SUSPICIOUS_ENCODING'
                );
            }
        }

        // Check for excessive control characters
        const controlChars = messageString.match(/[\x00-\x1F\x7F]/g);
        if (controlChars && controlChars.length > LIMITS.CONTROL_CHARS_MAX) {
            return this.createFailureResult(
                "Excessive control characters detected",
                'MEDIUM',
                'SUSPICIOUS_ENCODING'
            );
        }

        return this.createSuccessResult();
    }

    /**
     * Validate message size limits
     */
    async validateMessageSize(message) {
        const messageSize = this.getMessageSize(message);

        if (messageSize > this.maxMessageSize) {
            return this.createFailureResult(
                `Message too large: ${messageSize} bytes (max: ${this.maxMessageSize})`,
                'HIGH',
                'SIZE_LIMIT_EXCEEDED'
            );
        }

        // Check for suspiciously small messages (might be malformed)
        if (messageSize < LIMITS.MESSAGE_SIZE_MIN) {
            return this.createFailureResult(
                "Message suspiciously small",
                'LOW',
                'MALFORMED_MESSAGE'
            );
        }

        return this.createSuccessResult();
    }

    /**
     * Validate basic parameter schema and structure
     */
    async validateSchema(message) {
        // Check params structure if present
        if (message.params !== undefined) {
            // Params should be object or array
            if (typeof message.params !== 'object' || message.params === null) {
                return this.createFailureResult(
                    "Invalid params type - must be object or array",
                    'MEDIUM',
                    'INVALID_SCHEMA'
                );
            }

            // Limit number of parameters to prevent DoS
            const paramCount = Array.isArray(message.params) ? 
                message.params.length : 
                Object.keys(message.params).length;

            if (paramCount > this.maxParamCount) {
                return this.createFailureResult(
                    `Too many parameters: ${paramCount} (max: ${this.maxParamCount})`,
                    'MEDIUM',
                    'PARAM_LIMIT_EXCEEDED'
                );
            }

            // Check for excessively long string values
            const strings = this.extractStrings(message.params);
            for (const str of strings) {
                if (str.length > this.maxStringLength) {
                    return this.createFailureResult(
                        `String parameter too long: ${str.length} chars (max: ${this.maxStringLength})`,
                        'MEDIUM',
                        'STRING_LIMIT_EXCEEDED'
                    );
                }
            }
        }

        // Basic MCP-specific method validation
        if (message.method && this.isMcpMethod(message.method)) {
            const mcpValidation = this.validateMcpMethodSchema(message);
            if (!mcpValidation.passed) {
                return mcpValidation;
            }
        }

        return this.createSuccessResult();
    }

    /**
     * Check if this is a known MCP method
     */
    isMcpMethod(method) {
        const mcpMethods = [
            'tools/call',
            'tools/list', 
            'resources/read',
            'resources/list',
            'prompts/get',
            'prompts/list'
        ];
        return mcpMethods.includes(method);
    }

    /**
     * Validate MCP-specific method schemas
     */
    validateMcpMethodSchema(message) {
        switch (message.method) {
            case 'tools/call':
                if (!message.params?.name || typeof message.params.name !== 'string') {
                    return this.createFailureResult(
                        "tools/call requires 'name' parameter",
                        'MEDIUM',
                        'MISSING_REQUIRED_PARAM'
                    );
                }
                break;

            case 'resources/read':
                if (!message.params?.uri || typeof message.params.uri !== 'string') {
                    return this.createFailureResult(
                        "resources/read requires 'uri' parameter",
                        'MEDIUM',
                        'MISSING_REQUIRED_PARAM'
                    );
                }
                break;

            case 'prompts/get':
                if (!message.params?.name || typeof message.params.name !== 'string') {
                    return this.createFailureResult(
                        "prompts/get requires 'name' parameter",
                        'MEDIUM',
                        'MISSING_REQUIRED_PARAM'
                    );
                }
                break;
        }

        return this.createSuccessResult();
    }
}