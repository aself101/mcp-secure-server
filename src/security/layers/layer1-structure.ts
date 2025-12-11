/**
 * Layer 1: Structure Validation
 * Validates basic message structure, encoding, size, and schema
 */

import { ValidationLayer, ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import { LIMITS } from '../constants.js';

/** Layer 1 specific options */
export interface StructureLayerOptions extends ValidationLayerOptions {
  maxMessageSize?: number;
  maxParamCount?: number;
  maxStringLength?: number;
}

/** MCP message structure */
interface McpMessage {
  jsonrpc?: string;
  method?: string;
  params?: Record<string, unknown> | unknown[];
  id?: string | number | null;
}

export default class StructureValidationLayer extends ValidationLayer {
  private maxMessageSize: number;
  private maxParamCount: number;
  private maxStringLength: number;

  constructor(options: StructureLayerOptions = {}) {
    super(options);

    this.maxMessageSize = options.maxMessageSize ?? LIMITS.MESSAGE_SIZE_MAX;
    this.maxParamCount = options.maxParamCount ?? LIMITS.PARAM_COUNT_MAX;
    this.maxStringLength = options.maxStringLength ?? LIMITS.STRING_LENGTH_MAX;
  }

  async validate(message: unknown, _context?: ValidationContext): Promise<ValidationResult> {
    if (message === null || message === undefined) {
      return this.createFailureResult(
        "Message is null or undefined",
        'CRITICAL',
        'INVALID_MESSAGE'
      );
    }

    if (typeof message !== 'object') {
      return this.createFailureResult(
        "Message must be an object",
        'CRITICAL',
        'INVALID_MESSAGE'
      );
    }

    const msg = message as McpMessage;

    const validations = [
      this.validateJsonRpcStructure(msg),
      this.validateEncoding(msg),
      this.validateMessageSize(msg),
      this.validateSchema(msg)
    ];

    for (const validation of validations) {
      const result = await validation;
      if (!result.passed) {
        return result;
      }
    }

    return this.createSuccessResult();
  }

  private async validateJsonRpcStructure(message: McpMessage): Promise<ValidationResult> {
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

    if (message.method.length > LIMITS.METHOD_NAME_MAX || !/^[a-zA-Z0-9_/-]+$/.test(message.method)) {
      return this.createFailureResult(
        "Invalid method name format",
        'MEDIUM',
        'INVALID_METHOD'
      );
    }

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

  private async validateEncoding(message: McpMessage): Promise<ValidationResult> {
    const messageString = this.getMessageString(message);

    if (messageString.includes('\0')) {
      return this.createFailureResult(
        "Null bytes detected in message",
        'HIGH',
        'DANGEROUS_ENCODING'
      );
    }

    const dangerousUnicode = [
      '\u200B', // Zero width space
      '\u200C', // Zero width non-joiner
      '\u200D', // Zero width joiner
      '\u2060', // Word joiner
      '\uFEFF', // Zero width no-break space
      '\u202E'  // Right-to-left override
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

  private async validateMessageSize(message: McpMessage): Promise<ValidationResult> {
    const messageSize = this.getMessageSize(message);

    if (messageSize > this.maxMessageSize) {
      return this.createFailureResult(
        `Message too large: ${messageSize} bytes (max: ${this.maxMessageSize})`,
        'HIGH',
        'SIZE_LIMIT_EXCEEDED'
      );
    }

    if (messageSize < LIMITS.MESSAGE_SIZE_MIN) {
      return this.createFailureResult(
        "Message suspiciously small",
        'LOW',
        'MALFORMED_MESSAGE'
      );
    }

    return this.createSuccessResult();
  }

  private async validateSchema(message: McpMessage): Promise<ValidationResult> {
    if (message.params !== undefined) {
      if (typeof message.params !== 'object' || message.params === null) {
        return this.createFailureResult(
          "Invalid params type - must be object or array",
          'MEDIUM',
          'INVALID_SCHEMA'
        );
      }

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

    if (message.method && this.isMcpMethod(message.method)) {
      const mcpValidation = this.validateMcpMethodSchema(message);
      if (!mcpValidation.passed) {
        return mcpValidation;
      }
    }

    return this.createSuccessResult();
  }

  private isMcpMethod(method: string): boolean {
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

  private validateMcpMethodSchema(message: McpMessage): ValidationResult {
    const params = message.params as Record<string, unknown> | undefined;

    switch (message.method) {
      case 'tools/call':
        if (!params?.name || typeof params.name !== 'string') {
          return this.createFailureResult(
            "tools/call requires 'name' parameter",
            'MEDIUM',
            'MISSING_REQUIRED_PARAM'
          );
        }
        break;

      case 'resources/read':
        if (!params?.uri || typeof params.uri !== 'string') {
          return this.createFailureResult(
            "resources/read requires 'uri' parameter",
            'MEDIUM',
            'MISSING_REQUIRED_PARAM'
          );
        }
        break;

      case 'prompts/get':
        if (!params?.name || typeof params.name !== 'string') {
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
