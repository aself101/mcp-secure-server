/**
 * MCP Security Framework - Type Definitions
 *
 * This module exports all type definitions for the security framework.
 */

// Validation types
export type {
  Severity,
  ViolationType,
  ValidationResult,
  ValidationContext,
  PolicyContext,
  ValidatorFunction,
  ResponseValidatorFunction,
  GlobalRuleFunction,
  ValidatorOptions,
} from './validation.js';

// Type guards
export {
  isSeverity,
  isViolationType,
  isError,
  getErrorMessage,
} from './validation.js';

// Message types
export type {
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcNotification,
  JsonRpcError,
  JsonRpcResponse,
  JsonRpcErrorResponse,
  McpToolCallParams,
  McpResourceReadParams,
  McpPromptGetParams,
  McpResourceListParams,
  McpToolListParams,
  McpPromptListParams,
  MessageType,
  McpMethod,
} from './messages.js';

// Layer configuration types
export type {
  LayerOptions,
  StructureLayerOptions,
  ContentLayerOptions,
  BehaviorLayerOptions,
  SemanticsLayerOptions,
  ContextualLayerOptions,
  OAuthValidationOptions,
  DomainRestrictionsOptions,
  RateLimitingOptions,
  ResponseValidationOptions,
  SecurityOptions,
  ServerInfo,
  SecurityStats,
  BehaviorStats,
} from './layers.js';

// Policy types
export type {
  SideEffectType,
  ArgType,
  ArgDefinition,
  ToolSpec,
  ResourcePolicy,
  MethodDefinition,
  MethodSpec,
  ChainingRule,
  QuotaLimits,
  QuotaCheckResult,
  QuotaProvider,
  RateWindow,
  RequestEntry,
  ErrorSanitizerConfig,
  SecurityLoggerOptions,
} from './policies.js';
