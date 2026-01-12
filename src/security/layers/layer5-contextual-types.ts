/**
 * Type definitions for Layer 5 - Contextual Validation Layer.
 * Separated to keep the main implementation file under 300 lines.
 */

import type { ValidationResult, ValidationContext, ValidationLayerOptions } from './validation-layer-base.js';
import type { ContextualConfig } from './contextual-config-builder.js';

/** Layer 5 specific options extending base config */
export interface ContextualLayerOptions extends ValidationLayerOptions, ContextualConfig {}

/** Validator function type */
export type ValidatorFunction = (message: unknown, context: ContextualContext) => ValidationResult | Promise<ValidationResult>;

/** Response validator function type */
export type ResponseValidatorFunction = (response: unknown, request: unknown, context: ContextualContext) => ValidationResult | Promise<ValidationResult>;

/** Validator options */
export interface ValidatorOptions {
  enabled: boolean;
  priority: number;
  skipOnSuccess: boolean;
  failOnError?: boolean;
}

/** Response validator options */
export interface ResponseValidatorOptions {
  enabled: boolean;
  failOnError?: boolean;
  [key: string]: unknown;
}

/** Global rule options */
export interface GlobalRuleOptions {
  enabled: boolean;
  priority: number;
  failOnError?: boolean;
  [key: string]: unknown;
}

/** Stored validator entry */
export interface ValidatorEntry {
  validate: ValidatorFunction;
  options: ValidatorOptions;
}

/** Stored response validator entry */
export interface ResponseValidatorEntry {
  validate: ResponseValidatorFunction;
  options: ResponseValidatorOptions;
}

/** Stored global rule entry */
export interface GlobalRuleEntry {
  validate: ValidatorFunction;
  options: GlobalRuleOptions;
}

/** Context store entry */
export interface ContextStoreEntry {
  value: unknown;
  expires: number;
}

/** Context with session info */
export interface ContextualContext extends ValidationContext {
  sessionId?: string;
  [key: string]: unknown;
}

/** Enhanced result with Layer 5 metadata */
export interface EnhancedResult extends ValidationResult {
  detectionLayer?: string;
  validatorSource?: string;
}
