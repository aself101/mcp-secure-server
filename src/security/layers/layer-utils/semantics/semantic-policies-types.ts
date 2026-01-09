/**
 * Type definitions for semantic policy validation
 * @module semantic-policies-types
 */

import type { Severity, ViolationType } from '../../../../types/index.js';

/** Argument type definitions */
export type ArgType = 'string' | 'number' | 'boolean' | 'array' | 'object';

/** Argument shape definition */
export interface ArgDefinition {
  type: ArgType;
  optional?: boolean;
}

/** Side effect levels for tools */
export type SideEffects = 'none' | 'read' | 'write' | 'network';

/** Tool specification */
export interface ToolSpec {
  name: string;
  sideEffects: SideEffects;
  maxArgsSize?: number;
  maxEgressBytes?: number;
  argsShape?: Record<string, ArgDefinition>;
  quotaPerMinute?: number;
  quotaPerHour?: number;
}

/** Resource policy configuration */
export interface ResourcePolicy {
  allowedSchemes: string[];
  allowedHosts?: string[];
  rootDirs?: string[];
  denyGlobs?: (string | RegExp)[];
  maxPathLength?: number;
  maxUriLength?: number;
  maxReadBytes?: number;
}

/** Method parameter specification */
export interface MethodParamSpec {
  required?: string[];
}

/** Method specification */
export interface MethodSpec {
  shape: Record<string, MethodParamSpec>;
}

/** Chaining rule definition */
export interface ChainingRule {
  /** Method to transition from ('*' for any) */
  from: string;
  /** Method to transition to ('*' for any) */
  to: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  fromTool?: string;
  /** Tool name pattern (glob: * = any, ? = single char). Only applies to tools/call */
  toTool?: string;
  /** Side effect of the 'from' tool */
  fromSideEffect?: SideEffects;
  /** Side effect of the 'to' tool */
  toSideEffect?: SideEffects;
  /** Action to take when rule matches. Default: 'allow' */
  action?: 'allow' | 'deny';
  /** Rule identifier for logging */
  id?: string;
}

/** Complete policies configuration */
export interface Policies {
  tools: ToolSpec[];
  resourcePolicy: ResourcePolicy;
  methodSpec: MethodSpec;
  chainingRules: ChainingRule[];
}

/** Normalized policies with processed globs */
export interface NormalizedPolicies {
  resourcePolicy: ResourcePolicy & { denyGlobs: RegExp[] };
  methodSpec: MethodSpec;
  chainingRules: ChainingRule[];
}

/** Validation result */
export interface PolicyValidationResult {
  passed: boolean;
  reason?: string;
  severity?: Severity;
  violationType?: ViolationType;
  bytes?: number;
}

/** Context for path resolution */
export interface PathContext {
  baseDir?: string;
}

/** Tool call parameters */
export interface ToolCallParams {
  name?: string;
  arguments?: Record<string, unknown>;
  args?: Record<string, unknown>;
}
